package handler

// /oauth2/authorize — the upstream half of the OAuth 2.0 + PKCE
// authorization_code grant. Mounted as a plain chi route (not Huma)
// because:
//
//  1. The principal-credential field set is resolver-dependent —
//     api_key today, session cookie / mTLS tomorrow — and doesn't fit
//     a static OpenAPI input schema. Huma's value (declarative input
//     parsing + auto-generated OpenAPI) is poor fit here.
//  2. The endpoint's contract is "redirect 302 with code+state in the
//     URL query," not "JSON-in JSON-out." Huma's TokenOutput-style
//     status+body shape isn't a clean way to model that.
//
// The downstream half (decode + consume) lives in
// internal/service/oauth.go::authorizationCode and is served by
// /oauth2/token.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/service"
)

// registerAuthorizeRoute mounts GET and POST /oauth2/authorize on the
// public chi router.
//
// Both methods are mounted, and RFC 6749 §3.1 is the sentence that governs
// both: "The authorization server MUST support the use of the HTTP GET
// method for the authorization endpoint and MAY support the use of the
// POST method as well." OAuth 2.1 §3.1 carries the same text forward, and
// OpenID Connect requires both. So GET is an obligation and POST is a
// permitted extra — not, as is sometimes assumed, disallowed.
//
// GET is what matters here: the browser redirect it enables is the only
// shape an off-the-shelf OAuth client — an MCP client doing CIMD, say —
// knows how to drive. v1 withheld it because the CLI use case was
// POST-only and "GET would surface principal credentials in URL query
// strings + access logs" (#263). POST stays because it is the only method
// v1 had, so CLI callers depend on it.
//
// That concern was right and is preserved rather than traded away:
// authorizeHandler binds the resolver-facing Form accessor to the
// POST body ONLY. On a GET the protocol parameters come from the query
// string — where RFC 6749 puts them — while credentials must arrive in a
// header or cookie. ZeroID therefore never AUTHENTICATES from a URL.
//
// That is a narrower claim than "a credential never lands in a URL", which
// an earlier version of this comment made and could not keep: ZeroID does
// not control what a caller puts in the query string. A client author who
// mirrors the documented POST form into a GET gets a correct 401 — and
// would, before this was fixed, have had the secret written to ZeroID's own
// access log on the way there. The request loggers now record r.URL.Path
// rather than r.RequestURI for that reason; see logSafePath in server.go.
// Referer and browser history remain the caller's to manage.
func (a *API) registerAuthorizeRoute(router chi.Router) {
	router.Get("/oauth2/authorize", a.authorizeHandler)
	router.Post("/oauth2/authorize", a.authorizeHandler)
}

// authorizeHandler is the chi handler for GET and POST /oauth2/authorize.
//
// Pipeline:
//
//  1. Parse application/x-www-form-urlencoded body
//  2. Build a typed AuthorizeRequest snapshot from the parsed form +
//     headers + cookies (read-only — resolvers never see *http.Request)
//  3. client_id / redirect_uri presence gate — ONLY the two
//     §4.1.2.1-exempt parameters are checked before the client lookup.
//     3.5. Resolve the client and validate redirect_uri
//     (OAuthService.ResolveAuthorizeClient) — BEFORE the resolver chain,
//     so later failures have somewhere safe to be reported.
//     3.75. Remaining protocol-parameter gates (response_type=code, PKCE
//     presence, S256) — after 3.5 so their failures can redirect, before
//     step 4 so a doomed request never reaches a login surface.
//  4. Walk the registered PrincipalResolver chain. First non-nil
//     Principal wins. No matches → access_denied. A resolver reporting
//     ErrPrincipalAccessDenied → access_denied redirect on GET and POST
//     (see denyAuthorize).
//  5. Intersect (caller-requested scope ∩ resolver-narrowed scope) —
//     the service layer intersects again with the client's registered
//     scope, so the issued code carries the narrowest authority.
//  6. Hand off to OAuthService.IssueAuthCode with the resolved client
//     for scope intersection and JWT minting.
//  7. Build the redirect URL with code + state and emit 302.
//
// Failures split by WHERE they happen, which is what step 3.5 exists to
// make possible. RFC 6749 §4.1.2.1 wants most failures redirected back to
// the client as error + state, and exempts exactly the two where
// redirecting would itself be the vulnerability: an invalid client_id and
// a missing or unregistered redirect_uri.
//
// So everything decided BEFORE step 3.5 — the availability gate, the
// parse error, the client_id/redirect_uri presence gate, and client
// validation itself — answers with an RFC 6749 §5.2 JSON body via
// writeAuthorizeError, because there is no validated redirect_uri to
// trust yet. Everything after it goes through failAuthorize, which
// redirects on GET and keeps JSON on POST (see that function for why the
// method matters) — except a resource owner's explicit denial, which
// redirects on both methods (see denyAuthorize).
//
// Ordering was the whole difficulty, and it was upstream of this
// handler's own steps: principal resolution used to run before any client
// lookup, which lived inside IssueAuthCode. access_denied — the failure a
// browser user actually hits by not being signed in — therefore fired
// while no validated redirect_uri existed to send it to, and redirecting
// to an unvalidated URI would have been an open redirect. Hoisting the
// lookup into step 3.5 is what fixed it (#279); note the fix had to be a
// hoist rather than a reorder within IssueAuthCode, where redirect_uri
// validation ran after the grant-type gate and only the mint 500 sat
// downstream of it.
func (a *API) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	// ── Step 0: is this deployment serving the flow at all? ──────────
	// SetAuthorizationCodeAvailable(false) used to suppress only the
	// discovery metadata, leaving the endpoint itself live. That made it
	// an advertisement switch, not an off switch — and mounting GET gave
	// deployers a reason to want a real one: a cookie-based resolver is
	// safe under POST alone (SameSite=Lax withholds the cookie on a
	// cross-site POST) and CSRF-reachable once a top-level navigation can
	// drive it. A deployer who reaches for the documented hatch gets what
	// the name promises: the flow is off, on both methods.
	//
	// Nothing changes by default. The built-in guess is "any resolver
	// registered", and a deployment with none already answered 503 here
	// via ErrNoResolversRegistered — this just reaches the same answer
	// before touching the request.
	if !a.canServeAuthorizationCode() {
		writeAuthorizeError(w, http.StatusServiceUnavailable, oautherror.ServerError,
			"/oauth2/authorize is not available on this deployment")

		return
	}

	// ── Step 1: parse the query string (GET) or form body (POST) ─────
	if err := r.ParseForm(); err != nil {
		// Name the source the caller actually used: a GET has no body, so
		// "could not parse ... body" points at the wrong parameter for the
		// request that most often trips this (a malformed %-escape in the
		// query string).
		source := "application/x-www-form-urlencoded body"
		if r.Method == http.MethodGet {
			source = "query string"
		}
		writeAuthorizeError(w, http.StatusBadRequest, oautherror.InvalidRequest,
			"could not parse "+source)

		return
	}

	// ── Step 2: build the AuthorizeRequest snapshot ──────────────────
	// Form/Header/Cookie are typed accessors over the underlying
	// request — resolvers read through them without ever holding a
	// reference to *http.Request. PostForm.Get is naturally read-only.
	//
	// Protocol parameters come from the query string on GET (RFC 6749
	// §4.1.1) and the body on POST. Read exactly one source per method
	// rather than r.Form, which merges both: a merged view lets a caller
	// put client_id in the query and another in the body, and whichever
	// one the handler happens to read is a parameter-smuggling seam.
	//
	// The resolver-facing Form accessor stays bound to PostForm on BOTH
	// methods. That is what keeps credentials out of URLs on the GET
	// path: on a GET, req.Form is empty by construction, so a resolver
	// reading req.Form("api_key") sees nothing and must fall through to
	// a header or cookie. See registerAuthorizeRoute.
	// `values` is the SAME single source `params` reads, kept so a repeatable
	// parameter can be read in full. RFC 8707 §2 permits `resource` to appear
	// more than once, and params/Get would silently return only the first —
	// dropping a resource the client asked to be bound to.
	values := r.PostForm
	if r.Method == http.MethodGet {
		values = r.URL.Query()
	}
	params := values.Get
	postForm := r.PostForm
	header := r.Header
	req := &service.AuthorizeRequest{
		ClientID:            params("client_id"),
		RedirectURI:         params("redirect_uri"),
		ResponseType:        params("response_type"),
		CodeChallenge:       params("code_challenge"),
		CodeChallengeMethod: params("code_challenge_method"),
		State:               params("state"),
		Scope:               params("scope"),
		Resource:            values["resource"],
		Form:                postForm.Get,
		Header: func(name string) string {
			return header.Get(name)
		},
		Cookie: func(name string) string {
			c, err := r.Cookie(name)
			if err != nil {
				return ""
			}
			return c.Value
		},
	}

	// ── Step 3: client_id / redirect_uri presence ────────────────────
	// ONLY the two §4.1.2.1-exempt parameters are gated before client
	// resolution. Every other protocol-parameter check waits until after
	// step 3.5 — with the client and redirect_uri validated, those
	// failures can be reported the way the spec wants, a 302 back to the
	// client, instead of a JSON dead end in the browser. The service
	// layer enforces the same gates again at IssueAuthCode (defense in
	// depth for programmatic callers that bypass the handler).
	if req.ClientID == "" {
		writeAuthorizeError(w, http.StatusBadRequest, oautherror.InvalidRequest, "client_id is required")
		return
	}
	if req.RedirectURI == "" {
		writeAuthorizeError(w, http.StatusBadRequest, oautherror.InvalidRequest, "redirect_uri is required")
		return
	}

	// ── Step 3.5: resolve the client, validate redirect_uri ──────────
	// Deliberately BEFORE principal resolution, which is the whole point.
	// RFC 6749 §4.1.2.1 exempts exactly two failures from being redirected —
	// an invalid client_id and a missing/unregistered redirect_uri — because
	// redirecting either would be the vulnerability rather than the fix. Both
	// are decided here, and both stay JSON.
	//
	// Everything after this point has a redirect_uri the client registered, so
	// it can be reported the way the spec wants: a 302 carrying error + state.
	// Running this after the resolver, as v1 did, is what made access_denied
	// unreportable — see the header comment.
	oauthClient, err := a.oauthSvc.ResolveAuthorizeClient(r.Context(), req.ClientID, req.RedirectURI)
	if err != nil {
		code, description, status := extractOAuthError(err)
		log.Warn().Err(err).Str("client_id", req.ClientID).Msg("/oauth2/authorize client validation failed")

		// A non-nil client alongside the error means redirect_uri was validated
		// before the failure — so this is a §4.1.2.1 redirectable error
		// (unauthorized_client) rather than one of the two exemptions. Without
		// this branch a client whose grant types omit authorization_code got a
		// JSON blob in the browser despite having a perfectly good registered
		// redirect_uri, which is the dead end this PR exists to remove.
		if oauthClient != nil {
			a.failAuthorize(w, r, req, oauthClient, status, code, code, description)

			return
		}

		writeAuthorizeError(w, status, code, description)

		return
	}

	// ── Step 3.75: remaining protocol-parameter gates ────────────────
	// AFTER client resolution, deliberately: §4.1.2.1 puts invalid_request
	// and unsupported_response_type on the redirect list, so a browser
	// client with a perfectly good registered redirect_uri learns about
	// its own malformed parameter from the callback, not from a JSON blob
	// it never reads. failAuthorize keeps these as JSON on POST (CLI
	// callers have parsed that shape since v1) and for self-asserted
	// clients (see that function for why).
	//
	// Still BEFORE principal resolution: a request that cannot possibly
	// succeed must not send a user through the deployer's login surface
	// (step 4's interaction hook) only to be told its own parameter was
	// wrong after they authenticate.
	//
	// RFC 6749 §4.1.1 makes response_type REQUIRED. Enforce it on GET: the
	// browser leg is new surface with no back-compat obligation, and every
	// real OAuth client sends it. POST stays lenient because CLI callers
	// have been permitted to omit it since v1 and "code" is the only value
	// this endpoint has ever supported, so tightening it there would break
	// them for no security gain.
	if r.Method == http.MethodGet && req.ResponseType == "" {
		a.failAuthorize(w, r, req, oauthClient, http.StatusBadRequest,
			oautherror.InvalidRequest, oautherror.InvalidRequest,
			"response_type is required (RFC 6749 §4.1.1) and must be 'code'")

		return
	}

	if req.ResponseType != "" && req.ResponseType != "code" {
		// The redirect code is unsupported_response_type — the vocabulary
		// §4.1.2.1 defines for exactly this. The JSON code stays
		// invalid_request: that is what POST callers have parsed since v1,
		// and this PR pins POST behaviour unchanged.
		a.failAuthorize(w, r, req, oauthClient, http.StatusBadRequest,
			oautherror.InvalidRequest, oautherror.UnsupportedResponseType,
			"response_type must be 'code' (only authorization_code grant is supported at /oauth2/authorize)")

		return
	}

	if req.CodeChallenge == "" {
		a.failAuthorize(w, r, req, oauthClient, http.StatusBadRequest,
			oautherror.InvalidRequest, oautherror.InvalidRequest,
			"code_challenge is required")

		return
	}

	if req.CodeChallengeMethod == "" {
		a.failAuthorize(w, r, req, oauthClient, http.StatusBadRequest,
			oautherror.InvalidRequest, oautherror.InvalidRequest,
			"code_challenge_method is required")

		return
	}

	// S256 is checked HERE, not only at IssueAuthCode, because it is the one
	// remaining step-6 gate that a request can fail on values it supplied
	// itself. IssueAuthCode still enforces it for programmatic callers that
	// bypass this handler.
	if req.CodeChallengeMethod != "S256" {
		a.failAuthorize(w, r, req, oauthClient, http.StatusBadRequest,
			oautherror.InvalidRequest, oautherror.InvalidRequest,
			"code_challenge_method must be S256 (plain is not supported)")

		return
	}

	// The RFC 8707 resource ceiling (CAP-IDN-027). Validated HERE, alongside
	// the other parameters a request can doom itself on, rather than only at
	// step 6: reaching IssueAuthCode means having passed through the resolver
	// chain, so a client that sent a malformed identifier would first send its
	// human to a login surface and only then be refused. IssueAuthCode
	// re-validates, so a programmatic caller is still gated.
	//
	// invalid_target in BOTH vocabularies, unlike the response_type gate above
	// which splits them. That gate keeps invalid_request in the JSON body for
	// backward compatibility — "what POST callers have parsed since v1" — and
	// this gate is new, so it has no such callers to keep faith with. RFC 8707
	// §2 names invalid_target for a resource the AS cannot honour, and
	// /oauth2/token already answers that way for the same parameter; splitting
	// the codes here would mean one parameter reporting two different errors
	// depending on which endpoint rejected it.
	resourceCeiling, err := service.ValidateAuthorizeResource(req.Resource)
	if err != nil {
		_, desc, status := extractOAuthError(err)
		a.failAuthorize(w, r, req, oauthClient, status,
			oautherror.InvalidTarget, oautherror.InvalidTarget, desc)

		return
	}
	// Normalise the snapshot to the VALIDATED, de-duplicated ceiling. Two
	// consumers depend on this rather than on the raw parameter:
	// redirectToInteractiveLogin rebuilds return_to from req (and its contract
	// is that it carries only validated parameters), and any resolver that
	// reads req.Resource sees the canonical form rather than whatever repeated
	// or duplicated shape arrived on the wire.
	req.Resource = resourceCeiling

	// ── Step 4: principal resolution ─────────────────────────────────
	// The resolvePrincipal callback is wired unconditionally by
	// Server.NewServer (it's a method bound to the server's resolver
	// registry — never nil). The registry itself may be empty, which
	// is the "deployer forgot to wire it up" case — surfaced via the
	// ErrNoResolversRegistered sentinel below as a 503.
	principal, resolverName, err := a.resolvePrincipal(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrNoResolversRegistered) {
			// Configuration error, not a runtime credential error —
			// 503 so embedders see a clear setup signal. Distinct
			// from 401 ("you wired it up but no credential matched").
			log.Warn().Str("client_id", req.ClientID).Msg("/oauth2/authorize called but no PrincipalResolver is registered")
			writeAuthorizeError(w, http.StatusServiceUnavailable, oautherror.ServerError,
				"/oauth2/authorize is not configured on this deployment: no PrincipalResolver registered")
			return
		}
		if errors.Is(err, service.ErrPrincipalAccessDenied) {
			// The resolver authenticated the request and the resource owner
			// declined it. Not a failure of the request — an answer to it, and
			// one only zeroid can deliver, because only zeroid has validated the
			// redirect_uri it must travel to. Checked before the interaction
			// sentinel so a resolver that wraps both still ends the flow rather
			// than restarting a login the user has just declined.
			log.Info().
				Str("resolver", resolverName).
				Str("client_id", req.ClientID).
				Msg("resource owner denied the authorization request")
			a.denyAuthorize(w, req, oauthClient)

			return
		}
		if errors.Is(err, service.ErrPrincipalInteractionRequired) {
			// The resolver recognised this as a request a human could satisfy
			// but found nobody signed in. Send them somewhere they can, if the
			// deployer told us where; otherwise fall through to access_denied,
			// because a resolver cannot conjure a login surface a deployment
			// does not have.
			if a.redirectToInteractiveLogin(w, r, req, oauthClient, resolverName) {
				return
			}

			log.Warn().
				Str("resolver", resolverName).
				Str("client_id", req.ClientID).
				Msg("resolver requested interactive authentication but no interactive login URL is configured " +
					"(Server.SetInteractiveLoginURL); refusing as access_denied")
			a.failAuthorize(w, r, req, oauthClient, http.StatusUnauthorized, oautherror.InvalidClient,
				oautherror.AccessDenied, "interactive authentication required but unavailable")

			return
		}
		// A specific resolver found its credential in the request but
		// rejected it (wrong api_key, expired cookie, etc.). Log the
		// resolver name + error for operators; return a generic
		// invalid_client to the caller so we don't leak which
		// resolver path matched.
		log.Warn().
			Err(err).
			Str("resolver", resolverName).
			Str("client_id", req.ClientID).
			Msg("principal resolver rejected request")
		// access_denied, not invalid_client: the client is fine — we resolved
		// it at step 3.5 — it is the RESOURCE OWNER whose credential failed,
		// which is exactly what RFC 6749 §4.1.2.1 defines access_denied for.
		// The old invalid_client blamed the wrong party.
		a.failAuthorize(w, r, req, oauthClient, http.StatusUnauthorized, oautherror.InvalidClient,
			oautherror.AccessDenied, "credential rejected")

		return
	}
	if principal == nil {
		// Every registered resolver returned ErrPrincipalNotApplicable — the
		// caller didn't supply a credential any resolver recognized. On a
		// browser GET this is the ordinary "you are not signed in" case, so it
		// redirects as access_denied; on POST the JSON hint naming the
		// deployer-chosen credential fields is more useful to a CLI author.
		a.failAuthorize(w, r, req, oauthClient, http.StatusUnauthorized, oautherror.InvalidClient,
			oautherror.AccessDenied,
			"no applicable credential: request did not match any registered principal resolver")

		return
	}

	// ── Step 5: caller-requested ∩ resolver-narrowed scope ───────────
	// The service layer (IssueAuthCode) does the final intersection
	// against the client's registered scope set. Here we just combine
	// what the caller asked for with what the resolver pre-narrowed.
	// Tested with strings.Fields, not req.Scope != "": IssueAuthCode and
	// requireGrantableScope both decide "did the caller actually ask" by
	// parsing the scope string, so a whitespace-only scope must look omitted
	// here too. Branching on != "" narrowed to an empty set here while the
	// service still read the request as omitted and fell back to the client's
	// full registered scopes — wider than sending no scope at all.
	scopes := principal.Scopes
	if requested := strings.Fields(req.Scope); len(requested) > 0 {
		if len(scopes) > 0 {
			scopes = intersectStrings(requested, scopes)
		} else {
			scopes = requested
		}
	}

	// ── Step 6: mint via service ─────────────────────────────────────
	// Client is the one resolved at step 3.5, so IssueAuthCode skips the
	// LOOKUP — the expensive half, a DB read or a CIMD fetch. The policy
	// gates (active/public state, grant-type allow-list, redirect_uri
	// allow-list) are deliberately RE-RUN inside IssueAuthCode via
	// checkAuthorizeClientPolicy: they are I/O-free, and re-running them
	// is the only arrangement in which a caller supplying a pre-resolved
	// Client cannot skip a gate. See IssueAuthCodeRequest.Client.
	code, err := a.oauthSvc.IssueAuthCode(r.Context(), service.IssueAuthCodeRequest{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		AccountID:           principal.AccountID,
		ProjectID:           principal.ProjectID,
		UserID:              principal.UserID,
		OrgID:               principal.OrgID,
		UserEmail:           principal.UserEmail,
		UserName:            principal.UserName,
		Scopes:              scopes,
		RequestedScope:      req.Scope,
		Resources:           resourceCeiling,
		Client:              oauthClient,
	})
	if err != nil {
		log.Warn().
			Err(err).
			Str("resolver", resolverName).
			Str("client_id", req.ClientID).
			Str("account_id", principal.AccountID).
			Msg("IssueAuthCode rejected request")
		errCode, desc, status := extractOAuthError(err)
		a.failAuthorize(w, r, req, oauthClient, status, errCode, errCode, desc)

		return
	}

	// ── Step 7: 302 to redirect_uri with ?code=…&state=… ─────────────
	// redirect_uri has been validated by IssueAuthCode against the
	// client's registered list — we can trust it now. Parse + add
	// query params.
	u, parseErr := url.Parse(req.RedirectURI)
	if parseErr != nil {
		// IssueAuthCode validated this URL is in the client's
		// registered list; if it now fails to parse, the client's
		// registration is corrupt. 500 not 400.
		log.Error().Err(parseErr).Str("redirect_uri", req.RedirectURI).Msg("registered redirect_uri failed url.Parse")
		writeAuthorizeError(w, http.StatusInternalServerError, oautherror.ServerError,
			"failed to build redirect")
		return
	}
	q := u.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	// RFC 9207 §2: identify the issuing AS on every authorization response.
	q.Set("iss", a.issuer)
	u.RawQuery = q.Encode()

	log.Info().
		Str("resolver", resolverName).
		Str("client_id", req.ClientID).
		Str("account_id", principal.AccountID).
		Str("project_id", principal.ProjectID).
		Str("user_id", principal.UserID).
		Msg("authorization code issued")

	w.Header().Set("Location", u.String())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
}

// redirectToInteractiveLogin sends the user agent to the deployer's login
// surface, returning true when it handled the response.
//
// Returns false — leaving the caller to refuse — when a redirect is not the
// right answer:
//
//   - Not a GET. There is no user agent in a POST exchange to send anywhere; the
//     caller is a CLI or a server posting an assertion.
//   - No target configured. The deployment has no login surface, so there is
//     nowhere to go.
//   - refusesRedirectTo declines the client (no resolvable client). A CIMD
//     client is not refused here: cimd.allowed_domains is enforced when its
//     document resolves, so a client that reached this point was admitted.
//
// The return_to it appends is rebuilt from the VALIDATED protocol parameters, not
// copied from the inbound URL. That is deliberate: the inbound query is
// caller-controlled and may carry anything, including a credential someone put
// in the wrong channel, and forwarding it verbatim would hand that to the login
// surface (and into its logs) as a side effect of a failed sign-in. Rebuilding
// also means what comes back is exactly the request zeroid already validated.
// The only additions are parameters the embedder allowlisted by name
// (Server.SetInteractiveLoginPassthroughParams), which can never be protocol
// or credential parameters — see addPassthroughParams.
//
// The target itself comes from deployer configuration, so it is not validated as
// an open-redirect risk the way a client-supplied URI would be. It is worth
// noting that the func receives the request, though — a deployer deriving the
// target from request data reintroduces exactly that risk, which is why the
// godoc on the public setter says not to.
func (a *API) redirectToInteractiveLogin(
	w http.ResponseWriter, r *http.Request, req *service.AuthorizeRequest,
	client *domain.OAuthClient, resolverName string,
) bool {
	if r.Method != http.MethodGet || a.interactiveLoginURL == nil ||
		a.refusesRedirectTo(client, req.RedirectURI) {
		return false
	}

	target := a.interactiveLoginURL(req)
	if target == "" {
		return false
	}

	u, err := url.Parse(target)
	if err != nil {
		log.Error().Err(err).Str("target", target).
			Msg("interactive login URL is not parseable; refusing rather than emitting a broken Location")

		return false
	}

	// Rebuild the authorize request from validated fields only.
	returnTo := url.Values{
		"client_id":             {req.ClientID},
		"redirect_uri":          {req.RedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {req.CodeChallenge},
		"code_challenge_method": {req.CodeChallengeMethod},
	}
	if req.State != "" {
		returnTo.Set("state", req.State)
	}

	if req.Scope != "" {
		returnTo.Set("scope", req.Scope)
	}

	// The RFC 8707 consented ceiling MUST survive the login round trip
	// (CAP-IDN-027). Omitting it was a silent-unbinding bug of exactly the kind
	// this capability exists to close: the pre-login pass validates `resource`
	// and the resumed pass then sees it absent, so the code is minted with no
	// `rsc` claim, the access token carries no `resource` claim, and Shield —
	// which keys INV-IDN-006 on that claim's PRESENCE — honours the token at
	// every MCP server in the tenant. No error at any step. And because it is
	// the FIRST browser visit that bounces through login, that was the common
	// path, not an edge case.
	//
	// Added with Add rather than Set: RFC 8707 §2 permits the parameter to
	// repeat, and req.Resource holds the validated, de-duplicated ceiling
	// (normalised in authorizeHandler right after ValidateAuthorizeResource),
	// which is what this function's "validated fields only" contract requires.
	for _, resource := range req.Resource {
		returnTo.Add("resource", resource)
	}

	// Embedder-allowlisted extras (Server.SetInteractiveLoginPassthroughParams),
	// copied verbatim from the inbound query — the one deliberate exception to
	// "validated fields only", bounded by deployer configuration. GET only, so
	// the query is the parameter source (see authorizeHandler step 2).
	if a.interactiveLoginPassthrough != nil {
		if names := a.interactiveLoginPassthrough(); len(names) > 0 {
			addPassthroughParams(returnTo, r.URL.Query(), names, req.ClientID)
		}
	}

	q := u.Query()
	q.Set("return_to", a.issuer+"/oauth2/authorize?"+returnTo.Encode())
	u.RawQuery = q.Encode()

	log.Info().
		Str("resolver", resolverName).
		Str("client_id", req.ClientID).
		Msg("redirecting to interactive login")

	w.Header().Set("Location", u.String())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)

	return true
}

// failAuthorize reports a failure that occurred AFTER the client and
// redirect_uri were validated at step 3.5 — so, unlike the earlier gates, it has
// somewhere safe to send the caller.
//
// On GET it redirects per RFC 6749 §4.1.2.1: 302 to the registered redirect_uri
// with error, error_description and the caller's state. That is the only shape a
// browser-driven client can act on; a JSON body leaves the user staring at a raw
// error while the client waits on a callback that never arrives.
//
// On POST it keeps the JSON body. The POST caller is not a browser — it is a CLI
// or a server-side surface that authenticated the user itself and posts a
// credential (an RFC 7523 assertion, say), and it has parsed JSON errors since
// v1. Redirecting those would break them for no benefit, and there is no user
// agent in that exchange to redirect anyway.
//
// The GET redirect applies to CIMD clients exactly as to registered ones:
// cimd.allowed_domains is enforced once, when the document resolves, and a
// client that got this far was admitted. The cost of the open default (empty
// allow-list) is that anyone can publish a document whose redirect_uri this
// redirects to; docs/spec/zeroid-oauth-extensions.md §12.5 records that trade.
//
// jsonCode vs redirectCode: the wire code sometimes has to differ between the
// two shapes. A failed resolver is invalid_client to a programmatic POST caller
// (that is the vocabulary §5.2 gives it) but access_denied on the browser leg,
// where the client is fine and it is the resource owner who could not be
// authenticated. Passing both keeps each channel accurate instead of forcing one
// vocabulary onto the other.
//
// state is echoed only when the caller sent one. §4.1.2.1 requires it back
// exactly if it was sent, and it is the client's CSRF and correlation handle —
// dropping it on the error path is how a client ends up unable to match the
// failure to the request that caused it.
func (a *API) failAuthorize(
	w http.ResponseWriter, r *http.Request, req *service.AuthorizeRequest,
	client *domain.OAuthClient, status int, jsonCode, redirectCode, description string,
) {
	if r.Method == http.MethodGet && a.redirectAuthorizeError(w, req, client, redirectCode, description) {
		return
	}

	writeAuthorizeError(w, status, jsonCode, description)
}

// accessDeniedDescription is the error_description sent when a resolver reports
// that the resource owner declined. Fixed text on purpose: the resolver's error
// may carry deployer-internal detail (who the user was, which consent record
// matched), and none of that belongs in a URL the client and its logs receive.
const accessDeniedDescription = "the resource owner denied the request"

// denyAuthorize reports ErrPrincipalAccessDenied: the resource owner was
// authenticated and declined.
//
// It redirects on POST as well as GET, which is the one place this endpoint does
// so for an error, and the reason is who the POST caller is in this case. The
// sentinel only arises when a resolver has authenticated a request, and the POST
// shape that produces it is a login/consent front end posting a signed statement
// of the user's decision server-to-server. On approval that front end receives
// the code redirect and hands its Location to the browser; on denial it must be
// able to do the same with the error redirect, and it cannot build that redirect
// itself — zeroid alone has validated client_id and redirect_uri. failAuthorize's
// reason for keeping POST on JSON (a CLI that parses JSON errors) does not apply:
// a CLI resolver never returns this sentinel, so no existing caller sees a change.
//
// refusesRedirectTo still governs, identically to failAuthorize: where it
// refuses the destination, the answer is a JSON access_denied body instead of a
// Location. 403 rather than 401 on that path because nothing failed to
// authenticate — the owner was identified and said no. cimd.allowed_domains is
// not a redirect gate here: it is enforced once, at document resolution, so a
// self-asserted client that reached a resolver has already been admitted.
func (a *API) denyAuthorize(w http.ResponseWriter, req *service.AuthorizeRequest, client *domain.OAuthClient) {
	if a.redirectAuthorizeError(w, req, client, oautherror.AccessDenied, accessDeniedDescription) {
		return
	}

	writeAuthorizeError(w, http.StatusForbidden, oautherror.AccessDenied, accessDeniedDescription)
}

// redirectAuthorizeError writes the RFC 6749 §4.1.2.1 error redirect — 302 to
// the validated redirect_uri with error, error_description, state (if sent) and
// iss — and reports true. It writes nothing and reports false when the
// destination must not be redirected to (refusesRedirectTo) or does not parse,
// leaving the caller to answer with JSON. Method policy is the caller's: this
// function does not look at the request method.
func (a *API) redirectAuthorizeError(
	w http.ResponseWriter, req *service.AuthorizeRequest,
	client *domain.OAuthClient, redirectCode, description string,
) bool {
	if a.refusesRedirectTo(client, req.RedirectURI) {
		return false
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		// Unreachable in practice: ResolveAuthorizeClient matched this against
		// the client's registered list, which means it parsed. If it somehow
		// does not now, fall back to JSON rather than emit a broken Location —
		// never guess at a redirect target.
		log.Error().Err(err).Str("redirect_uri", req.RedirectURI).
			Msg("validated redirect_uri failed url.Parse on the error path")

		return false
	}

	q := u.Query()
	q.Set("error", redirectCode)
	q.Set("error_description", nqchar(description))

	if req.State != "" {
		q.Set("state", req.State)
	}

	// RFC 9207 §2 applies to error responses too: a mix-up attacker can just
	// as well relay an error, and a client checking iss must be able to check
	// it on every response it gets back from the authorization endpoint.
	q.Set("iss", a.issuer)

	u.RawQuery = q.Encode()

	w.Header().Set("Location", u.String())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)

	return true
}

// nqchar coerces a description to RFC 6749 §4.1.2.1's NQCHAR set —
// %x20-21 / %x23-5B / %x5D-7E, i.e. printable ASCII minus the double quote and
// backslash. Anything outside it becomes a space.
//
// Percent-encoding already makes any byte transport-safe, so this is about the
// charset the spec allows in the value rather than about injection: a client
// validating error_description strictly is entitled to reject an em dash. Applied
// at this one boundary rather than by auditing every literal, because the
// descriptions that reach here include service-layer strings from
// extractOAuthError, and "remember to keep this ASCII" does not survive the next
// person writing an error message.
//
// The JSON body needs no such treatment — §5.2 puts no charset limit on it, and
// UTF-8 reads better there.
func nqchar(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '"' || r == '\\':
			return ' '
		case r >= 0x20 && r <= 0x7e:
			return r
		default:
			return ' '
		}
	}, s)
}

// writeAuthorizeError emits an RFC 6749 §5.2 JSON error body. Used for every
// failure decided BEFORE the client and redirect_uri are validated — the
// availability gate, the parse error, the required-field gate, and client
// validation itself — because §4.1.2.1 exempts exactly those from being
// redirected: with no validated redirect_uri, a redirect would be an open
// redirect. Failures after that point go through failAuthorize.
// Cache-Control: no-store per RFC 6749 §5.1 to prevent intermediary
// caches from holding error responses tied to credential state.
func writeAuthorizeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// intersectStrings returns the set intersection of a and b, preserving
// the order of a. Used to combine caller-requested scopes with the
// resolver's pre-narrowed scope surface before handing off to
// IssueAuthCode (which intersects again with the client's registered
// scopes). Linear time + linear memory; the scope lists are small
// enough that a hash-set lookup is the right shape.
func intersectStrings(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return out
}
