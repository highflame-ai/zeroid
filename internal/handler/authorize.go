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
//     Principal wins. No matches → access_denied.
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
// method matters).
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
	params := r.PostForm.Get
	if r.Method == http.MethodGet {
		query := r.URL.Query()
		params = query.Get
	}
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
	scopes := principal.Scopes
	if req.Scope != "" {
		requested := strings.Fields(req.Scope)
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
		Scopes:              scopes,
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
// Returns false — leaving the caller to refuse — in the three cases where a
// redirect is not the right answer:
//
//   - Not a GET. There is no user agent in a POST exchange to send anywhere; the
//     caller is a CLI or a server posting an assertion.
//   - No target configured. The deployment has no login surface, so there is
//     nowhere to go.
//   - A self-asserted (CIMD) client whose publishing host nobody vetted. Sending
//     a user through the deployment's real login page on behalf of such a client
//     is the more damaging half of the same problem failAuthorize declines: the
//     victim authenticates for real, and the flow resumes toward an
//     attacker-published redirect_uri. Refusing here means an unvetted client
//     cannot borrow the login surface's credibility. Setting cimd.allowed_domains
//     vets the publishing hosts and lifts the refusal — see refusesRedirectTo.
//
// The return_to it appends is rebuilt from the VALIDATED protocol parameters, not
// copied from the inbound URL. That is deliberate: the inbound query is
// caller-controlled and may carry anything, including a credential someone put
// in the wrong channel, and forwarding it verbatim would hand that to the login
// surface (and into its logs) as a side effect of a failed sign-in. Rebuilding
// also means what comes back is exactly the request zeroid already validated.
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
		client == nil || a.refusesRedirectTo(client) {
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
// It also keeps the JSON body for a SELF-ASSERTED client, and that one is a
// deliberate deviation from §4.1.2.1 rather than a gap.
//
// §4.1.2.1's redirect rule rests on "registered" meaning a party somebody vetted.
// CIMD removes registration by design: the redirect_uris come from a document the
// requester published, CIMD is on by default, and allowed_domains ships empty, so
// the destination is attacker-CHOSEN rather than merely attacker-supplied. Under
// those conditions honouring the rule turns this endpoint into an unauthenticated
// redirector — reachable with no credential, since the failure being reported IS
// "you have no credential" — with the authorization server's own origin as the
// first hop. Three independent reviews flagged it; the deviation is the
// deliberate answer.
//
// What it costs: a CIMD client driving a browser cannot learn its error from the
// callback and must read the JSON body instead, which is exactly the ergonomic
// problem #279 set out to fix, kept for the one client class whose redirect
// target nobody vetted. Registered and dynamically-registered clients — where
// somebody did — are unaffected and get the conformant redirect.
//
// Deployers who want CIMD clients to receive redirects can restore them by
// setting cimd.allowed_domains, which re-establishes the vetting the rule assumes;
// see docs/cimd.md. The gate is provenance, not the CIMD feature itself.
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
	if r.Method != http.MethodGet || client == nil || a.refusesRedirectTo(client) {
		writeAuthorizeError(w, status, jsonCode, description)

		return
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		// Unreachable in practice: ResolveAuthorizeClient matched this against
		// the client's registered list, which means it parsed. If it somehow
		// does not now, fall back to JSON rather than emit a broken Location —
		// never guess at a redirect target.
		log.Error().Err(err).Str("redirect_uri", req.RedirectURI).
			Msg("validated redirect_uri failed url.Parse on the error path")
		writeAuthorizeError(w, status, jsonCode, description)

		return
	}

	q := u.Query()
	q.Set("error", redirectCode)
	q.Set("error_description", nqchar(description))

	if req.State != "" {
		q.Set("state", req.State)
	}

	u.RawQuery = q.Encode()

	w.Header().Set("Location", u.String())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
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
