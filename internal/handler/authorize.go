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

	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/service"
)

// registerAuthorizeRoute mounts POST /oauth2/authorize on the public
// chi router. GET is intentionally not supported in v1: RFC 6749
// §4.1.1 permits GET for browser redirects, but the v1 use case (CLI
// clients posting api_key + code_challenge) is POST-only. GET would
// surface principal credentials in URL query strings + access logs.
func (a *API) registerAuthorizeRoute(router chi.Router) {
	router.Post("/oauth2/authorize", a.authorizeHandler)
}

// authorizeHandler is the chi handler for POST /oauth2/authorize.
//
// Pipeline:
//
//  1. Parse application/x-www-form-urlencoded body
//  2. Build a typed AuthorizeRequest snapshot from the parsed form +
//     headers + cookies (read-only — resolvers never see *http.Request)
//  3. Required-field gate + response_type=code check (cheap, before
//     any DB hits)
//  4. Walk the registered PrincipalResolver chain. First non-nil
//     Principal wins. No matches → 401 invalid_client.
//  5. Intersect (caller-requested scope ∩ resolver-narrowed scope) —
//     the service layer intersects again with the client's registered
//     scope, so the issued code carries the narrowest authority.
//  6. Hand off to OAuthService.IssueAuthCode for client validation,
//     redirect_uri allow-list, S256 enforcement, and JWT minting.
//  7. Build the redirect URL with code + state and emit 302.
//
// Errors fall into two camps. Syntactic errors (missing fields, bad
// response_type) and credential failures (no resolver matched, all
// resolvers rejected) return RFC 6749 §5.2 JSON error bodies — we
// cannot redirect to a URL we haven't validated. Errors AFTER
// successful client lookup could in principle be redirected back per
// RFC 6749 §4.1.2.1, but v1 keeps them as JSON too; CLI clients
// (today's only consumer) parse JSON errors fine, and redirect-with-
// error needs careful URL validation we'd rather not introduce
// piecemeal.
func (a *API) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	// ── Step 1: parse form body ──────────────────────────────────────
	if err := r.ParseForm(); err != nil {
		writeAuthorizeError(w, http.StatusBadRequest, oautherror.InvalidRequest,
			"could not parse application/x-www-form-urlencoded body")
		return
	}

	// ── Step 2: build the AuthorizeRequest snapshot ──────────────────
	// Form/Header/Cookie are typed accessors over the underlying
	// request — resolvers read through them without ever holding a
	// reference to *http.Request. PostForm.Get is naturally read-only.
	postForm := r.PostForm
	header := r.Header
	req := &service.AuthorizeRequest{
		ClientID:            postForm.Get("client_id"),
		RedirectURI:         postForm.Get("redirect_uri"),
		ResponseType:        postForm.Get("response_type"),
		CodeChallenge:       postForm.Get("code_challenge"),
		CodeChallengeMethod: postForm.Get("code_challenge_method"),
		State:               postForm.Get("state"),
		Scope:               postForm.Get("scope"),
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

	// ── Step 3: required-field gate ──────────────────────────────────
	// Caller errors before any DB hits — fail fast with a clear
	// message. The service layer enforces the same gates again at
	// IssueAuthCode (defense in depth for programmatic callers that
	// bypass the handler), but we surface a per-field error here so
	// CLI clients get actionable feedback.
	if req.ClientID == "" {
		writeAuthorizeError(w, http.StatusBadRequest, oautherror.InvalidRequest, "client_id is required")
		return
	}
	if req.RedirectURI == "" {
		writeAuthorizeError(w, http.StatusBadRequest, oautherror.InvalidRequest, "redirect_uri is required")
		return
	}
	if req.CodeChallenge == "" {
		writeAuthorizeError(w, http.StatusBadRequest, oautherror.InvalidRequest, "code_challenge is required")
		return
	}
	if req.CodeChallengeMethod == "" {
		writeAuthorizeError(w, http.StatusBadRequest, oautherror.InvalidRequest, "code_challenge_method is required")
		return
	}
	if req.ResponseType != "" && req.ResponseType != "code" {
		// response_type is optional in our shape (we only support
		// "code" anyway), but if the caller passes something else
		// they have the wrong shape in their head — surface it
		// instead of silently accepting.
		writeAuthorizeError(w, http.StatusBadRequest, oautherror.InvalidRequest,
			"response_type must be 'code' (only authorization_code grant is supported at /oauth2/authorize)")
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
		writeAuthorizeError(w, http.StatusUnauthorized, oautherror.InvalidClient,
			"credential rejected")
		return
	}
	if principal == nil {
		// Every registered resolver returned ErrPrincipalNotApplicable —
		// the caller didn't supply a credential any resolver
		// recognized. 401 with a hint that points at the deployer-
		// chosen credential names is the most useful response.
		writeAuthorizeError(w, http.StatusUnauthorized, oautherror.InvalidClient,
			"no applicable credential — request did not match any registered principal resolver")
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
	})
	if err != nil {
		log.Warn().
			Err(err).
			Str("resolver", resolverName).
			Str("client_id", req.ClientID).
			Str("account_id", principal.AccountID).
			Msg("IssueAuthCode rejected request")
		errCode, desc, status := extractOAuthError(err)
		writeAuthorizeError(w, status, errCode, desc)
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

// writeAuthorizeError emits an RFC 6749 §5.2 JSON error body. Used for
// all error paths at /oauth2/authorize in v1 (no redirect-with-error).
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
