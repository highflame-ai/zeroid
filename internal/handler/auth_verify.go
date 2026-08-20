package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/pkg/dpop"
)

func (a *API) registerAuthVerifyRoute(router chi.Router) {
	router.Get("/oauth2/token/verify", a.authVerifyHandler)
}

// authVerifyHandler is a forward-auth endpoint for reverse proxies.
//
// Reverse proxies (nginx auth_request, Caddy forward_auth, Traefik forwardAuth)
// validate requests by calling an auth endpoint and inspecting the response
// code. On 2xx they copy specified response headers into the proxied request;
// on 4xx they reject the request.
//
// This endpoint bridges that pattern to ZeroID:
//
//  1. Reads the Bearer JWT from the Authorization header.
//  2. Introspects it (signature + revocation check).
//  3. When the token carries cnf.jkt, requires a matching DPoP proof
//     (RFC 9449 §6.1 sender-constraint). Forward-auth is the resource
//     server for every proxied upstream; surfacing cnf without enforcing
//     it would accept a stolen bound token as a bare Bearer.
//  4. On success: returns 200 with identity claims as response headers.
//  5. On failure: returns 401.
//
// Proxy config snippets:
//
//	# nginx
//	auth_request      /oauth2/token/verify;
//	auth_request_set  $forwarded_user $upstream_http_x_forwarded_user;
//	proxy_set_header  X-Forwarded-User $forwarded_user;
//
//	# Caddy
//	forward_auth zeroid:8899 {
//	  uri /oauth2/token/verify
//	  copy_headers X-Forwarded-User X-Zeroid-Identity-Type X-Zeroid-Trust-Level X-Zeroid-Account-ID X-Zeroid-Project-ID
//	}
func (a *API) authVerifyHandler(w http.ResponseWriter, r *http.Request) {
	prm := a.prmURL()

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// RFC 6750 §3.1 — "missing_token" is not in the standard enum,
		// but pre-PR usage shipped this string; preserved for client
		// compatibility. The RFC 9728 §5.1 breadcrumb is the additive
		// improvement.
		w.Header().Set("WWW-Authenticate", middleware.WWWAuthenticate("missing_token", "", prm))
		http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
		return
	}

	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		w.Header().Set("WWW-Authenticate", middleware.WWWAuthenticate(oautherror.InvalidRequest, "", prm))
		http.Error(w, `{"error":"invalid_authorization_header"}`, http.StatusUnauthorized)
		return
	}

	claims, err := a.oauthSvc.Introspect(r.Context(), token)
	if err != nil {
		log.Error().Err(err).Msg("auth/verify: introspect error")
		http.Error(w, fmt.Sprintf(`{"error":%q}`, oautherror.ServerError), http.StatusInternalServerError)
		return
	}

	active, _ := claims["active"].(bool)
	if !active {
		w.Header().Set("WWW-Authenticate", middleware.WWWAuthenticate(oautherror.InvalidToken, "", prm))
		http.Error(w, fmt.Sprintf(`{"error":%q}`, oautherror.InvalidToken), http.StatusUnauthorized)
		return
	}

	if rejectBoundTokenWithoutDPoP(w, r, token, claims, a.dpopVerifier, prm) {
		return
	}

	headerMap := map[string]string{
		"sub":           "X-Forwarded-User",
		"identity_type": "X-Zeroid-Identity-Type",
		"trust_level":   "X-Zeroid-Trust-Level",
		"account_id":    "X-Zeroid-Account-ID",
		"project_id":    "X-Zeroid-Project-ID",
		"external_id":   "X-Zeroid-External-ID",
	}
	for claim, header := range headerMap {
		if v, _ := claims[claim].(string); v != "" {
			w.Header().Set(header, v)
		}
	}

	// act is a nested object {"sub": "..."} — extract act.sub separately.
	if act, ok := claims["act"].(map[string]any); ok {
		if v, _ := act["sub"].(string); v != "" {
			w.Header().Set("X-Zeroid-Act-Sub", v)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"active":true}`))
}

// cnfJKTFromClaims pulls cnf.jkt from an introspection result. Introspect
// surfaces cnf as map[string]any (JWT nested object); issuance also uses
// map[string]string. Accept both so a shape quirk cannot skip enforcement.
func cnfJKTFromClaims(claims map[string]any) string {
	raw, ok := claims["cnf"]
	if !ok || raw == nil {
		return ""
	}
	switch cnf := raw.(type) {
	case map[string]any:
		if jkt, _ := cnf["jkt"].(string); jkt != "" {
			return jkt
		}
	case map[string]string:
		return cnf["jkt"]
	}
	return ""
}

// rejectBoundTokenWithoutDPoP enforces RFC 9449 §6.1 sender-constraint for
// DPoP-bound access tokens on the forward-auth path. Returns true when the
// response has already been written (caller must return). Unbound tokens and
// a nil verifier leave the request untouched.
func rejectBoundTokenWithoutDPoP(w http.ResponseWriter, r *http.Request, accessToken string, claims map[string]any, verifier *dpop.Verifier, prm string) bool {
	jkt := cnfJKTFromClaims(claims)
	if jkt == "" || verifier == nil {
		return false
	}

	proofJWT := r.Header.Get("DPoP")
	if proofJWT == "" {
		w.Header().Set("WWW-Authenticate", middleware.WWWAuthenticate(oautherror.InvalidToken, "token is DPoP-bound; DPoP proof header is required", prm))
		http.Error(w, `{"error":"invalid_token","error_description":"token is DPoP-bound; DPoP proof header is required"}`, http.StatusUnauthorized)
		return true
	}

	htu := middleware.EffectiveRequestURL(r.Context())
	if htu == "" {
		// RequestURLMiddleware always installs on the public router; keep a
		// defensive fallback for unit tests that call the helper directly.
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		htu = scheme + "://" + r.Host + r.URL.Path
	}

	if _, err := verifier.ValidateBoundToToken(r.Context(), dpop.ValidateRequest{
		ProofJWT:    proofJWT,
		Method:      r.Method,
		URL:         htu,
		AccessToken: accessToken,
	}, jkt); err != nil {
		log.Warn().Err(err).Str("path", r.URL.Path).Msg("auth/verify: DPoP proof rejected")
		w.Header().Set("WWW-Authenticate", middleware.WWWAuthenticate(oautherror.InvalidToken, "invalid DPoP proof", prm))
		http.Error(w, `{"error":"invalid_token","error_description":"invalid DPoP proof"}`, http.StatusUnauthorized)
		return true
	}
	return false
}
