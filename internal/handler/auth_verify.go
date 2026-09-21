package handler

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/oautherror"
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
//  3. On success: returns 200 with identity claims as response headers.
//  4. On failure: returns 401.
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

	// RFC 9110 §11.1: the scheme is case-insensitive. RFC 9449 §7.1: a
	// DPoP-bound access token is presented under the DPoP scheme, not
	// Bearer. Forward-auth is the resource server for every proxied
	// upstream, so it must read the scheme its own clients are told to send.
	token, scheme, ok := middleware.ExtractAuthToken(authHeader, middleware.SchemeBearer, middleware.SchemeDPoP)
	if !ok || token == "" {
		w.Header().Set("WWW-Authenticate", middleware.WWWAuthenticate(oautherror.InvalidRequest, "", prm))
		http.Error(w, `{"error":"invalid_authorization_header"}`, http.StatusUnauthorized)
		return
	}

	// RFC 9449 §7.1: the DPoP scheme asserts a proof accompanies the token.
	// Refuse the request when it does not, so the scheme can never present a
	// token under weaker terms than Bearer. The proof is verified against
	// cnf.jkt after introspection.
	if scheme == middleware.SchemeDPoP && r.Header.Get("DPoP") == "" {
		w.Header().Set("WWW-Authenticate", middleware.WWWAuthenticate(oautherror.InvalidRequest, "DPoP scheme requires a DPoP proof header", prm))
		http.Error(w, `{"error":"invalid_request","error_description":"DPoP scheme requires a DPoP proof header"}`, http.StatusUnauthorized)
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
