package handler

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
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
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="missing_token"`)
		http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
		return
	}

	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_request"`)
		http.Error(w, `{"error":"invalid_authorization_header"}`, http.StatusUnauthorized)
		return
	}

	claims, err := a.oauthSvc.Introspect(r.Context(), token)
	if err != nil {
		log.Error().Err(err).Msg("auth/verify: introspect error")
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	active, _ := claims["active"].(bool)
	if !active {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
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
