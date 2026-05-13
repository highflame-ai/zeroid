package handler

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// ── Well-known types ─────────────────────────────────────────────────────────

type JWKSOutput struct {
	Body jwk.Set
}

type OAuthMetadataOutput struct {
	Body map[string]any
}

// ── Well-known routes ────────────────────────────────────────────────────────

func (a *API) registerWellKnownRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "jwks",
		Method:      http.MethodGet,
		Path:        "/.well-known/jwks.json",
		Summary:     "JSON Web Key Set",
		Tags:        []string{"Discovery"},
	}, a.jwksOp)

	huma.Register(api, huma.Operation{
		OperationID: "oauth-server-metadata",
		Method:      http.MethodGet,
		Path:        "/.well-known/oauth-authorization-server",
		Summary:     "OAuth 2.0 Authorization Server Metadata",
		Tags:        []string{"Discovery"},
	}, a.oauthMetadataOp)
}

func (a *API) jwksOp(_ context.Context, _ *struct{}) (*JWKSOutput, error) {
	return &JWKSOutput{Body: a.jwksSvc.KeySet()}, nil
}

func (a *API) oauthMetadataOp(_ context.Context, _ *struct{}) (*OAuthMetadataOutput, error) {
	return &OAuthMetadataOutput{Body: map[string]any{
		"issuer":                                a.issuer,
		"token_endpoint":                        a.baseURL + "/oauth2/token",
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"grant_types_supported": []string{
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"api_key",
			"urn:openid:params:grant-type:ciba",
		},
		"jwks_uri":                 a.baseURL + "/.well-known/jwks.json",
		"introspection_endpoint":   a.baseURL + "/oauth2/token/introspect",
		"revocation_endpoint":      a.baseURL + "/oauth2/token/revoke",
		"response_types_supported": []string{"token"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"ES256", "RS256"},

		// CIBA (OpenID CIBA Core 1.0) discovery metadata. The fields here
		// let CIBA-aware clients auto-discover that this AS supports
		// backchannel authentication and which delivery modes are wired.
		"backchannel_authentication_endpoint":        a.baseURL + "/oauth2/bc-authorize",
		"backchannel_token_delivery_modes_supported": []string{"poll", "ping", "push"},
		"backchannel_user_code_parameter_supported":  false,
		// We don't accept signed bc-authorize requests in v1 — clients
		// authenticate via standard client_secret_basic/post against the
		// backchannel endpoint. An empty array signals "no signing algs
		// supported" per the spec's MAY clause.
		"backchannel_authentication_request_signing_alg_values_supported": []string{},
	}}, nil
}
