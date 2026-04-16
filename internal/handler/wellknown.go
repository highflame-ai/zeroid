package handler

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
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
		},
		"jwks_uri":                 a.baseURL + "/.well-known/jwks.json",
		"introspection_endpoint":   a.baseURL + "/oauth2/token/introspect",
		"revocation_endpoint":      a.baseURL + "/oauth2/token/revoke",
		"response_types_supported": []string{"token"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"ES256", "RS256"},
	}}, nil
}
