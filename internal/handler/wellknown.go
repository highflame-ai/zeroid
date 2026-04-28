package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// ── Well-known types ─────────────────────────────────────────────────────────

// JWKSOutput is the published /.well-known/jwks.json payload. We use a generic
// map (not jwk.Set) because we need to rewrite the "use" field on each key
// from "sig" (what jwx stores internally for verifier compatibility) to
// "jwt-svid" (what JWT-SVID §4 requires SPIFFE bundles to advertise).
type JWKSOutput struct {
	Body map[string]any
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
	// Marshal the in-memory keyset, then rewrite each key's "use" field to
	// "jwt-svid" before returning. JWT-SVID §4 requires this value on every
	// key in a SPIFFE bundle. We don't store it that way internally because
	// lestrrat-go/jwx's verifier skips keys whose use is anything other than
	// "sig" — see internal/signing/jwks.go.
	raw, err := json.Marshal(a.jwksSvc.KeySet())
	if err != nil {
		return nil, fmt.Errorf("marshal jwks: %w", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("unmarshal jwks: %w", err)
	}
	if keys, ok := body["keys"].([]any); ok {
		for _, k := range keys {
			if km, ok := k.(map[string]any); ok {
				km["use"] = "jwt-svid"
			}
		}
	}
	return &JWKSOutput{Body: body}, nil
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
