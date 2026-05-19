package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// ── Well-known types ─────────────────────────────────────────────────────────

// JWKSOutput is the RFC 7517 JSON Web Key Set published at
// /.well-known/jwks.json. Keys carry use="sig" per RFC 7517 §4.2 so stock
// OIDC / JWT libraries (PyJWT, jose, every WIF validator) accept the bundle.
// SPIFFE-strict consumers should fetch /.well-known/spiffe-trust-bundle.json
// instead.
type JWKSOutput struct {
	Body jwk.Set
}

// SPIFFETrustBundleOutput is the SPIFFE JWT-SVID trust bundle published at
// /.well-known/spiffe-trust-bundle.json. The "keys" entries carry
// use="JWT-SVID" per JWT-SVID §4. We use a generic map (not jwk.Set) because
// we both rewrite "use" on each key and add the SPIFFE bundle envelope fields
// ("spiffe_sequence", "spiffe_refresh_hint") that aren't part of RFC 7517.
type SPIFFETrustBundleOutput struct {
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
		Summary:     "JSON Web Key Set (RFC 7517)",
		Tags:        []string{"Discovery"},
	}, a.jwksOp)

	huma.Register(api, huma.Operation{
		OperationID: "spiffe-trust-bundle",
		Method:      http.MethodGet,
		Path:        "/.well-known/spiffe-trust-bundle.json",
		Summary:     "SPIFFE JWT-SVID trust bundle",
		Tags:        []string{"Discovery"},
	}, a.spiffeTrustBundleOp)

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

// spiffeRefreshHintSeconds is the suggested polling interval for SPIFFE
// consumers. 5 minutes matches the typical SPIRE trust-bundle refresh cadence.
const spiffeRefreshHintSeconds = 300

func (a *API) spiffeTrustBundleOp(_ context.Context, _ *struct{}) (*SPIFFETrustBundleOutput, error) {
	// Marshal the in-memory keyset, then rewrite each key's "use" field from
	// "sig" (which the keyset stores so lestrrat-go/jwx's verifier accepts it)
	// to "JWT-SVID" — the value JWT-SVID §4 requires SPIFFE bundles to
	// advertise. The SPIFFE bundle envelope adds "spiffe_sequence" and
	// "spiffe_refresh_hint" alongside the standard "keys" array.
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
				km["use"] = "JWT-SVID"
			}
		}
	}
	body["spiffe_sequence"] = 1
	body["spiffe_refresh_hint"] = spiffeRefreshHintSeconds
	return &SPIFFETrustBundleOutput{Body: body}, nil
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

		// RFC 7591 dynamic client registration.
		"registration_endpoint": a.baseURL + "/oauth2/register",

		// RFC 9449 — Demonstrating Proof of Possession (DPoP). Algorithms the
		// token endpoint will accept on the DPoP header. Symmetric algs are
		// excluded by spec.
		"dpop_signing_alg_values_supported": []string{"ES256", "RS256"},

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
