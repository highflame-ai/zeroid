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

// ProtectedResourceMetadataOutput is the RFC 9728 OAuth 2.0 Protected Resource
// Metadata document published at /.well-known/oauth-protected-resource. Agents
// that hit a 401 with a WWW-Authenticate: Bearer resource_metadata="…" header
// follow that breadcrumb to this document, then to the authorization server
// metadata it advertises.
type ProtectedResourceMetadataOutput struct {
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

	huma.Register(api, huma.Operation{
		OperationID: "oauth-protected-resource",
		Method:      http.MethodGet,
		Path:        "/.well-known/oauth-protected-resource",
		Summary:     "OAuth 2.0 Protected Resource Metadata (RFC 9728)",
		Tags:        []string{"Discovery"},
	}, a.protectedResourceMetadataOp)
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

// protectedResourceMetadataOp serves RFC 9728 OAuth 2.0 Protected Resource
// Metadata at /.well-known/oauth-protected-resource. The document points
// clients at this AS's metadata, which they fetch next to discover the token
// endpoint, JWKS, and supported grants.
//
// §2 field semantics:
//   - resource (REQUIRED): the canonical URL of the protected resource. ZeroID
//     is both the resource server and the authorization server in the
//     single-deployment topology, so resource == baseURL.
//   - authorization_servers: AS issuers a client SHOULD use; clients fetch
//     /.well-known/oauth-authorization-server from one of these.
//   - jwks_uri: the resource's own keyset for verifying signed responses.
//     ZeroID signs all tokens via the AS keyset, so we advertise the same
//     JWKS — verifiers don't need a separate resource keyset.
//   - bearer_methods_supported: how to present the access token. ZeroID
//     accepts the Authorization: Bearer header.
//
// resource_signing_alg_values_supported is intentionally NOT advertised:
// RFC 9728 §2 defines it as algs the resource uses *for signed responses*.
// ZeroID's /oauth2/token/introspect returns plain JSON (RFC 7662), not
// the JWT envelope from RFC 9701. When signed introspection lands, this
// field gets added in the same PR — not before.
func (a *API) protectedResourceMetadataOp(_ context.Context, _ *struct{}) (*ProtectedResourceMetadataOutput, error) {
	return &ProtectedResourceMetadataOutput{Body: map[string]any{
		"resource":                 a.baseURL,
		"resource_name":            "ZeroID",
		"authorization_servers":    []string{a.issuer},
		"jwks_uri":                 a.baseURL + "/.well-known/jwks.json",
		"bearer_methods_supported": []string{"header"},
		// RFC 9449 §5.3 — PRM-defined DPoP field. ZeroID will mint
		// DPoP-bound tokens when a client presents a DPoP proof at
		// /oauth2/token, but does not currently *require* DPoP for
		// resource access; bearer tokens are also accepted. The
		// per-resource policy that flips this to true lives in a later
		// PR alongside the per-resource enforcement check.
		//
		// Note: `dpop_signing_alg_values_supported` is RFC 9449 §5.1 AS
		// metadata, not PRM — it's already advertised in oauthMetadataOp.
		"dpop_bound_access_tokens_required": false,
	}}, nil
}
