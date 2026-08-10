// RFC 8414 (OAuth 2.0 Authorization Server Metadata) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// Happy-path coverage of /.well-known/oauth-authorization-server lives in
// wellknown_test.go. This file pins the §2 required-fields contract every
// RFC 8414 client depends on — issuer, jwks_uri, token_endpoint,
// grant_types_supported, response_types_supported.

package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fetchASMetadata returns the parsed JSON body of /.well-known/oauth-authorization-server.
func fetchASMetadata(t *testing.T) map[string]any {
	t.Helper()
	resp := get(t, "/.well-known/oauth-authorization-server", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decode(t, resp)
}

// ── RFC 8414 §2 — Authorization Server Metadata ─────────────────────────────

func TestRFC8414_S2_IssuerRequired(t *testing.T) {
	// RFC 8414 §2: "issuer REQUIRED. The authorization server's issuer
	//   identifier, which is a URL that uses the 'https' scheme and has no
	//   query or fragment components."
	body := fetchASMetadata(t)
	iss, ok := body["issuer"].(string)
	require.True(t, ok, "issuer REQUIRED")
	assert.NotEmpty(t, iss)
	assert.NotContains(t, iss, "?", "issuer URL MUST NOT have a query component")
	assert.NotContains(t, iss, "#", "issuer URL MUST NOT have a fragment component")
	assert.True(t, strings.HasPrefix(iss, "https://"),
		"issuer URL MUST use the https scheme (RFC 8414 §2) — caught a mis-configured Issuer")
}

func TestRFC8414_S2_TokenEndpointRequired(t *testing.T) {
	// RFC 8414 §2: "token_endpoint URL of the authorization server's token
	//   endpoint [RFC6749]. This is REQUIRED unless only the implicit grant
	//   type is supported." ZeroID supports machine-to-machine grants, so
	//   token_endpoint is required.
	body := fetchASMetadata(t)
	endpoint, _ := body["token_endpoint"].(string)
	assert.NotEmpty(t, endpoint, "token_endpoint REQUIRED")
	assert.Contains(t, endpoint, "/oauth2/token",
		"token_endpoint MUST point at the token endpoint path")
}

func TestRFC8414_S2_JwksUriRequiredWhenSigning(t *testing.T) {
	// RFC 8414 §2: "jwks_uri OPTIONAL. URL of the authorization server's JWK
	//   Set [JWK] document." ZeroID's policy is stricter — every deployment
	//   signs tokens, so jwks_uri MUST be advertised or downstream
	//   verifiers can't find the keys to verify with. The assertion
	//   enforces our policy.
	body := fetchASMetadata(t)
	jwks, _ := body["jwks_uri"].(string)
	assert.NotEmpty(t, jwks, "ZeroID policy: jwks_uri required (exceeds RFC OPTIONAL)")
	assert.Contains(t, jwks, "/.well-known/jwks.json")
}

func TestRFC8414_S2_GrantTypesSupportedListed(t *testing.T) {
	// RFC 8414 §2: "grant_types_supported OPTIONAL. JSON array containing a
	//   list of the OAuth 2.0 grant type values that this authorization
	//   server supports." If present, every advertised value must be a
	//   string and a recognised grant type identifier.
	body := fetchASMetadata(t)
	raw, _ := body["grant_types_supported"].([]any)
	require.NotEmpty(t, raw, "grant_types_supported is expected on a server with multiple grants")
	for _, g := range raw {
		s, ok := g.(string)
		require.True(t, ok, "every grant_types_supported entry MUST be a string")
		assert.NotEmpty(t, s)
	}
}

func TestRFC8414_S2_ResponseTypesSupportedListed(t *testing.T) {
	// RFC 8414 §2: "response_types_supported REQUIRED. JSON array containing
	//   a list of the OAuth 2.0 'response_type' values that this
	//   authorization server supports."
	body := fetchASMetadata(t)
	raw, ok := body["response_types_supported"].([]any)
	require.True(t, ok, "response_types_supported REQUIRED")
	require.NotEmpty(t, raw)
	for _, r := range raw {
		s, ok := r.(string)
		require.True(t, ok, "every response_types_supported entry MUST be a string")
		assert.NotEmpty(t, s)
	}
}

func TestRFC8414_S2_TokenEndpointAuthMethodsSupportedListed(t *testing.T) {
	// RFC 8414 §2: "token_endpoint_auth_methods_supported OPTIONAL. JSON
	//   array containing a list of client authentication methods supported."
	//   ZeroID accepts client_secret_post and client_secret_basic, so both
	//   should be advertised.
	body := fetchASMetadata(t)
	raw, _ := body["token_endpoint_auth_methods_supported"].([]any)
	methods := make(map[string]bool)
	for _, m := range raw {
		if s, ok := m.(string); ok {
			methods[s] = true
		}
	}
	assert.True(t, methods["client_secret_post"],
		"client_secret_post MUST be advertised — it's the M2M default")
	assert.True(t, methods["client_secret_basic"],
		"client_secret_basic MUST be advertised — RFC 7591 §2 default for DCR-registered clients")
}

// ── RFC 8414 §3.2 — Path is /.well-known/oauth-authorization-server ─────────

func TestRFC8414_S3_WellKnownPathIsExact(t *testing.T) {
	// RFC 8414 §3: "The path component of the [metadata URL] is
	//   /.well-known/oauth-authorization-server."
	resp := get(t, "/.well-known/oauth-authorization-server", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"GET /.well-known/oauth-authorization-server MUST return 200")
	contentType := resp.Header.Get("Content-Type")
	assert.True(t, strings.HasPrefix(contentType, "application/json"),
		"AS metadata MUST be served as application/json; got %q", contentType)
}

// ── ADR 0010 — MCP Enterprise-Managed Authorization (ID-JAG) ────────────────

// TestADR0010_IDJAGGrantProfileAdvertised verifies the AS metadata advertises
// the ID-JAG authorization grant profile (ADR 0010 D6). EMA-capable MCP clients
// read authorization_grant_profiles_supported to discover that this AS accepts
// an Identity Assertion Authorization Grant via the jwt-bearer grant.
func TestADR0010_IDJAGGrantProfileAdvertised(t *testing.T) {
	body := fetchASMetadata(t)

	// jwt-bearer (the grant the ID-JAG is presented through) must still be listed.
	grants, _ := body["grant_types_supported"].([]any)
	foundJWTBearer := false
	for _, g := range grants {
		if s, _ := g.(string); s == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			foundJWTBearer = true
		}
	}
	require.True(t, foundJWTBearer,
		"grant_types_supported MUST still advertise jwt-bearer (the ID-JAG presentation grant)")

	// The new field: the ID-JAG grant profile URN.
	profiles, ok := body["authorization_grant_profiles_supported"].([]any)
	require.True(t, ok, "authorization_grant_profiles_supported MUST be present (ADR 0010 D6)")
	found := false
	for _, p := range profiles {
		if s, _ := p.(string); s == "urn:ietf:params:oauth:grant-profile:id-jag" {
			found = true
		}
	}
	require.True(t, found,
		"authorization_grant_profiles_supported MUST advertise the ID-JAG grant profile")
}

// TestASMetadata_AuthorizationEndpointAdvertised — RFC 8414 §2 makes
// `authorization_endpoint` REQUIRED when the AS supports the
// authorization_code grant, and we advertise that grant.
//
// The omission was not merely untidy (#263). `authorization_endpoint` is a
// required field on the MCP Python SDK's OAuthMetadata model, so the entire
// document failed to parse; the client concluded the AS had no metadata,
// skipped CIMD — which is gated on client_id_metadata_document_supported
// being readable — and silently fell back to dynamic client registration.
// A discovery document that cannot be parsed is worse than one that is
// absent, because the client proceeds on wrong assumptions.
func TestASMetadata_AuthorizationEndpointAdvertised(t *testing.T) {
	meta := fetchASMetadata(t)

	grants, _ := meta["grant_types_supported"].([]any)
	require.Contains(t, grants, "authorization_code",
		"precondition: this test only applies while we advertise authorization_code")

	authzEndpoint, _ := meta["authorization_endpoint"].(string)
	require.NotEmpty(t, authzEndpoint,
		"RFC 8414 §2: authorization_endpoint is REQUIRED when authorization_code "+
			"is supported — without it a client cannot start the flow, and strict "+
			"metadata parsers reject the whole document")
	require.True(t, strings.HasSuffix(authzEndpoint, "/oauth2/authorize"),
		"authorization_endpoint must point at the real endpoint, got %q", authzEndpoint)

	// PKCE is mandatory on this endpoint (S256 only, no `plain`), so the
	// method list has to say so rather than leaving clients to guess.
	methods, _ := meta["code_challenge_methods_supported"].([]any)
	require.Equal(t, []any{"S256"}, methods,
		"code_challenge_methods_supported must advertise exactly S256")
}

// TestASMetadata_AuthorizationCodeAdvertisedOnlyWhenServable — discovery is a
// promise, and #263 showed what breaks when it is not kept.
//
// ZeroID advertised `authorization_code` and
// `client_id_metadata_document_supported` unconditionally, while
// /oauth2/authorize answered 503 on every deployment that registered no
// PrincipalResolver. An MCP client that believed the metadata skipped CIMD and
// silently fell back to dynamic client registration.
//
// This suite registers resolvers, so the grant MUST be advertised here. The
// negative case (empty chain omits it) is a unit-level property of
// API.SetAuthorizationCodeAvailable; this test pins the positive half and
// guards against the gate accidentally suppressing the grant on a deployment
// that can serve it.
func TestASMetadata_AuthorizationCodeAdvertisedOnlyWhenServable(t *testing.T) {
	meta := fetchASMetadata(t)

	grants, _ := meta["grant_types_supported"].([]any)
	require.Contains(t, grants, "authorization_code",
		"this suite registers PrincipalResolvers, so /oauth2/authorize can serve "+
			"the flow and metadata must advertise it")

	// The endpoint is advertised unconditionally: it exists and answers, and
	// omitting it makes the whole document unparseable to strict clients (the
	// MCP Python SDK requires the field).
	require.NotEmpty(t, meta["authorization_endpoint"],
		"authorization_endpoint must always be present (RFC 8414 §2)")

	// CIMD only applies to the authorization_code flow, so it rides the same
	// gate. Advertising it while the flow is unavailable is the same broken
	// promise.
	if cimd, ok := meta["client_id_metadata_document_supported"].(bool); ok && cimd {
		require.Contains(t, grants, "authorization_code",
			"client_id_metadata_document_supported must never be advertised "+
				"without the authorization_code grant it applies to")
	}
}

// TestASMetadata_AuthorizationCodeFieldsRideOneGate — every VALUE that only
// describes the authorization_code flow appears together or not at all, while
// the RFC 8414 §2 REQUIRED members stay present either way.
//
// Both branches are exercised: the suite's server has resolvers registered, so
// the servable side is the default, and SetAuthorizationCodeAvailable flips the
// other. Without that flip the unavailable branch — the entire point of the
// gate — would never execute, since every integration test shares one server.
func TestASMetadata_AuthorizationCodeFieldsRideOneGate(t *testing.T) {
	// Servable: the suite registers PrincipalResolvers.
	meta := fetchASMetadata(t)
	requireAuthorizationCodeAdvertised(t, meta, true)

	// Unavailable: flip the deployer predicate, then restore. Safe to mutate
	// shared state because no integration test calls t.Parallel().
	testZeroIDServer.SetAuthorizationCodeAvailable(func() bool { return false })
	defer testZeroIDServer.SetAuthorizationCodeAvailable(nil)

	requireAuthorizationCodeAdvertised(t, fetchASMetadata(t), false)

	// Restoring the built-in guess must bring the values back — the predicate
	// is dynamic by design.
	testZeroIDServer.SetAuthorizationCodeAvailable(nil)
	requireAuthorizationCodeAdvertised(t, fetchASMetadata(t), true)
}

// requireAuthorizationCodeAdvertised asserts the whole gated group is coherent
// for the expected servability, and that the always-required members survive.
func requireAuthorizationCodeAdvertised(t *testing.T, meta map[string]any, want bool) {
	t.Helper()

	grants, _ := meta["grant_types_supported"].([]any)
	require.Contains(t, meta, "response_types_supported",
		"RFC 8414 §2: response_types_supported is REQUIRED unconditionally — "+
			"omitting it makes the document invalid, which is the failure this "+
			"PR exists to fix")
	require.NotEmpty(t, meta["authorization_endpoint"],
		"authorization_endpoint is never gated: omitting it breaks strict parsers")

	responseTypes, _ := meta["response_types_supported"].([]any)
	_, hasPKCEMethods := meta["code_challenge_methods_supported"]
	cimd, _ := meta["client_id_metadata_document_supported"].(bool)

	if want {
		require.Contains(t, grants, "authorization_code")
		require.Equal(t, []any{"code"}, responseTypes)
		require.True(t, hasPKCEMethods,
			"code_challenge_methods_supported must accompany the advertised grant")

		return
	}

	require.NotContains(t, grants, "authorization_code")
	require.Empty(t, responseTypes,
		"the member stays present (RFC 8414 requires it) but must be empty — "+
			"advertising \"code\" on an AS that cannot serve it is the same lie "+
			"as advertising the grant")
	require.False(t, hasPKCEMethods,
		"code_challenge_methods_supported is OPTIONAL, so it is omitted rather "+
			"than emptied when the flow is unavailable")
	require.False(t, cimd,
		"CIMD applies only to authorization_code, which is not advertised")
}
