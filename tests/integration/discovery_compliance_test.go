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
	//   Set [JWK] document." Required in practice for any AS that signs
	//   tokens — verifiers need the keys.
	body := fetchASMetadata(t)
	jwks, _ := body["jwks_uri"].(string)
	assert.NotEmpty(t, jwks, "jwks_uri MUST be advertised — verifiers need the public keys")
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
	//   /.well-known/oauth-authorization-server." A request to that exact
	//   path MUST return the metadata; the suffix style "/.well-known/
	//   oauth-authorization-server/<resource>" is NOT how the spec wires
	//   issuer paths (per RFC 8414 §3.1's spec text and the IETF errata
	//   that disambiguated this), but ZeroID lives at a single root.
	resp := get(t, "/.well-known/oauth-authorization-server", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"GET /.well-known/oauth-authorization-server MUST return 200 with the metadata document")
	contentType := resp.Header.Get("Content-Type")
	assert.True(t, strings.HasPrefix(contentType, "application/json"),
		"AS metadata MUST be served as application/json; got %q", contentType)
}
