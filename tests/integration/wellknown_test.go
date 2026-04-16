package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJWKSEndpoint verifies that /.well-known/jwks.json returns a valid JWKS
// containing exactly one ES256 P-256 key with the expected kid.
func TestJWKSEndpoint(t *testing.T) {
	resp := get(t, "/.well-known/jwks.json", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := decode(t, resp)
	keys, ok := body["keys"].([]any)
	require.True(t, ok, "response must have a 'keys' array")
	require.GreaterOrEqual(t, len(keys), 1, "JWKS should contain at least one key")

	// Find the ES256 key by kid.
	var ecKey map[string]any
	for _, k := range keys {
		km := k.(map[string]any)
		if km["kid"] == testKeyID {
			ecKey = km
			break
		}
	}
	require.NotNil(t, ecKey, "JWKS must contain a key with kid=%s", testKeyID)

	assert.Equal(t, "EC", ecKey["kty"])
	assert.Equal(t, "ES256", ecKey["alg"])
	assert.Equal(t, "sig", ecKey["use"])
	assert.Equal(t, testKeyID, ecKey["kid"])
	assert.Equal(t, "P-256", ecKey["crv"])
	assert.NotEmpty(t, ecKey["x"], "EC key must have x coordinate")
	assert.NotEmpty(t, ecKey["y"], "EC key must have y coordinate")
	// Private key material must never appear in JWKS.
	assert.Empty(t, ecKey["d"], "private key component must not appear in JWKS")
}

// TestOAuthServerMetadata verifies that /.well-known/oauth-authorization-server
// returns valid RFC 8414 metadata with the correct issuer and supported grant types.
func TestOAuthServerMetadata(t *testing.T) {
	resp := get(t, "/.well-known/oauth-authorization-server", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := decode(t, resp)
	assert.Equal(t, testIssuer, body["issuer"])
	assert.NotEmpty(t, body["token_endpoint"])
	assert.NotEmpty(t, body["jwks_uri"])

	grantTypes, ok := body["grant_types_supported"].([]any)
	require.True(t, ok, "must declare grant_types_supported")

	grantSet := make(map[string]bool)
	for _, g := range grantTypes {
		grantSet[g.(string)] = true
	}
	assert.True(t, grantSet["client_credentials"], "must support client_credentials")
	assert.True(t, grantSet["urn:ietf:params:oauth:grant-type:jwt-bearer"], "must support jwt_bearer")
	assert.True(t, grantSet["urn:ietf:params:oauth:grant-type:token-exchange"], "must support token_exchange")
}

// TestHealthEndpoint verifies that /health returns 200.
func TestHealthEndpoint(t *testing.T) {
	resp := get(t, "/health", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestReadyEndpoint verifies that /ready returns 200 when the database is reachable.
func TestReadyEndpoint(t *testing.T) {
	resp := get(t, "/ready", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
}
