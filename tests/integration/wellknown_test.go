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
	// RFC 7517 §4.2 — stock OIDC / JWT libraries (PyJWT, jose) and every
	// WIF validator (Anthropic, Azure, GCP, AWS) reject keys whose use is
	// anything other than "sig" or "enc". SPIFFE-strict consumers fetch
	// /.well-known/spiffe-trust-bundle.json instead (see test below).
	assert.Equal(t, "sig", ecKey["use"])
	assert.Equal(t, testKeyID, ecKey["kid"])
	assert.Equal(t, "P-256", ecKey["crv"])
	assert.NotEmpty(t, ecKey["x"], "EC key must have x coordinate")
	assert.NotEmpty(t, ecKey["y"], "EC key must have y coordinate")
	// Private key material must never appear in JWKS.
	assert.Empty(t, ecKey["d"], "private key component must not appear in JWKS")
}

// TestSPIFFETrustBundleEndpoint verifies that
// /.well-known/spiffe-trust-bundle.json serves the same keys as the JWKS but
// with use="JWT-SVID" per JWT-SVID §4, plus the SPIFFE bundle envelope fields.
func TestSPIFFETrustBundleEndpoint(t *testing.T) {
	resp := get(t, "/.well-known/spiffe-trust-bundle.json", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := decode(t, resp)
	keys, ok := body["keys"].([]any)
	require.True(t, ok, "response must have a 'keys' array")
	require.GreaterOrEqual(t, len(keys), 1, "trust bundle should contain at least one key")

	var ecKey map[string]any
	for _, k := range keys {
		km := k.(map[string]any)
		if km["kid"] == testKeyID {
			ecKey = km
			break
		}
	}
	require.NotNil(t, ecKey, "trust bundle must contain a key with kid=%s", testKeyID)

	// JWT-SVID §4 requires use=JWT-SVID on every key in a SPIFFE bundle.
	assert.Equal(t, "JWT-SVID", ecKey["use"])
	assert.Equal(t, "EC", ecKey["kty"])
	assert.Equal(t, "ES256", ecKey["alg"])
	assert.Equal(t, "P-256", ecKey["crv"])
	assert.Empty(t, ecKey["d"], "private key component must not appear in trust bundle")

	// SPIFFE trust-bundle envelope fields.
	assert.NotNil(t, body["spiffe_sequence"], "must advertise spiffe_sequence")
	assert.NotNil(t, body["spiffe_refresh_hint"], "must advertise spiffe_refresh_hint")
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
	assert.True(t, grantSet["urn:openid:params:grant-type:ciba"], "must support CIBA grant")

	// CIBA (OpenID CIBA Core 1.0) discovery fields.
	assert.NotEmpty(t, body["backchannel_authentication_endpoint"],
		"must advertise backchannel_authentication_endpoint for CIBA-aware clients")

	deliveryModes, ok := body["backchannel_token_delivery_modes_supported"].([]any)
	require.True(t, ok, "must declare backchannel_token_delivery_modes_supported")
	modeSet := make(map[string]bool, len(deliveryModes))
	for _, m := range deliveryModes {
		modeSet[m.(string)] = true
	}
	assert.True(t, modeSet["poll"], "must advertise poll delivery mode")
	assert.True(t, modeSet["ping"], "must advertise ping delivery mode")
	assert.True(t, modeSet["push"], "must advertise push delivery mode")

	// RFC 7591 dynamic client registration endpoint.
	assert.NotEmpty(t, body["registration_endpoint"], "must advertise registration_endpoint for RFC 7591")

	// RFC 9449 DPoP signing alg advertisement.
	dpopAlgs, ok := body["dpop_signing_alg_values_supported"].([]any)
	require.True(t, ok, "must declare dpop_signing_alg_values_supported for RFC 9449")
	algSet := make(map[string]bool, len(dpopAlgs))
	for _, a := range dpopAlgs {
		s, ok := a.(string)
		require.True(t, ok, "dpop_signing_alg_values_supported entries must be strings")
		algSet[s] = true
	}
	assert.True(t, algSet["ES256"], "DPoP must advertise ES256")
	assert.True(t, algSet["RS256"], "DPoP must advertise RS256")
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
