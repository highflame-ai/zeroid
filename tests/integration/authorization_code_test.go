package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthorizationCodeCLIFlow exercises the full PKCE authorization_code flow
// for a CLI client (non-MCP): auth code JWT → 90-day RS256 access token, no refresh token.
func TestAuthorizationCodeCLIFlow(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testCLIClientID, "user-cli-001", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	accessToken := token["access_token"].(string)
	assert.Equal(t, "Bearer", token["token_type"])
	assert.NotEmpty(t, accessToken)

	// CLI tokens are 90 days (7776000 s).
	assert.EqualValues(t, 90*24*3600, token["expires_in"], "CLI access token TTL should be 90 days")

	// CLI clients do NOT receive a refresh token.
	assert.Empty(t, token["refresh_token"], "CLI clients must not receive a refresh token")

	// Introspect: token must be active with the correct subject.
	result := introspect(t, accessToken)
	assert.True(t, result["active"].(bool))
	assert.Equal(t, "user-cli-001", result["sub"])
	assert.Equal(t, testAccountID, result["account_id"])
	assert.Equal(t, testProjectID, result["project_id"])
}

// TestAuthorizationCodeWrongVerifier verifies that a mismatched PKCE code_verifier
// is rejected, preventing auth code replay.
func TestAuthorizationCodeWrongVerifier(t *testing.T) {
	_, challenge := buildPKCEPair(t)
	wrongVerifier, _ := buildPKCEPair(t) // different pair
	code := buildAuthCode(t, testCLIClientID, "user-pkce-fail", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": wrongVerifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestAuthorizationCodeRedirectURIMismatch verifies that a redirect_uri that
// doesn't match the one in the auth code is rejected.
func TestAuthorizationCodeRedirectURIMismatch(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testCLIClientID, "user-ruri-fail", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  "http://evil.example.com/callback",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestAuthorizationCodeMCPFlow exercises the authorization_code flow for an MCP
// client: auth code → short-lived (1h) access token + refresh token.
func TestAuthorizationCodeMCPFlow(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-mcp-001", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	accessToken := token["access_token"].(string)
	assert.Equal(t, "Bearer", token["token_type"])
	assert.NotEmpty(t, accessToken)

	// MCP access tokens are short-lived (1 hour).
	assert.EqualValues(t, 3600, token["expires_in"], "MCP access token TTL should be 1 hour")

	// MCP clients receive a refresh token for long-running workflows.
	refreshToken, ok := token["refresh_token"].(string)
	require.True(t, ok, "MCP clients must receive a refresh_token")
	assert.NotEmpty(t, refreshToken)
	assert.Contains(t, refreshToken, "zid_rt_", "refresh token must have zid_rt_ prefix")

	// Introspect the access token.
	result := introspect(t, accessToken)
	assert.True(t, result["active"].(bool))
	assert.Equal(t, "user-mcp-001", result["sub"])
}

// TestRefreshTokenFlow verifies that presenting a valid refresh token issues a
// new access token and a new refresh token (single-use rotation).
func TestRefreshTokenFlow(t *testing.T) {
	// Step 1: Get initial tokens via authorization_code (MCP client).
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-rt-001", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	initial := decode(t, resp)
	refreshToken := initial["refresh_token"].(string)

	// Step 2: Exchange refresh token for a new access token.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     testMCPClientID,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	refreshed := decode(t, resp)
	newAccessToken := refreshed["access_token"].(string)
	newRefreshToken, ok := refreshed["refresh_token"].(string)
	assert.NotEmpty(t, newAccessToken, "refresh must issue a new access token")
	require.True(t, ok, "refresh must issue a new refresh token")
	assert.NotEmpty(t, newRefreshToken)
	assert.NotEqual(t, refreshToken, newRefreshToken, "new refresh token must differ from the old one")

	// New access token must be active.
	result := introspect(t, newAccessToken)
	assert.True(t, result["active"].(bool))
	assert.Equal(t, "user-rt-001", result["sub"])
}

// TestRefreshTokenRotation verifies that a refresh token can only be used once —
// presenting the original token after rotation must be rejected.
func TestRefreshTokenRotation(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-rot-001", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	originalRefreshToken := decode(t, resp)["refresh_token"].(string)

	// First use — must succeed.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": originalRefreshToken,
		"client_id":     testMCPClientID,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	decode(t, resp) // consume body

	// Second use of the same (now-rotated) token — must be rejected.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": originalRefreshToken,
		"client_id":     testMCPClientID,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "rotated refresh token must be rejected on reuse")
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}
