package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issueClientRegisterToken provisions a confidential client whose only allowed
// scope is `client:register`, then runs the client_credentials grant against it
// to mint an initial access token suitable for POST /oauth2/register.
func issueClientRegisterToken(t *testing.T) string {
	t.Helper()
	agentID := uid("dcr-registrant")
	registerIdentity(t, agentID, []string{"client:register"})
	client := registerOAuthClient(t, agentID, []string{"client:register"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "client:register",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "client_credentials for client:register must succeed")
	body := decode(t, resp)
	token, _ := body["access_token"].(string)
	require.NotEmpty(t, token, "expected access_token in response")
	return token
}

// TestDCRRegisterCreateReadUpdateDelete walks the RFC 7591 → 7592 lifecycle:
// register → GET → PUT → DELETE, with auth switching from the initial access
// token (registration) to the registration_access_token (management).
func TestDCRRegisterCreateReadUpdateDelete(t *testing.T) {
	iat := issueClientRegisterToken(t)

	// POST /oauth2/register (RFC 7591)
	regResp := post(t, "/oauth2/register", map[string]any{
		"client_name":                "Acme M2M Integration",
		"grant_types":                []string{"client_credentials"},
		"scope":                      "billing:read billing:write",
		"token_endpoint_auth_method": "client_secret_post",
		"software_id":                "com.acme.integration",
		"software_version":           "1.0.0",
		"contacts":                   []string{"ops@acme.example"},
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusCreated, regResp.StatusCode)
	registered := decode(t, regResp)
	clientID, _ := registered["client_id"].(string)
	clientSecret, _ := registered["client_secret"].(string)
	regToken, _ := registered["registration_access_token"].(string)
	require.NotEmpty(t, clientID, "registration must return client_id")
	require.NotEmpty(t, clientSecret, "registration must return plain client_secret once")
	require.NotEmpty(t, regToken, "registration must return registration_access_token once")
	assert.Equal(t, "Acme M2M Integration", registered["client_name"])

	mgmtHeaders := map[string]string{"Authorization": "Bearer " + regToken}

	// GET /oauth2/register/{client_id} (RFC 7592)
	getResp := get(t, "/oauth2/register/"+clientID, mgmtHeaders)
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	fetched := decode(t, getResp)
	assert.Equal(t, clientID, fetched["client_id"])
	assert.Equal(t, "Acme M2M Integration", fetched["client_name"])
	_, hasSecretInGet := fetched["client_secret"]
	assert.False(t, hasSecretInGet, "GET must NOT re-reveal client_secret (RFC 7592)")
	_, hasRegTokenInGet := fetched["registration_access_token"]
	assert.False(t, hasRegTokenInGet, "GET must NOT re-reveal registration_access_token")

	// PUT /oauth2/register/{client_id} (RFC 7592 — full replacement)
	putResp := doRequest(t, http.MethodPut, "/oauth2/register/"+clientID, map[string]any{
		"client_name":                "Acme M2M Integration (renamed)",
		"grant_types":                []string{"client_credentials"},
		"scope":                      "billing:read",
		"token_endpoint_auth_method": "client_secret_post",
	}, mgmtHeaders)
	require.Equal(t, http.StatusOK, putResp.StatusCode)
	updated := decode(t, putResp)
	assert.Equal(t, "Acme M2M Integration (renamed)", updated["client_name"])
	assert.Equal(t, "billing:read", updated["scope"], "PUT must perform full replacement (scope narrowed)")

	// DELETE /oauth2/register/{client_id} (RFC 7592)
	delResp := doRequest(t, http.MethodDelete, "/oauth2/register/"+clientID, nil, mgmtHeaders)
	require.Equal(t, http.StatusNoContent, delResp.StatusCode)
	_ = delResp.Body.Close()

	// Subsequent GET must 401 — the row is gone, so the registration_access_token check fails.
	missingResp := get(t, "/oauth2/register/"+clientID, mgmtHeaders)
	assert.Equal(t, http.StatusUnauthorized, missingResp.StatusCode)
	_ = missingResp.Body.Close()
}

// TestDCRWithoutInitialAccessTokenRejected verifies that POST /oauth2/register
// requires an initial access token in the Authorization header.
func TestDCRWithoutInitialAccessTokenRejected(t *testing.T) {
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "Should Not Register",
		"grant_types": []string{"client_credentials"},
	}, nil)
	// Huma rejects with 422 for missing required header; either 401/422 is acceptable
	// shape (the body always carries an OAuth error code in our handler path).
	require.True(t, resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusUnprocessableEntity,
		"missing Authorization on POST /oauth2/register should be rejected; got %d", resp.StatusCode)
}

// TestDCRInsufficientScopeRejected verifies that an access token without the
// `client:register` scope cannot register clients even with a valid signature.
func TestDCRInsufficientScopeRejected(t *testing.T) {
	// Mint a token whose only scope is something unrelated.
	agentID := uid("dcr-wrongscope")
	registerIdentity(t, agentID, []string{"billing:read"})
	client := registerOAuthClient(t, agentID, []string{"billing:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "billing:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token, _ := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, token)

	regResp := post(t, "/oauth2/register", map[string]any{
		"client_name": "Should Not Register",
		"grant_types": []string{"client_credentials"},
	}, map[string]string{"Authorization": "Bearer " + token})
	assert.Equal(t, http.StatusForbidden, regResp.StatusCode, "token without client:register scope must be 403")
	errBody := decode(t, regResp)
	assert.Equal(t, "insufficient_scope", errBody["error"])
}
