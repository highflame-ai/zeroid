package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeactivatedAgentCannotIssueViaApiKey verifies that once an agent is
// deactivated, the api_key grant can no longer mint fresh tokens using that
// agent's key, and any previously-issued token is revoked.
//
// Guards the first security gap from issue #89: issuance paths must gate on
// identity.Status.IsUsable(), and DeactivateAgent must revoke active
// credentials and linked API keys.
func TestDeactivatedAgentCannotIssueViaApiKey(t *testing.T) {
	ext := uid("deactivate-apikey")
	reg := registerAgent(t, ext)
	require.NotEmpty(t, reg.APIKey)

	// Issue a token while active — should succeed.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokenBefore := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, tokenBefore)

	// Confirm it's active.
	pre := introspect(t, tokenBefore)
	assert.True(t, pre["active"].(bool), "token should be active before deactivation")

	// Deactivate the agent.
	deact, err := doRaw(t, http.MethodPost, adminPath("/agents/registry/"+reg.AgentID+"/deactivate"), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deact.StatusCode)
	_ = deact.Body.Close()

	// Existing token must now be inactive — cascade revocation on deactivate.
	post := introspect(t, tokenBefore)
	assert.False(t, post["active"].(bool),
		"previously-issued token must be revoked after agent deactivation")

	// New api_key grant request must be rejected. Either the key has been
	// revoked (invalid_grant at key lookup) or the identity status gate
	// trips (invalid_grant at identity check). Both are correct.
	resp = postInt(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"api_key grant must reject deactivated agent")
	body := decodeInt(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestDeactivatedAgentCannotIssueViaClientCredentials verifies the
// client_credentials grant rejects a deactivated identity. Covers the
// clientCredentials path where the identity is resolved via GetByExternalID
// — previously had no IsUsable() check.
func TestDeactivatedAgentCannotIssueViaClientCredentials(t *testing.T) {
	ext := uid("deactivate-cc")
	reg := registerAgent(t, ext)

	// Register a confidential OAuth client keyed on the same external_id so
	// client_credentials → identity resolution hits this agent.
	oauthClient := registerOAuthClient(t, ext, []string{"data:read"})

	// Issue via client_credentials while active — should succeed.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     oauthClient.ClientID,
		"client_secret": oauthClient.ClientSecret,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Deactivate the agent.
	deact, err := doRaw(t, http.MethodPost, adminPath("/agents/registry/"+reg.AgentID+"/deactivate"), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deact.StatusCode)
	_ = deact.Body.Close()

	// client_credentials request must now fail.
	resp = postInt(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     oauthClient.ClientID,
		"client_secret": oauthClient.ClientSecret,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"client_credentials must reject deactivated identity")
	body := decodeInt(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestDeactivationRevokesExistingCredentials verifies the cascade-revoke
// behavior on DeactivateAgent. Issues multiple credentials, deactivates, and
// confirms every one introspects as inactive.
func TestDeactivationRevokesExistingCredentials(t *testing.T) {
	ext := uid("deactivate-cascade")
	reg := registerAgent(t, ext)

	// Mint two tokens so we can verify both get swept on deactivation.
	tokens := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		r := post(t, "/oauth2/token", map[string]any{
			"grant_type": "api_key",
			"api_key":    reg.APIKey,
		}, nil)
		require.Equal(t, http.StatusOK, r.StatusCode)
		tokens = append(tokens, decode(t, r)["access_token"].(string))
	}

	// All active before deactivation.
	for _, tok := range tokens {
		assert.True(t, introspect(t, tok)["active"].(bool), "token should be active before deactivation")
	}

	// Deactivate.
	deact, err := doRaw(t, http.MethodPost, adminPath("/agents/registry/"+reg.AgentID+"/deactivate"), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deact.StatusCode)
	_ = deact.Body.Close()

	// All inactive after deactivation.
	for i, tok := range tokens {
		assert.False(t, introspect(t, tok)["active"].(bool),
			"token #%d must be revoked after agent deactivation", i)
	}
}

// TestDeactivationEmitsRetirementSignal verifies a high-severity retirement
// CAE signal is emitted so federated subscribers can react in near-real time
// without needing to poll introspection.
func TestDeactivationEmitsRetirementSignal(t *testing.T) {
	ext := uid("deactivate-signal")
	reg := registerAgent(t, ext)

	// Deactivate.
	deact, err := doRaw(t, http.MethodPost, adminPath("/agents/registry/"+reg.AgentID+"/deactivate"), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deact.StatusCode)
	_ = deact.Body.Close()

	// Query signals for this tenant and find the retirement event.
	resp := get(t, adminPath("/signals?limit=50"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	signals, ok := body["signals"].([]any)
	require.True(t, ok, "signals endpoint should return a signals array")

	var found map[string]any
	for _, s := range signals {
		sig := s.(map[string]any)
		if sig["identity_id"] == reg.AgentID && sig["signal_type"] == "retirement" {
			found = sig
			break
		}
	}
	require.NotNil(t, found, "a retirement signal for the deactivated agent must be present")
	assert.Equal(t, "high", found["severity"], "deactivation signal should be high severity")
	assert.Equal(t, "agent_deactivation", found["source"])
}

// postInt + decodeInt mirror the default `post`/`decode` helpers but do not
// invoke `require.Equal` on the status code, since the deactivation tests
// expect 400s that `require.Equal` would abort on before we can assert on
// the error body.
func postInt(t *testing.T, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	return doRequest(t, http.MethodPost, path, body, headers)
}

func decodeInt(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	return decode(t, resp)
}
