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
	afterRevoke := introspect(t, tokenBefore)
	assert.False(t, afterRevoke["active"].(bool),
		"previously-issued token must be revoked after agent deactivation")

	// New api_key grant request must be rejected. Either the key has been
	// revoked (invalid_grant at key lookup) or the identity status gate
	// trips (invalid_grant at identity check). Both are correct.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"api_key grant must reject deactivated agent")
	body := decode(t, resp)
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
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     oauthClient.ClientID,
		"client_secret": oauthClient.ClientSecret,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"client_credentials must reject deactivated identity")
	body := decode(t, resp)
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
	assert.Equal(t, "identity_lifecycle", found["source"])
}

// TestIdentityUpdateToDeactivatedRunsCleanup verifies that the centralized
// cleanup fires when the status transition happens via the generic
// PUT /identities/{id} path, not only via AgentService.DeactivateAgent. This
// guards the original #89 bypass: any route that sets status to deactivated
// must perform the full cleanup, not just the dedicated agent endpoint.
func TestIdentityUpdateToDeactivatedRunsCleanup(t *testing.T) {
	ext := uid("deactivate-via-update")
	reg := registerAgent(t, ext)

	// Issue a token while the identity is still active.
	issueResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, issueResp.StatusCode)
	token := decode(t, issueResp)["access_token"].(string)
	require.True(t, introspect(t, token)["active"].(bool))

	// Deactivate via the generic identity update — not the agent endpoint.
	patchResp, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+reg.AgentID),
		map[string]any{"status": "deactivated"}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patchResp.StatusCode, "PATCH /identities/{id} should succeed")
	_ = patchResp.Body.Close()

	// Existing token must be revoked by the centralized cleanup.
	assert.False(t, introspect(t, token)["active"].(bool),
		"PATCH /identities status=deactivated must trigger credential revocation")
}

// TestAdminIssueOnDeactivatedIdentityRejected verifies the IssueCredential gate
// closes the admin /credentials/issue bypass. Even an admin cannot mint a
// fresh credential for a deactivated identity.
func TestAdminIssueOnDeactivatedIdentityRejected(t *testing.T) {
	ext := uid("admin-issue-deactivated")
	reg := registerAgent(t, ext)

	// Deactivate.
	deact, err := doRaw(t, http.MethodPost, adminPath("/agents/registry/"+reg.AgentID+"/deactivate"), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deact.StatusCode)
	_ = deact.Body.Close()

	// Try the admin /credentials/issue endpoint — must fail.
	issueResp := post(t, adminPath("/credentials/issue"), map[string]any{
		"identity_id": reg.AgentID,
		"scopes":      []string{"data:read"},
	}, adminHeaders())
	assert.GreaterOrEqual(t, issueResp.StatusCode, 400,
		"admin /credentials/issue must reject deactivated identity")
	assert.Less(t, issueResp.StatusCode, 600)
}

// TestDeleteIdentityRunsCleanup verifies DeleteIdentity sweeps linked tokens
// before removing the identity row. Otherwise, credentials with the deleted
// identity_id would survive (FK set to NULL) and remain valid until TTL.
func TestDeleteIdentityRunsCleanup(t *testing.T) {
	ext := uid("delete-cleanup")
	reg := registerAgent(t, ext)

	issueResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, issueResp.StatusCode)
	token := decode(t, issueResp)["access_token"].(string)
	require.True(t, introspect(t, token)["active"].(bool))

	// DELETE /identities/{id} — permanent removal.
	delResp, err := doRaw(t, http.MethodDelete, adminPath("/identities/"+reg.AgentID), nil, adminHeaders())
	require.NoError(t, err)
	require.True(t, delResp.StatusCode >= 200 && delResp.StatusCode < 300,
		"DELETE /identities/{id} should succeed")
	_ = delResp.Body.Close()

	// Token must be revoked — cleanup ran before delete.
	assert.False(t, introspect(t, token)["active"].(bool),
		"DELETE /identities must revoke credentials before removing the identity row")
}
