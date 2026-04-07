package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCAECriticalSignalRevokesCredential verifies the core CAE contract:
// a CRITICAL severity signal automatically revokes all active credentials
// for the affected identity, and the next introspection returns active:false.
func TestCAECriticalSignalRevokesCredential(t *testing.T) {
	agentID := uid("cae-critical-agent")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	// Agent gets a valid token.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)["access_token"].(string)

	// Confirm token is active before signal.
	result := introspect(t, token)
	require.True(t, result["active"].(bool), "token must be active before CAE signal")

	// Fetch identity ID from introspection for the signal payload.
	identityID := identityIDFromToken(t, token)

	// Platform injects a CRITICAL anomalous_behavior signal.
	signalResp := post(t, "/api/v1/signals/ingest", map[string]any{
		"identity_id": identityID,
		"signal_type": "anomalous_behavior",
		"severity":    "critical",
		"source":      "integration-test",
		"payload":     map[string]any{"reason": "test revocation"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, signalResp.StatusCode)
	signalResp.Body.Close()

	// Give the in-process revocation goroutine a moment to complete.
	time.Sleep(100 * time.Millisecond)

	// Token must now be inactive.
	result = introspect(t, token)
	assert.False(t, result["active"].(bool), "token must be inactive after CRITICAL CAE signal")
}

// TestCAEHighSignalRevokesCredential verifies that HIGH severity also triggers revocation
// (only low and medium leave credentials active).
func TestCAEHighSignalRevokesCredential(t *testing.T) {
	agentID := uid("cae-high-agent")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)["access_token"].(string)
	identityID := identityIDFromToken(t, token)

	signalResp := post(t, "/api/v1/signals/ingest", map[string]any{
		"identity_id": identityID,
		"signal_type": "anomalous_behavior",
		"severity":    "high",
		"source":      "integration-test",
		"payload":     map[string]any{},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, signalResp.StatusCode)
	signalResp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	result := introspect(t, token)
	assert.False(t, result["active"].(bool), "token must be inactive after HIGH CAE signal")
}

// TestCAELowSignalDoesNotRevokeCredential verifies that LOW severity signals
// are recorded but do not automatically revoke credentials.
func TestCAELowSignalDoesNotRevokeCredential(t *testing.T) {
	agentID := uid("cae-low-agent")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)["access_token"].(string)
	identityID := identityIDFromToken(t, token)

	signalResp := post(t, "/api/v1/signals/ingest", map[string]any{
		"identity_id": identityID,
		"signal_type": "anomalous_behavior",
		"severity":    "low",
		"source":      "integration-test",
		"payload":     map[string]any{},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, signalResp.StatusCode)
	signalResp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	// Token must still be active — low severity does not revoke.
	result := introspect(t, token)
	assert.True(t, result["active"].(bool), "LOW severity signal must not revoke credentials")
}

// TestCAESignalRevokesAllActiveCredentials verifies that when multiple tokens are
// active for the same identity, a critical signal revokes all of them.
func TestCAESignalRevokesAllActiveCredentials(t *testing.T) {
	agentID := uid("cae-multi-token-agent")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	// Issue two separate tokens for the same agent.
	getToken := func() string {
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return decode(t, resp)["access_token"].(string)
	}

	token1 := getToken()
	token2 := getToken()
	identityID := identityIDFromToken(t, token1)

	// Both should be active.
	assert.True(t, introspect(t, token1)["active"].(bool))
	assert.True(t, introspect(t, token2)["active"].(bool))

	// Ingest critical signal once.
	signalResp := post(t, "/api/v1/signals/ingest", map[string]any{
		"identity_id": identityID,
		"signal_type": "credential_change",
		"severity":    "critical",
		"source":      "integration-test",
		"payload":     map[string]any{},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, signalResp.StatusCode)
	signalResp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	// Both tokens must be inactive.
	assert.False(t, introspect(t, token1)["active"].(bool), "token1 must be revoked")
	assert.False(t, introspect(t, token2)["active"].(bool), "token2 must be revoked")
}

// TestCAESignalCascadesRevocationToChildren verifies that revoking a parent
// credential via a CAE signal also invalidates all downstream credentials
// that were issued via RFC 8693 token_exchange against that parent.
//
// Chain under test:
//
//	orchestrator (depth=0) → sub-agent (depth=1) → grandchild (depth=2)
//
// Firing a CRITICAL signal against the orchestrator must cause all three
// tokens to become inactive on introspection.
func TestCAESignalCascadesRevocationToChildren(t *testing.T) {
	// ── Orchestrator: client_credentials (depth=0) ──────────────────────────
	orchID := uid("casc-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// ── Sub-agent: token_exchange from orchestrator (depth=1) ───────────────
	sub1Key := generateKey(t)
	sub1Identity := registerIdentity(t, uid("casc-sub1"), []string{"data:read"}, ecPublicKeyPEM(t, sub1Key))

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   buildAssertion(t, sub1Key, sub1Identity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	depth1Token := decode(t, resp)["access_token"].(string)

	// ── Grandchild: token_exchange from sub-agent (depth=2) ─────────────────
	sub2Key := generateKey(t)
	sub2Identity := registerIdentity(t, uid("casc-sub2"), []string{"data:read"}, ecPublicKeyPEM(t, sub2Key))

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": depth1Token,
		"actor_token":   buildAssertion(t, sub2Key, sub2Identity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	depth2Token := decode(t, resp)["access_token"].(string)

	// ── All three tokens must be active before the signal ───────────────────
	require.True(t, introspect(t, orchToken)["active"].(bool), "orchestrator token must be active before signal")
	require.True(t, introspect(t, depth1Token)["active"].(bool), "depth-1 token must be active before signal")
	require.True(t, introspect(t, depth2Token)["active"].(bool), "depth-2 token must be active before signal")

	// ── Fire CRITICAL signal against the orchestrator identity ───────────────
	orchIdentityID := identityIDFromToken(t, orchToken)
	signalResp := post(t, "/api/v1/signals/ingest", map[string]any{
		"identity_id": orchIdentityID,
		"signal_type": "anomalous_behavior",
		"severity":    "critical",
		"source":      "integration-test",
		"payload":     map[string]any{"reason": "cascade revocation test"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, signalResp.StatusCode)
	signalResp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	// ── Orchestrator's own token must be inactive ────────────────────────────
	assert.False(t, introspect(t, orchToken)["active"].(bool),
		"orchestrator token must be inactive after CRITICAL signal")

	// ── Downstream tokens must be inactive via cascade ───────────────────────
	assert.False(t, introspect(t, depth1Token)["active"].(bool),
		"depth-1 token must be inactive: parent credential was revoked")
	assert.False(t, introspect(t, depth2Token)["active"].(bool),
		"depth-2 token must be inactive: grandparent credential was revoked")
}

// TestSignalListEndpoint verifies that ingested signals are queryable.
func TestSignalListEndpoint(t *testing.T) {
	agentID := uid("signal-list-agent")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)["access_token"].(string)
	identityID := identityIDFromToken(t, token)

	signalResp := post(t, "/api/v1/signals/ingest", map[string]any{
		"identity_id": identityID,
		"signal_type": "ip_change",
		"severity":    "medium",
		"source":      "integration-test",
		"payload":     map[string]any{"old_ip": "1.2.3.4", "new_ip": "5.6.7.8"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, signalResp.StatusCode)
	signalResp.Body.Close()

	listResp := get(t, "/api/v1/signals", adminHeaders())
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	body := decode(t, listResp)
	signals, ok := body["signals"].([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(signals), 1)
}
