package integration_test

import (
	"fmt"
	"net/http"
	"strings"
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

// identityIDFromToken introspects a token and returns the identity_id claim.
// Assumes the introspect response contains "identity_id" or derives it from "sub".
func identityIDFromToken(t *testing.T, token string) string {
	t.Helper()
	result := introspect(t, token)

	// The introspect response may include identity_id directly.
	if id, ok := result["identity_id"].(string); ok && id != "" {
		return id
	}

	// Fall back: look up the identity by external_id from the sub claim.
	// sub = spiffe://{domain}/{account}/{project}/{identity_type}/{external_id}
	sub, ok := result["sub"].(string)
	require.True(t, ok, "introspect response must have sub claim")

	// Extract external_id from WIMSE URI.
	externalID, err := extractExternalIDFromWIMSE(sub)
	require.NoError(t, err)

	// Look up identity via list endpoint filtered by listing all and finding by external_id.
	listResp := get(t, "/api/v1/identities", adminHeaders())
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	body := decode(t, listResp)
	items, ok := body["identities"].([]any)
	require.True(t, ok)
	for _, item := range items {
		identity := item.(map[string]any)
		if identity["external_id"].(string) == externalID {
			return identity["id"].(string)
		}
	}
	t.Fatalf("could not find identity for external_id=%s", externalID)
	return ""
}

// extractExternalIDFromWIMSE parses spiffe://{domain}/{acct}/{proj}/{identity_type}/{external_id}.
func extractExternalIDFromWIMSE(wimseURI string) (string, error) {
	const prefix = "spiffe://" + testWIMSE + "/"
	if len(wimseURI) <= len(prefix) {
		return "", fmt.Errorf("invalid WIMSE URI: %s", wimseURI)
	}
	parts := strings.Split(wimseURI[len(prefix):], "/")
	if len(parts) != 4 {
		return "", fmt.Errorf("unexpected WIMSE URI format: %s (got %d parts)", wimseURI, len(parts))
	}
	return parts[3], nil
}
