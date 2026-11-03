package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setStatus moves an identity to a new status through the generic identity
// update, the path every status change goes through.
func setStatus(t *testing.T, identityID, status string) {
	t.Helper()
	resp, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+identityID),
		map[string]any{"status": status}, adminHeaders())
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PATCH /identities/{id} status=%s", status)
}

// TestSuspensionRevokesLiveAndDelegatedCredentials verifies that suspending an
// identity cuts off the credentials it already holds, not only new issuance.
// Before, a suspended identity's live token, and the token a sub-agent got by
// delegation from it, kept working until they expired, and no revocation event
// fired, so a subscriber that enforces from those events never learned.
func TestSuspensionRevokesLiveAndDelegatedCredentials(t *testing.T) {
	// root (client_credentials) → sub-agent (token_exchange, parent_jti=root)
	rootID := uid("suspend-root")
	registerIdentity(t, rootID, []string{"data:read"})
	rootClient := registerOAuthClient(t, rootID, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     rootClient.ClientID,
		"client_secret": rootClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rootToken := decode(t, resp)["access_token"].(string)
	rootJTI := jtiOf(t, rootToken)
	rootIdentityID := identityIDFromToken(t, rootToken)

	subKey := generateKey(t)
	subIdentity := registerIdentity(t, uid("suspend-sub"), []string{"data:read"}, ecPublicKeyPEM(t, subKey))
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": rootToken,
		"actor_token":   buildAssertion(t, subKey, subIdentity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	subToken := decode(t, resp)["access_token"].(string)
	subJTI := jtiOf(t, subToken)

	require.True(t, introspect(t, rootToken)["active"].(bool))
	require.True(t, introspect(t, subToken)["active"].(bool))
	require.Empty(t, revocationCapture.forJTI(rootJTI), "no event before suspension")
	require.Empty(t, revocationCapture.forJTI(subJTI), "no event before suspension")

	setStatus(t, rootIdentityID, "suspended")

	assert.False(t, introspect(t, rootToken)["active"].(bool),
		"the suspended identity's live token must be revoked")
	assert.False(t, introspect(t, subToken)["active"].(bool),
		"a token delegated from the suspended identity must be revoked by the cascade")

	// Synchronous dispatch (set in TestMain) ⇒ events are already captured.
	rootEvents := revocationCapture.forJTI(rootJTI)
	subEvents := revocationCapture.forJTI(subJTI)
	require.Len(t, rootEvents, 1, "the suspended identity's JTI must fire exactly one event")
	require.Len(t, subEvents, 1, "the delegated JTI must fire too, or a subscriber keeps serving it")
	for _, e := range append(rootEvents, subEvents...) {
		assert.Equal(t, "identity_suspended", e.Reason)
	}

	// The sub-agent's own identity is not suspended: it can still mint its own.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":  buildAssertion(t, subKey, subIdentity.WIMSEURI),
		"scope":      "data:read",
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the sub-agent's own identity must stay usable")
	_ = resp.Body.Close()
}

// TestSuspensionIsReversible verifies that a suspension, unlike a deactivation,
// keeps the identity's API keys: issuance is refused while suspended, and a
// reactivated identity mints fresh credentials with the same key.
func TestSuspensionIsReversible(t *testing.T) {
	reg := registerAgent(t, uid("suspend-reversible"))
	issue := func() *http.Response {
		return post(t, "/oauth2/token", map[string]any{
			"grant_type": "api_key",
			"api_key":    reg.APIKey,
		}, nil)
	}

	resp := issue()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	before := decode(t, resp)["access_token"].(string)

	setStatus(t, reg.AgentID, "suspended")

	assert.False(t, introspect(t, before)["active"].(bool), "the live token must be revoked on suspension")
	resp = issue()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "issuance must be refused while suspended")
	assert.Equal(t, "invalid_grant", decode(t, resp)["error"])

	setStatus(t, reg.AgentID, "active")

	resp = issue()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the API key must still work after reactivation")
	after := decode(t, resp)["access_token"].(string)
	assert.True(t, introspect(t, after)["active"].(bool))
	assert.False(t, introspect(t, before)["active"].(bool), "reactivation must not revive a revoked token")
}

// TestSuspensionEmitsSuspendedSignal verifies the CAE signal names the
// suspension, so a subscriber can tell it from a retirement.
func TestSuspensionEmitsSuspendedSignal(t *testing.T) {
	reg := registerAgent(t, uid("suspend-signal"))

	setStatus(t, reg.AgentID, "suspended")

	resp := get(t, adminPath("/signals?limit=50"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	signals, ok := decode(t, resp)["signals"].([]any)
	require.True(t, ok, "signals endpoint should return a signals array")

	var types []string
	for _, s := range signals {
		sig := s.(map[string]any)
		if sig["identity_id"] == reg.AgentID {
			types = append(types, sig["signal_type"].(string))
			if sig["signal_type"] == "identity_suspended" {
				assert.Equal(t, "high", sig["severity"])
				assert.Equal(t, "identity_lifecycle", sig["source"])
			}
		}
	}
	assert.Contains(t, types, "identity_suspended")
	assert.NotContains(t, types, "retirement", "a suspension is not a retirement")
}
