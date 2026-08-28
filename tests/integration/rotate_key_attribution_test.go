package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// actSub returns the act.sub claim of a token minted from apiKey, or "" when
// the token carries no act claim at all. act.sub is the human the credential
// acts for — the first link in the "which human initiated this action" chain.
func actSub(t *testing.T, apiKey string) string {
	t.Helper()
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "api_key exchange should succeed")
	claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
	act, ok := claims["act"].(map[string]any)
	if !ok {
		return ""
	}
	sub, _ := act["sub"].(string)
	return sub
}

// rotate performs POST /agents/registry/{id}/rotate-key with the given extra
// headers merged over adminHeaders, and returns the new API key.
func rotate(t *testing.T, agentID string, extra map[string]string) string {
	t.Helper()
	headers := adminHeaders()
	for k, v := range extra {
		headers[k] = v
	}
	resp := post(t, adminPath("/agents/registry/"+agentID+"/rotate-key"), nil, headers)
	require.Equal(t, http.StatusOK, resp.StatusCode, "rotate-key should succeed")
	key, ok := decode(t, resp)["api_key"].(string)
	require.True(t, ok, "rotate-key response should carry api_key")
	require.NotEmpty(t, key)
	return key
}

// TestRotateKeyPreservesHumanAttribution locks in the audit-chain fix for
// #281. Rotation used to stamp CreatedBy as the literal "system:key_rotation",
// and the api_key grant copies CreatedBy into act.sub — so every token minted
// from a rotated key named the rotation subsystem instead of a human. The
// human→agent link in the delegation chain was lost, silently, on a routine
// operational action we actively encourage.
//
// Rotation changes the secret, not who is accountable. act.sub must keep
// naming a human across a rotation.
func TestRotateKeyPreservesHumanAttribution(t *testing.T) {
	// registerAgent stamps created_by "test-user", which becomes both the
	// identity's owner_user_id and the bootstrap key's CreatedBy.
	reg := registerAgent(t, uid("rotate-attribution"))

	before := actSub(t, reg.APIKey)
	require.Equal(t, "test-user", before,
		"baseline: an api_key token names the human who created the key")

	// The rotation caller is the better attribution when it is known: this
	// human performed the action, so name them rather than the registrant.
	rotatedKey := rotate(t, reg.AgentID, map[string]string{"X-User-ID": "alice@example.com"})
	assert.Equal(t, "alice@example.com", actSub(t, rotatedKey),
		"act.sub should name the human who rotated the key")

	// The regression itself: the subsystem literal must not appear while a
	// human is knowable.
	assert.NotEqual(t, "system:key_rotation", actSub(t, rotatedKey),
		"act.sub must never be the rotation subsystem when a human is known")
}

// TestRotateKeyFallsBackToIdentityOwner covers the unattributed caller — an
// internal service relay that rotates without sending X-User-ID. The identity's
// registered owner is still a human, so act.sub must name them rather than
// degrade to the subsystem literal.
func TestRotateKeyFallsBackToIdentityOwner(t *testing.T) {
	reg := registerAgent(t, uid("rotate-owner-fallback"))

	rotatedKey := rotate(t, reg.AgentID, nil)
	assert.Equal(t, "test-user", actSub(t, rotatedKey),
		"with no rotation caller, act.sub should fall back to the identity owner")
}

// TestRotateKeyRejectsSpoofedSystemCaller checks that the rotation path
// inherits the audit-spoof guard in TenantContextMiddleware. A caller that
// submits the reserved system: prefix must not get it reflected into act.sub,
// or an admin could forge subsystem attribution for their own rotation and
// make a deliberate action look automated in the audit trail.
func TestRotateKeyRejectsSpoofedSystemCaller(t *testing.T) {
	reg := registerAgent(t, uid("rotate-spoof-guard"))

	// Case-folding variants too: a downstream log query that filters with
	// ILIKE 'system:%' would otherwise read these as worker activity.
	for _, spoof := range []string{
		"system:key_rotation",
		"System:key_rotation",
		"SYSTEM:expired_sweep",
	} {
		rotatedKey := rotate(t, reg.AgentID, map[string]string{"X-User-ID": spoof})
		got := actSub(t, rotatedKey)
		assert.Equal(t, "test-user", got,
			"spoofed X-User-ID %q must be dropped and fall back to the owner; got %q", spoof, got)
	}
}
