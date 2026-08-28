package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// actSub returns the act.sub claim of a token minted from apiKey, or "" when
// the token carries no act claim. act.sub is the human the credential acts
// for — the first link in the "which human initiated this action" chain.
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

// rotate performs POST /agents/registry/{id}/rotate-key with extra headers
// merged over adminHeaders, and returns the new API key.
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

// setIdentityAttribution writes owner_user_id and created_by directly. Both
// columns are invariant-protected through the API — registration requires an
// owner and UpdateIdentity cannot clear one — so the lower-precedence branches
// of rotationAttribution are only reachable from a deployer-imported or
// legacy row, which this reproduces.
func setIdentityAttribution(t *testing.T, identityID, ownerUserID, createdBy string) {
	t.Helper()
	_, err := testDB.NewUpdate().
		Table("identities").
		Set("owner_user_id = ?", ownerUserID).
		Set("created_by = ?", createdBy).
		Where("id = ?", identityID).
		Exec(context.Background())
	require.NoError(t, err)
}

// TestRotateKeyPreservesHumanAttribution locks in the audit-chain fix for
// #281. Rotation used to stamp CreatedBy as the literal "system:key_rotation",
// and the api_key grant copies CreatedBy into act.sub — so every token minted
// from a rotated key named the rotation subsystem instead of a human. The
// human→agent link was lost, silently, on a routine operational action.
func TestRotateKeyPreservesHumanAttribution(t *testing.T) {
	reg := registerAgent(t, uid("rotate-attribution"))
	setIdentityAttribution(t, reg.AgentID, "owner-alice", "registrant-carol")

	rotatedKey := rotate(t, reg.AgentID, nil)
	got := actSub(t, rotatedKey)

	assert.Equal(t, "owner-alice", got,
		"act.sub should name the identity owner after rotation")
	assert.NotEqual(t, "system:key_rotation", got,
		"the regression: act.sub must not be the rotation subsystem when a human is known")
}

// TestRotateKeyPrefersOwnerOverRotationOperator pins the precedence decision.
// act.sub means "the human this credential acts for", and the rotated key mints
// tokens for the rest of its life — so it must name the accountable owner, not
// the on-call operator who happened to rotate the key after a leak scare.
// Naming the operator would also leave every token disagreeing with its own
// owner_user_id claim, which never happens for a freshly registered agent.
//
// The operator is not lost: RotateKey logs created_by, and identity_audit_logs
// records the X-User-ID caller separately.
func TestRotateKeyPrefersOwnerOverRotationOperator(t *testing.T) {
	reg := registerAgent(t, uid("rotate-owner-wins"))
	setIdentityAttribution(t, reg.AgentID, "owner-alice", "registrant-carol")

	rotatedKey := rotate(t, reg.AgentID, map[string]string{"X-User-ID": "sre-bob"})
	assert.Equal(t, "owner-alice", actSub(t, rotatedKey),
		"the rotation operator must not displace the accountable owner in act.sub")
}

// TestRotateKeyFallsBackToIdentityCreatedBy covers a row whose owner_user_id is
// empty but whose created_by still names a human — a row predating the
// ownership invariant, or one a deployer imported. The identity store already
// answers "who is the human for this identity" as
// COALESCE(NULLIF(owner_user_id, ”), created_by); rotation must not stamp the
// system literal over attribution sitting one column away.
func TestRotateKeyFallsBackToIdentityCreatedBy(t *testing.T) {
	reg := registerAgent(t, uid("rotate-createdby-fallback"))
	setIdentityAttribution(t, reg.AgentID, "", "registrant-carol")

	rotatedKey := rotate(t, reg.AgentID, nil)
	assert.Equal(t, "registrant-carol", actSub(t, rotatedKey),
		"with no owner, act.sub should fall back to the identity's created_by")
}

// TestRotateKeyFallsBackToRotationCaller covers the last human available: the
// row names nobody, but a human performed the rotation. Naming them beats
// naming a subsystem.
func TestRotateKeyFallsBackToRotationCaller(t *testing.T) {
	reg := registerAgent(t, uid("rotate-caller-fallback"))
	setIdentityAttribution(t, reg.AgentID, "", "")

	rotatedKey := rotate(t, reg.AgentID, map[string]string{"X-User-ID": "sre-bob"})
	assert.Equal(t, "sre-bob", actSub(t, rotatedKey),
		"with no human on the row, act.sub should name the rotation caller")
}

// TestRotateKeySystemPrincipalWhenNoHumanKnown pins the exact audit literal for
// the case where nothing names a human. Operators and log queries that filter
// with ILIKE 'system:%' depend on the string, and it is assembled by
// concatenation, so an assertion on the whole value is what pins it.
func TestRotateKeySystemPrincipalWhenNoHumanKnown(t *testing.T) {
	reg := registerAgent(t, uid("rotate-no-human"))
	setIdentityAttribution(t, reg.AgentID, "", "")

	rotatedKey := rotate(t, reg.AgentID, nil)
	assert.Equal(t, "system:key_rotation", actSub(t, rotatedKey),
		"with no human anywhere, act.sub should be the system principal verbatim")
}

// TestRotateKeyRejectsSpoofedSystemCaller checks the audit-spoof guard on every
// source, not only the HTTP header. TenantContextMiddleware drops a system:
// prefixed X-User-ID, but owner_user_id and created_by reach rotation from
// columns no write path filters — POST /agents/register takes created_by
// straight from the request body. A forged subsystem value from any source must
// not become act.sub, or a deliberate human action can be made to look
// automated.
func TestRotateKeyRejectsSpoofedSystemCaller(t *testing.T) {
	// Case-folding variants too: a downstream log query filtering with
	// ILIKE 'system:%' would otherwise read these as worker activity.
	spoofs := []string{"system:key_rotation", "System:key_rotation", "SYSTEM:expired_sweep"}

	t.Run("via X-User-ID header", func(t *testing.T) {
		reg := registerAgent(t, uid("rotate-spoof-header"))
		setIdentityAttribution(t, reg.AgentID, "owner-alice", "")
		for _, spoof := range spoofs {
			rotatedKey := rotate(t, reg.AgentID, map[string]string{"X-User-ID": spoof})
			assert.Equal(t, "owner-alice", actSub(t, rotatedKey),
				"spoofed X-User-ID %q must not reach act.sub", spoof)
		}
	})

	t.Run("via owner_user_id and created_by columns", func(t *testing.T) {
		for _, spoof := range spoofs {
			reg := registerAgent(t, uid("rotate-spoof-column"))
			setIdentityAttribution(t, reg.AgentID, spoof, spoof)

			rotatedKey := rotate(t, reg.AgentID, map[string]string{"X-User-ID": "sre-bob"})
			assert.Equal(t, "sre-bob", actSub(t, rotatedKey),
				"spoofed column value %q must be skipped in favour of a real human", spoof)
		}
	})
}

// TestRotateKeyOversizedCallerDoesNotLockOutAgent guards the foot-gun that
// rotation revokes the outgoing keys BEFORE it creates the replacement. An
// over-long X-User-ID would fail the INSERT against service_keys.created_by
// (VARCHAR(255)) and leave the identity with every key revoked and no
// replacement — a hard lockout triggered by a header. Before #281 CreatedBy was
// a fixed 19-character constant, so no caller input could reach that state.
//
// The row carries no owner and no created_by, so the caller is the only
// candidate and the oversized value is genuinely exercised rather than
// short-circuited by a higher-precedence source.
func TestRotateKeyOversizedCallerDoesNotLockOutAgent(t *testing.T) {
	reg := registerAgent(t, uid("rotate-oversized-caller"))
	setIdentityAttribution(t, reg.AgentID, "", "")

	oversized := make([]byte, 300)
	for i := range oversized {
		oversized[i] = 'x'
	}

	// rotate() requires 200: an unbounded value reaches the INSERT, fails it,
	// and returns 500 with every key already revoked.
	rotatedKey := rotate(t, reg.AgentID, map[string]string{"X-User-ID": string(oversized)})
	assert.Equal(t, "system:key_rotation", actSub(t, rotatedKey),
		"an oversized caller must be skipped, leaving the honest system principal")
}

// TestRotateKeyRejectsMalformedColumnAttribution covers padded and blank
// attribution on the identity row. A padded id matches nothing stored unpadded,
// so it is a silent audit break rather than a near-miss — IdentityService.
// OffboardOwner rejects the same shape for the same reason. These are reachable
// because POST /agents/register takes created_by straight from the request body
// with no normalisation.
//
// Not covered here: a padded X-User-ID. Go's HTTP layer trims optional
// whitespace around a header value, so a padded caller never reaches the
// service in the first place.
func TestRotateKeyRejectsMalformedColumnAttribution(t *testing.T) {
	for name, malformed := range map[string]string{
		"padded":          "owner-alice ",
		"whitespace only": "   ",
	} {
		t.Run(name, func(t *testing.T) {
			reg := registerAgent(t, uid("rotate-malformed-column"))
			setIdentityAttribution(t, reg.AgentID, malformed, malformed)

			rotatedKey := rotate(t, reg.AgentID, map[string]string{"X-User-ID": "sre-bob"})
			assert.Equal(t, "sre-bob", actSub(t, rotatedKey),
				"malformed column value %q must be skipped in favour of a real human", malformed)
		})
	}
}
