package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

func chainIdentity() *domain.Identity {
	return &domain.Identity{
		WIMSEURI:     "spiffe://zeroid.test/acct/proj/agent/child",
		ExternalID:   "child",
		IdentityType: domain.IdentityTypeAgent,
		TrustLevel:   domain.TrustLevelFirstParty,
	}
}

// decodeAct round-trips an act claim through JSON, the way a requesting
// token's act is stored on the backchannel row and read back.
func decodeAct(t *testing.T, act map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(act)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// A chain minted under the legacy profile and stepped up under rfc8693 gets
// the requesting identity's attributes in the outermost act, with the
// delegating agent as the prior actor (#411).
func TestRequestingChainActors_LegacyActGainsActorAttributes(t *testing.T) {
	ident := chainIdentity()
	orchestrator := "spiffe://zeroid.test/acct/proj/agent/orchestrator"
	legacyAct := decodeAct(t, map[string]any{"sub": orchestrator})

	actors := requestingChainActors(ident, legacyAct, "spiffe://zeroid.test/acct/proj/agent/root")
	assert.Equal(t, map[string]any{
		"sub":           ident.WIMSEURI,
		"identity_type": string(ident.IdentityType),
		"trust_level":   string(ident.TrustLevel),
		"external_id":   ident.ExternalID,
		"act":           map[string]any{"sub": orchestrator},
	}, rfc8693Act(actors, legacyAct))
}

// The legacy act of a first-hop child names the chain's principal (the root
// workload or the person). The principal is `sub`, never an actor.
func TestRequestingChainActors_LegacyActNamingThePrincipalIsNotAnActor(t *testing.T) {
	ident := chainIdentity()
	root := "spiffe://zeroid.test/acct/proj/agent/root"
	actors := requestingChainActors(ident, map[string]any{"sub": root}, root)
	require.Len(t, actors, 1)
	assert.Equal(t, ident.WIMSEURI, actors[0].Sub)
	assert.Equal(t, ident.ExternalID, actors[0].ExternalID)
}

// A legacy act naming an end user does not put the person in act.
func TestRequestingChainActors_LegacyActNamingAUserIsNotAnActor(t *testing.T) {
	actors := requestingChainActors(chainIdentity(), map[string]any{"sub": "alice"}, "")
	require.Len(t, actors, 1)
	assert.Equal(t, chainIdentity().WIMSEURI, actors[0].Sub)
}

// Same-profile control: a chain minted under rfc8693 and stepped up under
// rfc8693 is issued the act it already carried, nested actors included.
func TestRequestingChainActors_RFC8693ActIsReproduced(t *testing.T) {
	ident := chainIdentity()
	issued := decodeAct(t, actorChainClaim([]domain.Actor{
		{Sub: ident.WIMSEURI, IdentityType: string(ident.IdentityType), TrustLevel: string(ident.TrustLevel), ExternalID: ident.ExternalID},
		{Sub: "spiffe://zeroid.test/acct/proj/agent/orchestrator"},
		{Sub: "root-client"},
	}))

	actors := requestingChainActors(ident, issued, "spiffe://zeroid.test/acct/proj/agent/root")
	assert.Equal(t, issued, rfc8693Act(actors, issued))
}

func TestRequestingChainActors_NoActIsTheCurrentActorAlone(t *testing.T) {
	actors := requestingChainActors(chainIdentity(), nil, "")
	require.Len(t, actors, 1)
	assert.Equal(t, string(domain.TrustLevelFirstParty), actors[0].TrustLevel)
}

func TestRFC8693Act(t *testing.T) {
	rfcShaped := map[string]any{"sub": "spiffe://x/agent/a", "identity_type": "agent"}
	legacyShaped := map[string]any{"sub": "spiffe://x/agent/orchestrator"}
	actors := []domain.Actor{{Sub: "spiffe://x/agent/b", IdentityType: "agent"}}

	assert.Equal(t, actorChainClaim(actors), rfc8693Act(actors, legacyShaped), "an actor chain wins over a verbatim act")
	assert.Equal(t, actorChainClaim(actors), rfc8693Act(actors, rfcShaped), "an actor chain wins over a verbatim act")
	assert.Equal(t, rfcShaped, rfc8693Act(nil, rfcShaped), "an act already in the rfc8693 shape is kept")
	assert.Nil(t, rfc8693Act(nil, legacyShaped), "a legacy act names no current actor, so it is not emitted")
	assert.Nil(t, rfc8693Act(nil, nil))
}
