package authjwt

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func claimsFrom(t *testing.T, claims map[string]any) *Claims {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	return extractClaims(tok)
}

// An rfc8693-profile exchanged token: Alice is the principal, agent C the
// current actor, B and A prior actors.
func rfc8693Chain(t *testing.T) *Claims {
	return claimsFrom(t, map[string]any{
		"sub":            "alice",
		"principal_type": "user",
		"client_id":      "agent-c",
		"act": map[string]any{
			"sub":           "spiffe://zeroid.test/a/p/agent/agent-c",
			"identity_type": "agent",
			"trust_level":   "first_party",
			"external_id":   "agent-c",
			"act": map[string]any{
				"sub": "spiffe://zeroid.test/a/p/agent/agent-b",
				"act": map[string]any{"sub": "agent-a"},
			},
		},
		"delegation_depth": 2,
	})
}

func TestClaims_RFC8693Profile(t *testing.T) {
	c := rfc8693Chain(t)
	assert.False(t, c.IsLegacyProfile())
	assert.Equal(t, PrincipalUser, c.PrincipalType())
	assert.Equal(t, "alice", c.Subject, "the principal stays sub")
	assert.Equal(t, "spiffe://zeroid.test/a/p/agent/agent-c", c.CurrentActor())
	assert.Equal(t, []string{"spiffe://zeroid.test/a/p/agent/agent-b", "agent-a"}, c.PriorActors())
	assert.NotContains(t, c.Custom, "principal_type", "a typed claim, not a custom one")
}

// Agent() built the agent from top-level attributes, which the rfc8693 profile
// moves into act, so it returned nil for every exchanged token, and its
// DelegatedBy was act.sub — the agent itself. It must read the current actor.
func TestClaims_AgentUnderRFC8693IsTheCurrentActor(t *testing.T) {
	a := rfc8693Chain(t).Agent()
	require.NotNil(t, a, "an exchanged token still describes its agent")
	assert.Equal(t, "spiffe://zeroid.test/a/p/agent/agent-c", a.Sub)
	assert.Equal(t, "agent-c", a.ExternalID)
	assert.Equal(t, "first_party", a.TrustLevel)
	assert.Equal(t, "spiffe://zeroid.test/a/p/agent/agent-b", a.DelegatedBy, "the delegator is the first prior actor, not the agent itself")
}

func TestClaims_RFC8693RootHasNoActor(t *testing.T) {
	c := claimsFrom(t, map[string]any{
		"sub": "spiffe://zeroid.test/a/p/agent/orch", "principal_type": "workload", "external_id": "orch",
	})
	assert.Equal(t, "spiffe://zeroid.test/a/p/agent/orch", c.CurrentActor(), "with no act, the actor is sub")
	assert.Nil(t, c.PriorActors())
	require.NotNil(t, c.Agent())
	assert.Equal(t, "orch", c.Agent().ExternalID)
}

// A legacy token's act names a delegator or a key's creator, so it is never
// read as the current actor or as actor history.
func TestClaims_LegacyProfile(t *testing.T) {
	c := claimsFrom(t, map[string]any{
		"sub":         "spiffe://zeroid.test/a/p/agent/agent-b",
		"external_id": "agent-b",
		"act":         map[string]any{"sub": "spiffe://zeroid.test/a/p/agent/orch"},
	})
	assert.True(t, c.IsLegacyProfile())
	assert.Empty(t, c.PrincipalType())
	assert.Equal(t, "spiffe://zeroid.test/a/p/agent/agent-b", c.CurrentActor())
	assert.Nil(t, c.PriorActors())
	a := c.Agent()
	require.NotNil(t, a)
	assert.Equal(t, "agent-b", a.ExternalID)
	assert.Equal(t, "spiffe://zeroid.test/a/p/agent/orch", a.DelegatedBy, "legacy Agent() is unchanged")
}

func TestClaims_ActorChainParsingIsBounded(t *testing.T) {
	act := map[string]any{"sub": "deepest"}
	for i := 0; i < 40; i++ {
		act = map[string]any{"sub": "actor", "act": act}
	}
	c := claimsFrom(t, map[string]any{"sub": "alice", "principal_type": "user", "act": act})
	assert.LessOrEqual(t, len(c.PriorActors()), maxActorChain)
}

// A typed act value goes through the JSON fallback, which must honour the same
// bound as the map path.
func TestClaims_ActorChainParsingIsBounded_TypedValue(t *testing.T) {
	type typedAct struct {
		Sub string    `json:"sub"`
		Act *typedAct `json:"act,omitempty"`
	}
	act := &typedAct{Sub: "deepest"}
	for i := 0; i < 40; i++ {
		act = &typedAct{Sub: "actor", Act: act}
	}
	got := parseActorClaims(act)
	require.NotNil(t, got)
	depth := 0
	for a := got; a != nil; a = a.Actor {
		depth++
	}
	assert.LessOrEqual(t, depth, maxActorChain)
}
