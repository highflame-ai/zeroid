package service

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

func TestActorChainClaim_CurrentActorOutermostWithAttributes(t *testing.T) {
	got := actorChainClaim([]domain.Actor{
		{Sub: "wimse://c", IdentityType: "agent", TrustLevel: "first_party", ExternalID: "agent-c"},
		{Sub: "wimse://b", IdentityType: "agent", TrustLevel: "unverified", ExternalID: "agent-b"},
		{Sub: "agent-a"},
	})
	assert.Equal(t, map[string]any{
		"sub":           "wimse://c",
		"identity_type": "agent",
		"trust_level":   "first_party",
		"external_id":   "agent-c",
		// Prior actors carry only `sub`: they are informational (RFC 8693 §4.1).
		"act": map[string]any{
			"sub": "wimse://b",
			"act": map[string]any{"sub": "agent-a"},
		},
	}, got)
}

// The cap bounds token size. Past it the DEEPEST prior actors go, never the
// current actor, since access control uses only the current actor.
func TestActorChainClaim_CapsAtMaxDepthDroppingTheDeepest(t *testing.T) {
	actors := make([]domain.Actor, domain.MaxActorChainDepth+3)
	for i := range actors {
		actors[i] = domain.Actor{Sub: fmt.Sprintf("actor-%02d", i)}
	}
	claim := actorChainClaim(actors)

	var subs []string
	for act := claim; act != nil; {
		subs = append(subs, act["sub"].(string))
		next, _ := act["act"].(map[string]any)
		act = next
	}
	require.Len(t, subs, domain.MaxActorChainDepth)
	assert.Equal(t, "actor-00", subs[0], "the current actor is always kept")
	assert.Equal(t, fmt.Sprintf("actor-%02d", domain.MaxActorChainDepth-1), subs[len(subs)-1])
}

func tokenWith(t *testing.T, claims map[string]any) jwt.Token {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	return tok
}

func TestPriorActorsOf_ReadsTheRFC8693Chain(t *testing.T) {
	tok := tokenWith(t, map[string]any{
		"principal_type": "user",
		"act": map[string]any{
			"sub":         "wimse://b",
			"trust_level": "first_party",
			"act":         map[string]any{"sub": "agent-a"},
		},
	})
	assert.Equal(t, []domain.Actor{{Sub: "wimse://b"}, {Sub: "agent-a"}}, priorActorsOf(tok),
		"prior actors keep only their sub")
}

// A legacy token's single-level act holds a delegating orchestrator or an end
// user depending on the grant. Reading it as an actor chain would put a person
// in act, which the design forbids.
func TestPriorActorsOf_IgnoresTheLegacyShape(t *testing.T) {
	tok := tokenWith(t, map[string]any{
		"act": map[string]any{"sub": "alice"},
	})
	assert.Nil(t, priorActorsOf(tok))
}

func TestPriorActorsOf_RootHasNone(t *testing.T) {
	assert.Nil(t, priorActorsOf(tokenWith(t, map[string]any{"principal_type": "workload"})))
}

func TestAccessTokenTyp(t *testing.T) {
	jwtPolicy := &domain.CredentialPolicy{JWTTyp: domain.JWTTypJWT}
	atPolicy := &domain.CredentialPolicy{JWTTyp: domain.JWTTypAccessToken}
	defaultPolicy := &domain.CredentialPolicy{}
	for _, tc := range []struct {
		name   string
		policy *domain.CredentialPolicy
		want   string
	}{
		{"defaults to at+jwt with no policy", nil, "at+jwt"},
		{"defaults to at+jwt with an unset policy", defaultPolicy, "at+jwt"},
		{"honours a policy choosing JWT", jwtPolicy, "JWT"},
		{"honours a policy choosing at+jwt", atPolicy, "at+jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, accessTokenTyp(tc.policy))
		})
	}
}
