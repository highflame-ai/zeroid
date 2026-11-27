package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/mockidp"
)

// The depth limit rests on a token at depth d naming at most d+1 actors. These
// tests build chains of each shape to the limit and check that the deepest
// token's act names every actor, and that a re-scope or a CIBA approval at the
// limit, which add no depth, keep it whole.

// TestDelegationDepth_PersonChainWithRootActorAtLimit: an ID-token exchange
// mints the person's token with the bound agent as act at depth 0, so the
// chain's first actor comes from the root token's act, not its client_id. A
// re-scope by that agent adds no depth. Fifteen delegations later the token
// names all 16 actors; a re-scope and a CIBA approval at depth 15 keep them,
// and the next delegation is refused.
func TestDelegationDepth_PersonChainWithRootActorAtLimit(t *testing.T) {
	p := newP1C(t)
	person := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, nil), map[string]any{"scope": "tools:read"})
	require.Equal(t, http.StatusOK, person.StatusCode, "body=%s", person.RawBody)
	require.Equal(t, []string{p.agent.wimse}, actChain(t, decodeIssuedTokenClaims(t, person.AccessToken)))

	rescoped := delegate(t, p.f, person.AccessToken, p.agent)
	require.Nil(t, rescoped["claims"].(map[string]any)["delegation_depth"], "a re-scope adds no depth")
	token := rescoped["token"].(string)

	want := []string{p.agent.wimse}
	var current tiAgent
	for hop := 1; hop <= delegationDepthLimit; hop++ {
		current = p.tn.agentWithDepth(t, delegationDepthLimit)
		next := delegate(t, p.f, token, current)
		token = next["token"].(string)
		want = append([]string{current.wimse}, want...)
	}
	claims := decodeIssuedTokenClaims(t, token)
	assert.EqualValues(t, delegationDepthLimit, claims["delegation_depth"])
	assert.Equal(t, "user_hf_alice", claims["sub"])
	require.Len(t, want, domain.MaxActorChainDepth)
	assert.Equal(t, want, actChain(t, claims), "every actor, current first, back to the agent the person's token named")

	t.Run("a re-scope at the limit keeps every actor", func(t *testing.T) {
		again := delegate(t, p.f, token, current)["claims"].(map[string]any)
		assert.EqualValues(t, delegationDepthLimit, again["delegation_depth"])
		assert.Equal(t, want, actChain(t, again))
	})

	t.Run("a CIBA approval at the limit keeps every actor", func(t *testing.T) {
		approved := newCIBARunner(t, p.f, p.tn).run(t, token, nil)
		assert.EqualValues(t, delegationDepthLimit, approved["delegation_depth"])
		assert.Equal(t, want, actChain(t, approved))
	})

	t.Run("the next delegation is refused, whatever the actor's policy says", func(t *testing.T) {
		over := p.tn.agentWithDepth(t, delegationDepthLimit)
		setInDB(t, "credential_policies", over.policyID, "max_delegation_depth = ?", 25)
		resp := postFederation(t, p.f.http.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": token,
			"actor_token":   actorAssertion(t, over.key, over.wimse),
			"scope":         "tools:read",
		})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		var body map[string]any
		require.NoError(t, json.Unmarshal([]byte(resp.RawBody), &body))
		assert.Equal(t, "policy_violation", body["error"])
		assert.Contains(t, body["error_description"], fmt.Sprintf("delegation depth %d exceeds the maximum of %d", delegationDepthLimit+1, delegationDepthLimit))
	})
}

// TestDelegationDepth_BrokerPersonChainAtLimit: a person's token from the
// trusted-broker exchange has no act. Fifteen delegations from it name every
// delegate, then the root token's client when it has one.
func TestDelegationDepth_BrokerPersonChainAtLimit(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}
	policyID := tn.policyWith(t, scopes, map[string]any{"max_delegation_depth": delegationDepthLimit})
	token, alice := tn.userRoot(t, scopes)
	root := decodeJWTPayload(t, token)
	require.NotContains(t, root, "act", "a root grant names no actor")

	var want []string
	if cid, _ := root["client_id"].(string); cid != "" {
		want = []string{cid}
	}
	for hop := 1; hop <= delegationDepthLimit; hop++ {
		body, wimse := tn.exchange(t, policyID, uid(fmt.Sprintf("broker-depth-%02d", hop)), scopes, token)
		token = body["access_token"].(string)
		want = append([]string{wimse}, want...)
	}
	claims := decodeJWTPayload(t, token)
	assert.EqualValues(t, delegationDepthLimit, claims["delegation_depth"])
	assert.Equal(t, alice, claims["sub"], "the person stays the principal")
	assert.LessOrEqual(t, len(want), domain.MaxActorChainDepth)
	assert.Equal(t, want, actChain(t, claims), "every actor is named, current first")
}
