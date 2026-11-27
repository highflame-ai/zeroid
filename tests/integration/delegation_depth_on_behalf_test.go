package integration_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// TestDelegationDepth_OnBehalfExchangeAtLimit: the service-token on-behalf
// exchange adds a hop, the gateway, at the head of the subject's act chain.
// A subject one hop short of the limit yields a token at the limit whose act
// claim names the gateway and every actor beneath it, back to the root
// grant's client. A subject already at the limit is refused with
// policy_violation: no credential policy governs the gateway's carrier, so
// the issuance chokepoint is what holds the chain to the limit here.
func TestDelegationDepth_OnBehalfExchangeAtLimit(t *testing.T) {
	gw := gateway(t)
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}
	policyID := tn.policyWith(t, scopes, map[string]any{"max_delegation_depth": delegationDepthLimit})

	token, _ := tn.workloadRoot(t, policyID, scopes)
	rootClientID := decodeJWTPayload(t, token)["client_id"].(string)
	require.NotEmpty(t, rootClientID)

	var want []string
	var short string // the token one hop short of the limit
	for hop := 1; hop <= delegationDepthLimit; hop++ {
		body, wimse := tn.exchange(t, policyID, uid(fmt.Sprintf("obo-depth-%02d", hop)), scopes, token)
		token = body["access_token"].(string)
		want = append([]string{wimse}, want...)
		if hop == delegationDepthLimit-1 {
			short = token
		}
	}

	code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(short, receiverResource)), nil)
	require.Equal(t, http.StatusOK, code, "a subject at depth %d may be exchanged on behalf: %v", delegationDepthLimit-1, got)
	claims := decodeJWTPayload(t, got["access_token"].(string))
	assert.EqualValues(t, delegationDepthLimit, claims["delegation_depth"])
	chain := actChain(t, claims)
	assert.Len(t, chain, domain.MaxActorChainDepth, "the gateway's token fills the act claim without overflowing it")
	assert.Equal(t, append(append([]string{gw.identity.WIMSEURI}, want[1:]...), rootClientID), chain,
		"the gateway, then every actor of the subject's chain, back to the root grant's client")

	code, got = postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(token, receiverResource)), nil)
	requireSvcRefused(t, http.StatusBadRequest, "policy_violation", got, code)
	assert.Contains(t, got["error_description"], fmt.Sprintf("delegation depth %d exceeds", delegationDepthLimit+1))
}
