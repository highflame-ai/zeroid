package service

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/highflame-ai/zeroid/domain"
)

// act.client_id is written on the CURRENT actor only. A resource server pairs
// it with act.sub to identify the actor, so a prior actor carrying one would
// let a nested level read as an authenticated client.
func TestActorChainClaim_ClientIDOnCurrentActorOnly(t *testing.T) {
	got := actorChainClaim([]domain.Actor{
		{Sub: "spiffe://d/a/p/service/gw", IdentityType: "service", ClientID: "gw"},
		{Sub: "spiffe://d/a/p/agent/b", ClientID: "must-not-appear"},
	})
	assert.Equal(t, "gw", got["client_id"])
	prior, _ := got["act"].(map[string]any)
	assert.Equal(t, map[string]any{"sub": "spiffe://d/a/p/agent/b"}, prior,
		"a prior actor carries only sub, never client_id")
}

// No client authentication, no claim: the field must not appear empty.
func TestActorChainClaim_NoClientIDWhenUnset(t *testing.T) {
	got := actorChainClaim([]domain.Actor{{Sub: "spiffe://d/a/p/agent/c", IdentityType: "agent"}})
	_, present := got["client_id"]
	assert.False(t, present)
}

// A verbatim act (a CIBA step-up into a requesting chain) keeps its actor but
// loses client_id: that grant did not authenticate the actor as a client.
func TestRFC8693Act_VerbatimActLosesClientID(t *testing.T) {
	parent := map[string]any{
		"sub":           "spiffe://d/a/p/service/gw",
		"identity_type": "service",
		"client_id":     "gw",
		"act":           map[string]any{"sub": "spiffe://d/a/p/agent/x"},
	}
	got := rfc8693Act(nil, parent)
	_, present := got["client_id"]
	assert.False(t, present, "a copied act must not carry the earlier grant's client authentication")
	assert.Equal(t, "spiffe://d/a/p/service/gw", got["sub"])
	assert.Equal(t, parent["act"], got["act"])
	assert.Equal(t, "gw", parent["client_id"], "the caller's map is not modified")
}

// An actor chain built by this grant keeps the client_id it set.
func TestRFC8693Act_ChainKeepsClientID(t *testing.T) {
	got := rfc8693Act([]domain.Actor{{Sub: "spiffe://d/a/p/service/gw", ClientID: "gw"}}, nil)
	assert.Equal(t, "gw", got["client_id"])
}

func TestWithoutActorClientID_NoClientIDReturnsSameMap(t *testing.T) {
	act := map[string]any{"sub": "x"}
	got := withoutActorClientID(act)
	got["probe"] = true
	assert.Equal(t, true, act["probe"], "no copy is made when there is nothing to remove")
}
