package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// A delegated grant is the three-way intersection
//
//	requested ∩ the subject token's own scopes ∩ the actor's ceiling
//
// When it comes out empty, one message served all three causes — and the
// three need OPPOSITE fixes: name the scopes, widen the delegator, or widen
// the sub-agent. These tests pin that the denial says which term was empty.
//
// The error CODE stays invalid_scope, and the description keeps its original
// leading sentence, so a caller matching on either keeps working.

func denialText(t *testing.T, err error) string {
	t.Helper()
	require.Error(t, err)
	oe, ok := err.(*OAuthError)
	require.True(t, ok, "denial must be an *OAuthError so the token endpoint renders error_description")
	assert.Equal(t, oautherror.InvalidScope, oe.Code, "the wire contract is invalid_scope; only the description changes")
	assert.Contains(t, oe.Description, "requested scopes are not available for delegation",
		"the original sentence stays as a prefix so existing log greps keep matching")
	return oe.Description
}

func TestDelegationScopeDenial_NoScopesRequested(t *testing.T) {
	// token_exchange is the ONE grant with no RFC 6749 §3.3 default, so an
	// omitted scope is a hard failure rather than "grant the full ceiling".
	// A caller who has only ever used the other grants will not expect that.
	err := delegationScopeDenial(nil, map[string]bool{"tools:read": true}, nil)

	desc := denialText(t, err)
	assert.Contains(t, desc, "no scopes were requested")
	assert.NotContains(t, desc, "does not hold", "nothing was asked for, so no scope can be named")
	assert.NotContains(t, desc, "not registered for")
}

func TestDelegationScopeDenial_SubjectDoesNotHold(t *testing.T) {
	// The middle term. The delegator itself lacks the scope, so widening the
	// SUB-AGENT would not help — the usual wrong turn.
	err := delegationScopeDenial(
		[]string{"data:read", "tools:read"},
		map[string]bool{}, // subject holds nothing
		[]string{"data:read", "tools:read"},
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the subject token does not hold [data:read tools:read]")
	assert.NotContains(t, desc, "not registered for")
}

func TestDelegationScopeDenial_ActorCeilingExcludes(t *testing.T) {
	// The third term. The delegator holds it; the sub-agent was never
	// registered for it. Here widening the sub-agent IS the fix.
	err := delegationScopeDenial(
		[]string{"data:read"},
		map[string]bool{"data:read": true},
		[]string{"tools:read"}, // actor ceiling excludes data:read
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the actor identity is not registered for [data:read]")
	assert.NotContains(t, desc, "does not hold")
}

func TestDelegationScopeDenial_BothTermsNamedSeparately(t *testing.T) {
	// A mixed request must not collapse into one cause: the caller has two
	// different repairs to make, on two different identities.
	err := delegationScopeDenial(
		[]string{"data:read", "order:write"},
		map[string]bool{"data:read": true}, // subject lacks order:write
		[]string{"order:write"},            // actor ceiling lacks data:read
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the subject token does not hold [order:write]")
	assert.Contains(t, desc, "the actor identity is not registered for [data:read]")
}

func TestDelegationScopeDenial_UnrestrictedActorBlamesTheSubjectOnly(t *testing.T) {
	// An actor with no ceiling cannot be the cause: an empty ceiling means
	// "no restriction from this layer". Blaming it would send the caller to
	// widen a registration that was never the constraint.
	err := delegationScopeDenial(
		[]string{"data:read"},
		map[string]bool{},
		nil, // no actor ceiling
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the subject token does not hold [data:read]")
	assert.NotContains(t, desc, "not registered for")
}

func TestDelegationScopeDenial_EachScopeIsBlamedOnce(t *testing.T) {
	// A scope both parties lack is reported under the subject alone. Listing
	// it twice would read as two separate problems.
	err := delegationScopeDenial(
		[]string{"data:read"},
		map[string]bool{},      // subject lacks it
		[]string{"tools:read"}, // and the actor ceiling lacks it too
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the subject token does not hold [data:read]")
	assert.NotContains(t, desc, "not registered for",
		"a scope the subject cannot delegate is not also the sub-agent's problem")
}
