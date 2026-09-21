package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
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
	err := delegationScopeDenial(nil, map[string]bool{"tools:read": true}, nil, ceilingUnset)

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
		ceilingFromPolicy,
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
		ceilingFromIdentity,
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the actor identity is not registered for [data:read]")
	assert.NotContains(t, desc, "does not hold")
	assert.NotContains(t, desc, "credential policy",
		"this ceiling came from the registration, so the policy is not the thing to edit")
}

func TestDelegationScopeDenial_BothTermsNamedSeparately(t *testing.T) {
	// A mixed request must not collapse into one cause: the caller has two
	// different repairs to make, on two different identities.
	err := delegationScopeDenial(
		[]string{"data:read", "order:write"},
		map[string]bool{"data:read": true}, // subject lacks order:write
		[]string{"order:write"},            // actor ceiling lacks data:read
		ceilingFromIdentity,
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
		ceilingUnset,
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
		ceilingFromPolicy,
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the subject token does not hold [data:read]")
	assert.NotContains(t, desc, "not registered for",
		"a scope the subject cannot delegate is not also the sub-agent's problem")
}

// effectiveAllowedScopes is either/or: when the credential policy sets scopes,
// the identity's own list is never read. A denial that always blamed the
// registration would send the caller to edit a field the ceiling did not come
// from — the exact wrong-repair hint this denial exists to remove.

func TestDelegationScopeDenial_PolicyCeilingBlamesThePolicy(t *testing.T) {
	err := delegationScopeDenial(
		[]string{"data:read"},
		map[string]bool{"data:read": true},
		[]string{"tools:read"},
		ceilingFromPolicy,
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the actor's credential policy does not permit [data:read]")
	assert.NotContains(t, desc, "not registered for",
		"the registration may well list data:read; the policy overrode it")
}

func TestEffectiveAllowedScopesWithSource(t *testing.T) {
	policy := &domain.CredentialPolicy{AllowedScopes: []string{"tools:read"}}
	identity := &domain.Identity{AllowedScopes: []string{"order:read"}}

	t.Run("a policy ceiling wins and is reported as the source", func(t *testing.T) {
		scopes, src := effectiveAllowedScopesWithSource(policy, identity)
		assert.Equal(t, []string{"tools:read"}, scopes)
		assert.Equal(t, ceilingFromPolicy, src)
	})

	t.Run("an unrestricted policy falls back to the identity", func(t *testing.T) {
		scopes, src := effectiveAllowedScopesWithSource(&domain.CredentialPolicy{}, identity)
		assert.Equal(t, []string{"order:read"}, scopes)
		assert.Equal(t, ceilingFromIdentity, src)
	})

	t.Run("neither layer restricts", func(t *testing.T) {
		scopes, src := effectiveAllowedScopesWithSource(&domain.CredentialPolicy{}, &domain.Identity{})
		assert.Empty(t, scopes)
		assert.Equal(t, ceilingUnset, src)
	})

	t.Run("the source never disagrees with the scopes effectiveAllowedScopes returns", func(t *testing.T) {
		// One decision point: a caller that re-derived the source separately
		// would go stale the moment the precedence changes.
		for _, c := range []struct {
			name     string
			policy   *domain.CredentialPolicy
			identity *domain.Identity
		}{
			{"policy wins", policy, identity},
			{"identity fallback", &domain.CredentialPolicy{}, identity},
			{"nothing set", nil, nil},
		} {
			t.Run(c.name, func(t *testing.T) {
				scopes, _ := effectiveAllowedScopesWithSource(c.policy, c.identity)
				assert.Equal(t, effectiveAllowedScopes(c.policy, c.identity), scopes)
			})
		}
	})
}
