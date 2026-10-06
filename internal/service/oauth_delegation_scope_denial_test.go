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
	err := delegationScopeDenial(nil, map[string]bool{"tools:read": true}, nil, nil, false)

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
		nil,
		false,
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
		nil,                    // the policy places no restriction
		[]string{"tools:read"}, // the registration excludes data:read
		false,
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
		nil,
		[]string{"order:write"}, // actor registration lacks data:read
		false,
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
		nil, // no actor policy ceiling
		nil, // no actor registration ceiling
		false,
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
		[]string{"tools:read"}, // and the actor policy lacks it too
		nil,
		false,
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the subject token does not hold [data:read]")
	assert.NotContains(t, desc, "not registered for",
		"a scope the subject cannot delegate is not also the sub-agent's problem")
}

// The actor's credential policy and its registration are separate ceilings
// that both bind, and they need different repairs. A denial must name the
// one that excluded the scope, and a scope both exclude is blamed on the
// policy alone.

func TestDelegationScopeDenial_PolicyCeilingBlamesThePolicy(t *testing.T) {
	err := delegationScopeDenial(
		[]string{"data:read"},
		map[string]bool{"data:read": true},
		[]string{"tools:read"},
		[]string{"data:read"}, // the registration lists it; the policy does not
		false,
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the actor's credential policy does not permit [data:read]")
	assert.NotContains(t, desc, "not registered for",
		"the registration lists data:read; only the policy excluded it")
}

func TestDelegationScopeDenial_RowNarrowerThanPolicyBlamesTheRegistration(t *testing.T) {
	// The policy permits the scope and the registration does not. The row
	// binds even though the policy restricts, so the registration is the
	// thing to widen.
	err := delegationScopeDenial(
		[]string{"nhi:manage"},
		map[string]bool{"nhi:manage": true},
		[]string{"nhi:manage", "tools:read"},
		[]string{"tools:read"},
		false,
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the actor identity is not registered for [nhi:manage]")
	assert.NotContains(t, desc, "credential policy")
}

func TestDelegationScopeDenial_ScopeBothCeilingsExcludeIsBlamedOnce(t *testing.T) {
	err := delegationScopeDenial(
		[]string{"data:read"},
		map[string]bool{"data:read": true},
		[]string{"tools:read"},
		[]string{"tools:read"},
		false,
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "the actor's credential policy does not permit [data:read]")
	assert.NotContains(t, desc, "not registered for")
}

func TestIdentityScopeCeilings(t *testing.T) {
	policy := &domain.CredentialPolicy{AllowedScopes: []string{"tools:read"}}
	identity := &domain.Identity{AllowedScopes: []string{"order:read"}}

	p, r := identityScopeCeilings(policy, identity)
	assert.Equal(t, []string{"tools:read"}, p)
	assert.Equal(t, []string{"order:read"}, r, "the row is returned even when the policy restricts")

	p, r = identityScopeCeilings(nil, nil)
	assert.Empty(t, p)
	assert.Empty(t, r)
}

func TestGrantScopes(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		ceilings  [][]string
		want      []string
		denied    bool
	}{
		{"no ceiling, omitted request keeps the legacy scopeless grant", "", nil, nil, false},
		{"no ceiling, explicit request passes through", "a b", [][]string{nil, {}}, []string{"a", "b"}, false},
		{"omitted request defaults to the single ceiling", "", [][]string{{"a", "b"}}, []string{"a", "b"}, false},
		{"row narrower than policy yields the intersection", "",
			[][]string{{"nhi:manage", "tools:read"}, {"tools:read"}}, []string{"tools:read"}, false},
		{"empty ceilings are skipped, not treated as denials", "",
			[][]string{nil, {"a", "b"}, {}, {"b"}}, []string{"b"}, false},
		{"explicit request narrowed by every ceiling", "a b c",
			[][]string{{"a", "b"}, {"b", "c"}}, []string{"b"}, false},
		{"disjoint ceilings deny an omitted request instead of minting a scopeless token", "",
			[][]string{{"nhi:manage"}, {"tools:read"}}, nil, true},
		{"an earlier denial is not reset by a later ceiling", "",
			[][]string{{"a"}, {"b"}, {"a", "b"}}, nil, true},
		{"explicit request outside every ceiling is denied", "z",
			[][]string{{"a"}}, nil, true},
		{"whitespace-only request is treated as omitted", "  ",
			[][]string{{"a"}}, []string{"a"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := grantScopes(c.requested, c.ceilings...)
			if c.denied {
				require.Error(t, err)
				oe, ok := err.(*OAuthError)
				require.True(t, ok)
				assert.Equal(t, oautherror.InvalidScope, oe.Code)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}

	t.Run("the default is a copy, not the ceiling's backing array", func(t *testing.T) {
		ceiling := []string{"a", "b"}
		got, err := grantScopes("", ceiling)
		require.NoError(t, err)
		got[0] = "mutated"
		assert.Equal(t, "a", ceiling[0])
	})
}

// TestDelegationScopeDenial_NamesUserGrantScopes: for a chain acting for a
// person the actor's ceiling is its policy's user_grant_scopes (D10), so the
// denial must send the caller to that field, not to allowed_scopes.
func TestDelegationScopeDenial_NamesUserGrantScopes(t *testing.T) {
	err := delegationScopeDenial(
		[]string{"data:write"},
		map[string]bool{"data:write": true},
		[]string{"data:read"},
		nil,
		true,
	)

	desc := denialText(t, err)
	assert.Contains(t, desc, "user_grant_scopes does not permit [data:write]")
}
