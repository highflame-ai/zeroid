package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

func delegationPolicy(maxDepth int) *domain.CredentialPolicy {
	return &domain.CredentialPolicy{
		Name: "delegation", IsActive: true, MaxTTLSeconds: 3600, MaxDelegationDepth: maxDepth,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
	}
}

func exchangeAtDepth(depth int) EnforcePolicyRequest {
	return EnforcePolicyRequest{TTL: 60, GrantType: domain.GrantTypeTokenExchange, DelegationDepth: depth}
}

// A policy stored with a max_delegation_depth above the limit is held to the
// limit at issuance: a token at depth d names up to d+1 actors, so one deeper
// than MaxActorChainDepth-1 could not carry its whole act chain.
func TestEnforcePolicy_StoredDepthAboveLimitIsClamped(t *testing.T) {
	svc := &CredentialPolicyService{}
	limit := domain.MaxActorChainDepth - 1
	for _, stored := range []int{limit + 1, 25, 1_000_000} {
		policy := delegationPolicy(stored)
		require.NoError(t, svc.EnforcePolicy(t.Context(), policy, exchangeAtDepth(limit)), "stored %d: depth %d is within the limit", stored, limit)
		err := svc.EnforcePolicy(t.Context(), policy, exchangeAtDepth(limit+1))
		require.Error(t, err, "stored %d: depth %d is past the limit", stored, limit+1)
		assert.True(t, errors.Is(err, ErrPolicyViolation), "the refusal is a policy violation: %v", err)
		assert.Contains(t, err.Error(), "act claim")
	}
}

// A policy within the limit is unchanged: its own maximum binds, and 0 still
// means the identity may not delegate at all.
func TestEnforcePolicy_DepthWithinLimitUnchanged(t *testing.T) {
	svc := &CredentialPolicyService{}
	require.NoError(t, svc.EnforcePolicy(t.Context(), delegationPolicy(0), exchangeAtDepth(0)))
	err := svc.EnforcePolicy(t.Context(), delegationPolicy(0), exchangeAtDepth(1))
	assert.True(t, errors.Is(err, ErrPolicyViolation), "0 allows no delegation: %v", err)

	require.NoError(t, svc.EnforcePolicy(t.Context(), delegationPolicy(3), exchangeAtDepth(3)))
	err = svc.EnforcePolicy(t.Context(), delegationPolicy(3), exchangeAtDepth(4))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds policy maximum 3")
}
