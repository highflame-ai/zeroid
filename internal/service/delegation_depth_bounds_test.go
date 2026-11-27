package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// The limit keeps the deepest token's act chain, its delegates plus the root
// grant's client, within MaxActorChainDepth.
func TestMaxDelegationDepthLimit_FitsTheActChain(t *testing.T) {
	assert.Equal(t, domain.MaxActorChainDepth, domain.MaxDelegationDepthLimit+1)
}

func TestValidateMaxDelegationDepth(t *testing.T) {
	for _, depth := range []int{0, 1, domain.DefaultMaxDelegationDepth, domain.MaxDelegationDepthLimit} {
		assert.NoError(t, validateMaxDelegationDepth(depth), "%d is in range", depth)
	}
	for _, depth := range []int{-5, -1, domain.MaxDelegationDepthLimit + 1, domain.MaxActorChainDepth + 1, 1_000_000} {
		err := validateMaxDelegationDepth(depth)
		assert.True(t, errors.Is(err, ErrInvalidPolicyField), "%d is out of range: %v", depth, err)
		assert.ErrorContains(t, err, "max_delegation_depth")
	}
}

// CreatePolicy validates before it writes, so an out-of-range depth never
// reaches the store (this service has none).
func TestCreatePolicy_RefusesOutOfRangeMaxDelegationDepth(t *testing.T) {
	svc := &CredentialPolicyService{}
	for _, depth := range []int{-5, domain.MaxDelegationDepthLimit + 1, 1_000_000} {
		_, err := svc.CreatePolicy(t.Context(), CreatePolicyRequest{Name: "p", MaxDelegationDepth: depth})
		assert.True(t, errors.Is(err, ErrInvalidPolicyField), "%d: %v", depth, err)
	}
}

// The chokepoint holds every grant to the limit, including those no
// credential policy governs.
func TestIssueCredential_RefusesDepthPastLimit(t *testing.T) {
	svc := &CredentialService{tree: lineageTree{}}
	_, _, err := svc.IssueCredential(t.Context(), IssueRequest{
		Identity:        &domain.Identity{ID: "id-1", Status: domain.IdentityStatusActive},
		ParentJTI:       "parent",
		DelegationDepth: domain.MaxDelegationDepthLimit + 1,
	})
	assert.True(t, errors.Is(err, ErrPolicyViolation), "%v", err)
}

// lineageTree is an identityTreeReader whose identities are all active roots
// and whose credential lineage read returns err.
type lineageTree struct{ err error }

func (lineageTree) AncestorChain(_ context.Context, id, accountID, projectID string) ([]postgres.Ancestor, error) {
	return []postgres.Ancestor{{ID: id, Status: domain.IdentityStatusActive}}, nil
}

func (l lineageTree) CredentialLineage(context.Context, string) ([]postgres.LineageIdentity, error) {
	return nil, l.err
}
