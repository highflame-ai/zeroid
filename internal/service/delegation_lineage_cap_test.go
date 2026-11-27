package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// A chain past the lineage cap is refused as too long, not as a stopped
// identity: every identity in it may be active.
func TestCheckLineageUsable_ChainPastCapIsTooLong(t *testing.T) {
	svc := &CredentialService{tree: lineageTree{err: postgres.ErrLineageTooLong}}
	err := svc.checkLineageUsable(t.Context(), "parent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDelegationChainTooLong), "%v", err)
	assert.False(t, errors.Is(err, domain.ErrIdentityNotUsable), "no identity is stopped: %v", err)
	assert.Contains(t, ErrDelegationChainTooLong.Error(), "50")
	assert.True(t, issuanceRefusal(err), "grants that pass refusals through pass this one")
}

// Introspection reads the same cap as inactive, with the same reason.
func TestCredentialTreeRefusal_ChainPastCap(t *testing.T) {
	svc := &CredentialService{tree: lineageTree{err: postgres.ErrLineageTooLong}}
	reason, err := svc.credentialTreeRefusal(t.Context(), &domain.IssuedCredential{ParentJTI: "parent"})
	require.NoError(t, err)
	assert.Equal(t, postgres.ErrLineageTooLong.Error(), reason)
}

// A chain that loops is still refused as before.
func TestCheckLineageUsable_LoopingChainStillRefused(t *testing.T) {
	svc := &CredentialService{tree: lineageTree{err: postgres.ErrBrokenLineage}}
	err := svc.checkLineageUsable(t.Context(), "parent")
	assert.True(t, errors.Is(err, domain.ErrIdentityNotUsable), "%v", err)
	assert.False(t, errors.Is(err, ErrDelegationChainTooLong), "%v", err)
}
