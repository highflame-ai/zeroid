package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// TestMayAct_ActorMustMatch: RFC 8693 §4.4. A may_act claim names the one
// party that may act for the subject, and a claim naming nobody permits nobody.
func TestMayAct_ActorMustMatch(t *testing.T) {
	const actor = "spiffe://zeroid.test/a/p/agent/b"
	const issuer = "https://zeroid.test"
	for _, tc := range []struct {
		name   string
		mayAct map[string]any
		want   bool
	}{
		{"names this actor", map[string]any{"sub": actor}, true},
		{"names this actor with ZeroID's issuer", map[string]any{"sub": actor, "iss": issuer}, true},
		{"names another actor", map[string]any{"sub": "spiffe://zeroid.test/a/p/agent/c"}, false},
		{"names this actor under another issuer", map[string]any{"sub": actor, "iss": "https://elsewhere.test"}, false},
		{"names no subject", map[string]any{"iss": issuer}, false},
		{"empty", map[string]any{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mayActPermits(tc.mayAct, actor, issuer))
		})
	}
}

func TestEnforcePolicy_RequiredPrincipalType(t *testing.T) {
	svc := &CredentialPolicyService{}
	policy := &domain.CredentialPolicy{
		Name: "requires-user", IsActive: true, MaxTTLSeconds: 3600, MaxDelegationDepth: 5,
		AllowedGrantTypes:     []string{string(domain.GrantTypeTokenExchange)},
		RequiredPrincipalType: domain.RequirePrincipalUser,
	}
	req := func(pt domain.PrincipalType) EnforcePolicyRequest {
		return EnforcePolicyRequest{TTL: 60, GrantType: domain.GrantTypeTokenExchange, PrincipalType: pt}
	}
	require.NoError(t, svc.EnforcePolicy(t.Context(), policy, req(domain.PrincipalUser)))
	for _, pt := range []domain.PrincipalType{domain.PrincipalWorkload, domain.PrincipalUnknown, ""} {
		err := svc.EnforcePolicy(t.Context(), policy, req(pt))
		assert.True(t, errors.Is(err, ErrPolicyViolation), "%q must not satisfy a user requirement: %v", pt, err)
	}

	any := *policy
	any.RequiredPrincipalType = ""
	assert.NoError(t, svc.EnforcePolicy(t.Context(), &any, req(domain.PrincipalWorkload)), "no requirement admits any principal")
}

// EnforceSubset: an API key's policy may require more than its identity's,
// never less, in the order any < user < owner.
func TestEnforceSubset_RequiredPrincipalType(t *testing.T) {
	svc := &CredentialPolicyService{}
	pol := func(req string) *domain.CredentialPolicy {
		return &domain.CredentialPolicy{MaxTTLSeconds: 3600, MaxDelegationDepth: 5, RequiredPrincipalType: req}
	}
	assert.NoError(t, svc.EnforceSubset(pol("user"), pol("")), "narrower may require more")
	assert.NoError(t, svc.EnforceSubset(pol("user"), pol("user")))
	err := svc.EnforceSubset(pol(""), pol("user"))
	assert.True(t, errors.Is(err, ErrPolicySubsetViolation), "narrower may not require less: %v", err)
}

func TestValidateRequiredPrincipalType(t *testing.T) {
	assert.NoError(t, validateRequiredPrincipalType(""))
	assert.NoError(t, validateRequiredPrincipalType("user"))
	assert.True(t, errors.Is(validateRequiredPrincipalType("owner"), ErrInvalidPolicyField),
		"owner needs the personal-agent profile and is refused until it ships")
	assert.True(t, errors.Is(validateRequiredPrincipalType("human"), ErrInvalidPolicyField))
}
