package service

import (
	"context"
	"errors"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

// TestCIBAApproveScopeNeverIssuedToAgentIdentity pins the issuance chokepoint:
// a credential carrying the ciba:approve scope is refused for agent identities
// regardless of what their scope ceilings say.
func TestCIBAApproveScopeNeverIssuedToAgentIdentity(t *testing.T) {
	svc := NewCredentialService(nil, nil, nil, nil, "https://issuer.example.test", 900, 3600, 30)
	_, _, err := svc.IssueCredential(context.Background(), IssueRequest{
		Identity: &domain.Identity{
			IdentityType:  domain.IdentityTypeAgent,
			Status:        domain.IdentityStatusActive,
			AllowedScopes: []string{domain.ScopeCIBAApprove},
		},
		Scopes: []string{"tools:read", domain.ScopeCIBAApprove},
	})
	if !errors.Is(err, ErrScopesNotAllowed) {
		t.Fatalf("expected ErrScopesNotAllowed, got %v", err)
	}
}

func TestScopeRefusedForIdentityType(t *testing.T) {
	cases := []struct {
		typ    domain.IdentityType
		scopes []string
		want   string
	}{
		{domain.IdentityTypeAgent, []string{domain.ScopeCIBAApprove}, domain.ScopeCIBAApprove},
		{domain.IdentityTypeAgent, []string{"tools:read"}, ""},
		{domain.IdentityTypeService, []string{domain.ScopeCIBAApprove}, ""},
		{domain.IdentityTypeApplication, []string{domain.ScopeCIBAApprove}, ""},
	}
	for _, tc := range cases {
		if got := scopeRefusedForIdentityType(tc.typ, tc.scopes); got != tc.want {
			t.Errorf("scopeRefusedForIdentityType(%s, %v) = %q, want %q", tc.typ, tc.scopes, got, tc.want)
		}
	}
}
