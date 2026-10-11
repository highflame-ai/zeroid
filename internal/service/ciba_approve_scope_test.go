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
		{domain.IdentityTypeMCPServer, []string{domain.ScopeCIBAApprove}, domain.ScopeCIBAApprove},
		{domain.IdentityTypeService, []string{domain.ScopeCIBAApprove}, ""},
		{domain.IdentityTypeApplication, []string{domain.ScopeCIBAApprove}, ""},
	}
	for _, tc := range cases {
		if got := scopeRefusedForIdentityType(tc.typ, tc.scopes); got != tc.want {
			t.Errorf("scopeRefusedForIdentityType(%s, %v) = %q, want %q", tc.typ, tc.scopes, got, tc.want)
		}
	}
}

// TestCIBAApproveScopeRequiresExplicitListing pins that an empty scope
// ceiling never yields ciba:approve: a non-agent identity that does not list
// the scope (and has no credential policy that does) is refused.
func TestCIBAApproveScopeRequiresExplicitListing(t *testing.T) {
	svc := NewCredentialService(nil, nil, nil, nil, "https://issuer.example.test", 900, 3600, 30)
	for _, typ := range []domain.IdentityType{domain.IdentityTypeService, domain.IdentityTypeApplication} {
		_, _, err := svc.IssueCredential(context.Background(), IssueRequest{
			Identity: &domain.Identity{
				IdentityType: typ,
				Status:       domain.IdentityStatusActive,
			},
			Scopes: []string{domain.ScopeCIBAApprove},
		})
		if !errors.Is(err, ErrScopesNotAllowed) {
			t.Fatalf("%s: expected ErrScopesNotAllowed, got %v", typ, err)
		}
	}
}

func TestCIBAApproveListedOnIdentity(t *testing.T) {
	svc := NewCredentialService(nil, nil, nil, nil, "https://issuer.example.test", 900, 3600, 30)
	listed := &domain.Identity{IdentityType: domain.IdentityTypeService, AllowedScopes: []string{"a", domain.ScopeCIBAApprove}}
	if !svc.cibaApproveListed(context.Background(), IssueRequest{Identity: listed}) {
		t.Fatal("identity listing ciba:approve must be accepted")
	}
	unlisted := &domain.Identity{IdentityType: domain.IdentityTypeService, AllowedScopes: []string{"a"}}
	if svc.cibaApproveListed(context.Background(), IssueRequest{Identity: unlisted}) {
		t.Fatal("identity not listing ciba:approve must be refused")
	}
}

func TestApprovalChannelSubTypeValidOnlyForService(t *testing.T) {
	if !domain.SubTypeApprovalChannel.ValidForIdentityType(domain.IdentityTypeService) {
		t.Fatal("approval_channel must be valid for service identities")
	}
	for _, typ := range []domain.IdentityType{domain.IdentityTypeAgent, domain.IdentityTypeApplication, domain.IdentityTypeMCPServer} {
		if domain.SubTypeApprovalChannel.ValidForIdentityType(typ) {
			t.Fatalf("approval_channel must not be valid for %s", typ)
		}
	}
}

func TestRequireTrustedApprovalChannelWrite(t *testing.T) {
	ctx := context.Background()
	trusted := WithTrustedApprovalChannelWrite(ctx)
	if TrustedApprovalChannelWrite(ctx) || !TrustedApprovalChannelWrite(trusted) {
		t.Fatal("the trusted mark is off by default and on once set")
	}
	for _, tc := range []struct {
		sub    domain.SubType
		scopes []string
	}{
		{domain.SubTypeApprovalChannel, nil},
		{"", []string{"tools:read", domain.ScopeCIBAApprove}},
	} {
		if err := requireTrustedApprovalChannelWrite(ctx, tc.sub, tc.scopes); !errors.Is(err, ErrApprovalChannelWriteNotTrusted) {
			t.Fatalf("%v %v: expected refusal, got %v", tc.sub, tc.scopes, err)
		}
		if err := requireTrustedApprovalChannelWrite(trusted, tc.sub, tc.scopes); err != nil {
			t.Fatalf("%v %v: trusted write refused: %v", tc.sub, tc.scopes, err)
		}
	}
	if err := requireTrustedApprovalChannelWrite(ctx, domain.SubTypeLLMProvider, []string{"tools:read"}); err != nil {
		t.Fatalf("ordinary write refused: %v", err)
	}
}

// TestCIBAApproveRequiresTrustedCredential pins that ciba:approve is refused
// when the presented credential was not written in the trusted
// approval-channel context, even for an identity that lists the scope.
func TestCIBAApproveRequiresTrustedCredential(t *testing.T) {
	svc := NewCredentialService(nil, nil, nil, nil, "https://issuer.example.test", 900, 3600, 30)
	_, _, err := svc.IssueCredential(context.Background(), IssueRequest{
		Identity: &domain.Identity{
			IdentityType:  domain.IdentityTypeService,
			SubType:       domain.SubTypeApprovalChannel,
			Status:        domain.IdentityStatusActive,
			AllowedScopes: []string{domain.ScopeCIBAApprove},
		},
		Scopes: []string{domain.ScopeCIBAApprove},
	})
	if !errors.Is(err, ErrScopesNotAllowed) {
		t.Fatalf("expected ErrScopesNotAllowed, got %v", err)
	}
}
