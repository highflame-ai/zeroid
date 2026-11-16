package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

func allowAll(context.Context, ReservedScopeGrant) error { return nil }

func TestReservedScopes_SetNeedsAuthorizer(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, nil, time.Minute); err == nil {
		t.Fatal("prefixes without an authorizer must be refused")
	}
	if err := r.Set(nil, nil, 0); err != nil {
		t.Fatalf("no prefixes turns it off: %v", err)
	}
}

func TestReservedScopes_In(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, allowAll, 0); err != nil {
		t.Fatal(err)
	}
	got := r.in([]string{"hf.config.manage", "data:read", "hfx"})
	if len(got) != 1 || got[0] != "hf.config.manage" {
		t.Fatalf("in = %v", got)
	}
	if (*ReservedScopes)(nil).in([]string{"hf.config.manage"}) != nil {
		t.Fatal("nil ReservedScopes reserves nothing")
	}
}

// CreateKey refuses a reserved scope outside the trusted write, before any
// lookup or insert.
func TestCreateKeyRefusesUntrustedReservedScope(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, allowAll, 0); err != nil {
		t.Fatal(err)
	}
	svc := &APIKeyService{reserved: r}
	_, err := svc.CreateKey(context.Background(), CreateAPIKeyRequest{Scopes: []string{"hf.config.manage"}})
	if !errors.Is(err, ErrReservedScopeWriteNotTrusted) {
		t.Fatalf("want ErrReservedScopeWriteNotTrusted, got %v", err)
	}
	_, err = svc.CreateKey(WithReservedScopeWrite(context.Background()), CreateAPIKeyRequest{Scopes: []string{"hf.config.manage"}})
	if errors.Is(err, ErrReservedScopeWriteNotTrusted) {
		t.Fatal("the trusted write must pass the reserved-scope check")
	}
}

// IssueCredential is the chokepoint: no path but the api_key grant's checks
// issues a reserved scope.
func TestIssueCredentialRefusesUnauthorizedReservedScope(t *testing.T) {
	r := &ReservedScopes{}
	if err := r.Set([]string{"hf."}, allowAll, 0); err != nil {
		t.Fatal(err)
	}
	s := &CredentialService{reserved: r, defaultTTL: 300, maxTTL: 3600}
	_, _, err := s.IssueCredential(context.Background(), IssueRequest{
		Identity: &domain.Identity{ID: "id-1", Status: domain.IdentityStatusActive, IdentityType: domain.IdentityTypeService},
		Scopes:   []string{"hf.config.manage"},
	})
	if !errors.Is(err, ErrScopesNotAllowed) || !strings.Contains(err.Error(), "only on the api_key grant") {
		t.Fatalf("want the reserved-scope refusal, got %v", err)
	}
}
