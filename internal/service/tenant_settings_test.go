package service

import (
	"context"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

// A credential service with no tenant settings wired, and a tenant with no
// settings row, both issue in the default profile, which is rfc8693. The
// no-row path reads the database and is covered by the integration test
// TestTenantSettings_TokenProfile; this pins the default and the unwired path.
func TestTokenProfile_DefaultIsRFC8693(t *testing.T) {
	if domain.DefaultTokenProfile != domain.TokenProfileRFC8693 {
		t.Fatalf("DefaultTokenProfile = %q, want %q", domain.DefaultTokenProfile, domain.TokenProfileRFC8693)
	}
	for name, s := range map[string]*TenantSettingsService{
		"nil service": nil,
		"nil repo":    NewTenantSettingsService(nil),
	} {
		got, err := s.TokenProfile(context.Background(), "acct", "proj")
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if got != domain.TokenProfileRFC8693 {
			t.Errorf("%s: TokenProfile = %q, want %q", name, got, domain.TokenProfileRFC8693)
		}
	}
}
