package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

func TestResolveFederatedPerson(t *testing.T) {
	ctx := context.Background()
	req := FederatedPersonRequest{GrantType: PersonGrantIDJAG, AccountID: "a", ProjectID: "p", Issuer: "https://idp", Subject: "oid-1"}

	t.Run("no resolver, static issuer: sub is the IdP subject, no user_idp_sub", func(t *testing.T) {
		s := &OAuthService{}
		got, err := s.resolveFederatedPerson(ctx, false, req)
		if err != nil || got.sub != "oid-1" || got.idpSub != "" {
			t.Fatalf("got %+v err %v", got, err)
		}
	})
	t.Run("no resolver, issuer row: fail closed", func(t *testing.T) {
		s := &OAuthService{}
		_, err := s.resolveFederatedPerson(ctx, true, req)
		if oauthCode(err) != "server_error" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("resolver maps the person; the IdP subject moves to user_idp_sub", func(t *testing.T) {
		s := &OAuthService{}
		var seen FederatedPersonRequest
		s.SetFederatedPersonResolver(func(_ context.Context, r FederatedPersonRequest) (string, error) {
			seen = r
			return "user_hf_1", nil
		})
		got, err := s.resolveFederatedPerson(ctx, true, req)
		if err != nil || got.sub != "user_hf_1" || got.idpSub != "oid-1" || got.idpIss != "https://idp" {
			t.Fatalf("got %+v err %v", got, err)
		}
		if seen != req {
			t.Fatalf("resolver saw %+v", seen)
		}
	})
	t.Run("not a member is invalid_grant", func(t *testing.T) {
		s := &OAuthService{}
		s.SetFederatedPersonResolver(func(context.Context, FederatedPersonRequest) (string, error) {
			return "", ErrPersonNotMember
		})
		if _, err := s.resolveFederatedPerson(ctx, true, req); oauthCode(err) != "invalid_grant" {
			t.Fatalf("err = %v", err)
		}
	})
	for name, fn := range map[string]FederatedPersonResolver{
		"error": func(context.Context, FederatedPersonRequest) (string, error) {
			return "", errors.New("admin said: db password wrong")
		},
		"empty id": func(context.Context, FederatedPersonRequest) (string, error) { return " ", nil },
		"panic":    func(context.Context, FederatedPersonRequest) (string, error) { panic("boom") },
	} {
		t.Run(name+" fails closed without leaking", func(t *testing.T) {
			s := &OAuthService{}
			s.SetFederatedPersonResolver(fn)
			_, err := s.resolveFederatedPerson(ctx, false, req)
			var oe *OAuthError
			if !errors.As(err, &oe) || oe.Code != "server_error" || strings.Contains(oe.Description, "password") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("nil removes the resolver", func(t *testing.T) {
		s := &OAuthService{}
		s.SetFederatedPersonResolver(func(context.Context, FederatedPersonRequest) (string, error) { return "x", nil })
		s.SetFederatedPersonResolver(nil)
		got, _ := s.resolveFederatedPerson(ctx, false, req)
		if got.sub != "oid-1" {
			t.Fatal("resolver still installed")
		}
	})
}

// A resolved person's sub is the deployer's user, so user_id_iss (sub's
// issuer) must not stay the IdP's; the IdP pair moves to user_idp_iss/user_idp_sub.
func TestFederatedPersonApply(t *testing.T) {
	req := IssueRequest{SubjectOverride: "oid-1", CustomClaims: map[string]any{"user_id_iss": "https://idp", "token_exchange": "id_jag"}}
	federatedPerson{sub: "user_hf_1", idpIss: "https://idp", idpSub: "oid-1"}.apply(&req)
	if req.SubjectOverride != "user_hf_1" || req.IdPIssuer != "https://idp" || req.IdPSubject != "oid-1" {
		t.Fatalf("req = %+v", req)
	}
	if _, ok := req.CustomClaims["user_id_iss"]; ok {
		t.Fatal("user_id_iss must not name the IdP once sub is the deployer's user")
	}
	if got := (&CredentialService{issuer: "https://zeroid"}).resolvePrincipal(IssueRequest{SubjectOverride: req.SubjectOverride, CustomClaims: req.CustomClaims}); got.Iss != "https://zeroid" {
		t.Fatalf("principal issuer = %q, want ZeroID's, as on authorization_code", got.Iss)
	}

	static := IssueRequest{SubjectOverride: "oid-1", CustomClaims: map[string]any{"user_id_iss": "https://idp"}}
	federatedPerson{sub: "oid-1"}.apply(&static)
	if static.CustomClaims["user_id_iss"] != "https://idp" || static.IdPSubject != "" || static.IdPIssuer != "" {
		t.Fatalf("without a resolver the IdP stays sub's issuer: %+v", static)
	}
}

func TestEmailVerified(t *testing.T) {
	cases := []struct {
		claims map[string]any
		claim  string
		want   bool
	}{
		{map[string]any{"email_verified": true}, "", true},
		{map[string]any{"email_verified": false}, "", false},
		{map[string]any{"xms_edov": true}, "xms_edov", true},
		{map[string]any{"xms_edov": "1"}, "xms_edov", true},
		{map[string]any{"xms_edov": true}, "", false},
		{map[string]any{"email_verified": "yes"}, "", false},
		{map[string]any{}, "", false},
	}
	for _, tc := range cases {
		if got := emailVerified(tc.claims, tc.claim); got != tc.want {
			t.Errorf("emailVerified(%v, %q) = %v", tc.claims, tc.claim, got)
		}
	}
}

func TestIssuerEmailVerified(t *testing.T) {
	okta := domain.ExternalIssuerConfig{ClaimMapping: map[string]string{"email_verified": "email_verified"}}
	trusted := okta
	trusted.TrustEmail = true
	entraTrusted := domain.ExternalIssuerConfig{ClaimMapping: map[string]string{"email_verified": "xms_edov"}, TrustEmail: true}
	cases := []struct {
		name   string
		claims map[string]any
		cfg    domain.ExternalIssuerConfig
		email  string
		want   bool
	}{
		{"the claim decides when present", map[string]any{"email_verified": true}, okta, "a@corp.example", true},
		{"no claim, not trusted", map[string]any{}, okta, "a@corp.example", false},
		{"no claim, trusted: the issuer vouches for its email", map[string]any{}, trusted, "a@corp.example", true},
		{"an explicit false is never overridden", map[string]any{"email_verified": false}, trusted, "a@corp.example", false},
		{"an explicit string false is never overridden", map[string]any{"email_verified": "false"}, trusted, "a@corp.example", false},
		{"trusted, but no email to vouch for", map[string]any{}, trusted, "", false},
		{"the mapped claim, absent, trusted", map[string]any{"email_verified": false}, entraTrusted, "a@corp.example", true},
		{"the mapped claim, present", map[string]any{"xms_edov": "1"}, entraTrusted, "a@corp.example", true},
	}
	for _, tc := range cases {
		if got := issuerEmailVerified(tc.claims, tc.cfg, tc.email); got != tc.want {
			t.Errorf("%s: issuerEmailVerified(%v) = %v, want %v", tc.name, tc.claims, got, tc.want)
		}
	}
}

func TestReservedClaims_IdPSub(t *testing.T) {
	if !reservedClaims["user_idp_iss"] || !reservedClaims["user_idp_sub"] || !reservedClaims["user_id_iss"] {
		t.Fatal("user_idp_iss, user_idp_sub and user_id_iss are written only by ZeroID")
	}
}
