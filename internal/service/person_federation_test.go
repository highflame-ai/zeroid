package service

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestResolveFederatedPerson(t *testing.T) {
	ctx := context.Background()
	req := FederatedPersonRequest{GrantType: PersonGrantIDJAG, AccountID: "a", ProjectID: "p", Issuer: "https://idp", Subject: "oid-1"}

	t.Run("no resolver, static issuer: sub is the IdP subject, no idp_sub", func(t *testing.T) {
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
	t.Run("resolver maps the person; the IdP subject moves to idp_sub", func(t *testing.T) {
		s := &OAuthService{}
		var seen FederatedPersonRequest
		s.SetFederatedPersonResolver(func(_ context.Context, r FederatedPersonRequest) (string, error) {
			seen = r
			return "user_hf_1", nil
		})
		got, err := s.resolveFederatedPerson(ctx, true, req)
		if err != nil || got.sub != "user_hf_1" || got.idpSub != "oid-1" {
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

func TestReservedClaims_IdPSub(t *testing.T) {
	if !reservedClaims["idp_sub"] || !reservedClaims["user_id_iss"] {
		t.Fatal("idp_sub and user_id_iss are written only by the federated grants")
	}
}
