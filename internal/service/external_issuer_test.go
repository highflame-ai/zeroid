package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/highflame-ai/zeroid/domain"
)

func TestUniquenessConflict(t *testing.T) {
	row := func(id, acct string, kind domain.IssuerKind, key string) *domain.ExternalIssuer {
		return &domain.ExternalIssuer{ID: id, AccountID: acct, Kind: kind, ConstraintsKey: key}
	}
	cases := []struct {
		name     string
		existing []*domain.ExternalIssuer
		cand     *domain.ExternalIssuer
		shared   bool
		want     bool
	}{
		{name: "first row", cand: row("", "a", domain.IssuerKindPerson, "")},
		{name: "second account, unique issuer", existing: []*domain.ExternalIssuer{row("1", "a", domain.IssuerKindPerson, "")},
			cand: row("", "b", domain.IssuerKindPerson, ""), want: true},
		{name: "second account, unique issuer, other kind", existing: []*domain.ExternalIssuer{row("1", "a", domain.IssuerKindPerson, "")},
			cand: row("", "b", domain.IssuerKindWorkload, ""), want: true},
		{name: "same account, other kind", existing: []*domain.ExternalIssuer{row("1", "a", domain.IssuerKindPerson, "")},
			cand: row("", "a", domain.IssuerKindWorkload, "")},
		{name: "same account, same kind", existing: []*domain.ExternalIssuer{row("1", "a", domain.IssuerKindPerson, "")},
			cand: row("", "a", domain.IssuerKindPerson, ""), want: true},
		{name: "shared, second account, other constraints", existing: []*domain.ExternalIssuer{row("1", "a", domain.IssuerKindWorkload, "k1")},
			cand: row("", "b", domain.IssuerKindWorkload, "k2"), shared: true},
		{name: "shared, second account, same constraints", existing: []*domain.ExternalIssuer{row("1", "a", domain.IssuerKindWorkload, "k1")},
			cand: row("", "b", domain.IssuerKindWorkload, "k1"), shared: true, want: true},
		{name: "update ignores itself", existing: []*domain.ExternalIssuer{row("1", "a", domain.IssuerKindPerson, "")},
			cand: row("1", "a", domain.IssuerKindPerson, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := uniquenessConflict(tc.existing, tc.cand, tc.shared); got != tc.want {
				t.Fatalf("conflict = %v, want %v", got, tc.want)
			}
		})
	}
}

func jwksServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testJWKS(t *testing.T, kid string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import[jwk.Key](&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.KeyIDKey, kid)
	set := jwk.NewSet()
	_ = set.AddKey(key)
	raw, _ := json.Marshal(set)
	return string(raw)
}

func TestExternalIssuerCheck(t *testing.T) {
	svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{
		Store: IssuerStoreDB, AllowPrivateEndpoints: true, HTTPClient: http.DefaultClient,
	})
	ctx := context.Background()

	t.Run("reachable", func(t *testing.T) {
		srv := jwksServer(t, http.StatusOK, testJWKS(t, "k1"))
		got, err := svc.Check(ctx, srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Reachable || got.KeyCount != 1 || len(got.KIDs) != 1 || got.KIDs[0] != "k1" || got.Error != "" {
			t.Fatalf("check = %+v", got)
		}
	})
	t.Run("upstream error body is not echoed", func(t *testing.T) {
		srv := jwksServer(t, http.StatusInternalServerError, "secret internal detail")
		got, err := svc.Check(ctx, srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(got)
		if got.Reachable || got.Error != "jwks_unreachable" || strings.Contains(string(raw), "secret") {
			t.Fatalf("check = %s", raw)
		}
	})
	t.Run("empty", func(t *testing.T) {
		srv := jwksServer(t, http.StatusOK, `{"keys":[]}`)
		got, _ := svc.Check(ctx, srv.URL)
		if got.Error != "jwks_empty" {
			t.Fatalf("check = %+v", got)
		}
	})
	t.Run("invalid url is an error", func(t *testing.T) {
		_, err := svc.Check(ctx, "ftp://x")
		var apiErr *IssuerAPIError
		if !errors.As(err, &apiErr) || apiErr.Code != "invalid_jwks_uri" || apiErr.Status != http.StatusBadRequest {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the default client refuses a private address", func(t *testing.T) {
		guarded := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB})
		got, err := guarded.Check(ctx, "https://127.0.0.1:1/keys")
		if err != nil {
			t.Fatal(err)
		}
		if got.Error != "jwks_private_address" {
			t.Fatalf("check = %+v", got)
		}
	})
}

func TestExternalIssuerConfigModeRefusesWrites(t *testing.T) {
	svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{
		StaticIssuers: []domain.ExternalIssuerConfig{{Issuer: "https://i", Audience: "a", AllowedAccounts: []string{"acct"}}},
	})
	_, _, err := svc.Create(context.Background(), "acct", "u", IssuerInput{})
	var apiErr *IssuerAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != "issuer_store_config" {
		t.Fatalf("err = %v", err)
	}
	list, err := svc.List(context.Background(), "acct")
	if err != nil || len(list) != 1 || list[0].Source != domain.IssuerSourceConfig {
		t.Fatalf("config mode lists static entries read-only: %v %v", list, err)
	}
	if other, _ := svc.List(context.Background(), "other"); len(other) != 0 {
		t.Fatal("another account does not see the entry")
	}
}

func TestIdentityJWKS(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr := pkixPEM(t, &priv.PublicKey)
	raw, err := identityJWKS(&domain.Identity{ID: "id-1", PublicKeyPEM: pemStr})
	if err != nil {
		t.Fatal(err)
	}
	set, err := jwk.Parse(raw)
	if err != nil || set.Len() != 1 {
		t.Fatalf("set = %s, err %v", raw, err)
	}
	if _, err := identityJWKS(&domain.Identity{ID: "id-2"}); err == nil {
		t.Fatal("an identity with no key has no JWKS")
	}
}
