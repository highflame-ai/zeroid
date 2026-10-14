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
		{name: "shared, second account, other kind", existing: []*domain.ExternalIssuer{row("1", "a", domain.IssuerKindWorkload, "k1")},
			cand: row("", "b", domain.IssuerKindPerson, "k2"), shared: true},
		{name: "shared, second account, no constraints overlap trivially", existing: []*domain.ExternalIssuer{row("1", "a", domain.IssuerKindWorkload, "k1")},
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

// issuerServer serves a discovery document at /.well-known/openid-configuration
// naming docIssuer (the server's own URL when empty) and keys at /keys.
func issuerServer(t *testing.T, docIssuer string, keysStatus int, keysBody string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			iss := docIssuer
			if iss == "" {
				iss = srv.URL
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": srv.URL + "/keys"})
		case "/keys":
			w.WriteHeader(keysStatus)
			_, _ = w.Write([]byte(keysBody))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExternalIssuerCheck(t *testing.T) {
	svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{
		Store: IssuerStoreDB, AllowPrivateEndpoints: true, HTTPClient: http.DefaultClient,
	})
	ctx := context.Background()

	t.Run("discovery, then keys", func(t *testing.T) {
		srv := issuerServer(t, "", http.StatusOK, testJWKS(t, "k1"))
		got, err := svc.Check(ctx, srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Reachable || got.KeyCount != 1 || got.KIDs[0] != "k1" || got.Error != "" || got.JWKSURI != srv.URL+"/keys" {
			t.Fatalf("check = %+v", got)
		}
	})
	t.Run("a discovery document naming another issuer is refused", func(t *testing.T) {
		srv := issuerServer(t, "https://victim.example", http.StatusOK, testJWKS(t, "k1"))
		got, _ := svc.Check(ctx, srv.URL)
		if got.Error != "discovery_issuer_mismatch" || got.Reachable {
			t.Fatalf("check = %+v", got)
		}
	})
	t.Run("no discovery document", func(t *testing.T) {
		srv := issuerServer(t, "", http.StatusOK, "")
		got, _ := svc.Check(ctx, srv.URL+"/nothing-here")
		if got.Error != "discovery_unreachable" {
			t.Fatalf("check = %+v", got)
		}
	})
	t.Run("upstream key error body is not echoed", func(t *testing.T) {
		srv := issuerServer(t, "", http.StatusInternalServerError, "secret internal detail")
		got, _ := svc.Check(ctx, srv.URL)
		raw, _ := json.Marshal(got)
		if got.Reachable || got.Error != "jwks_unreachable" || strings.Contains(string(raw), "secret") {
			t.Fatalf("check = %s", raw)
		}
	})
	t.Run("empty keys", func(t *testing.T) {
		srv := issuerServer(t, "", http.StatusOK, `{"keys":[]}`)
		got, _ := svc.Check(ctx, srv.URL)
		if got.Error != "jwks_empty" {
			t.Fatalf("check = %+v", got)
		}
	})
	t.Run("an invalid issuer is an error", func(t *testing.T) {
		_, err := svc.Check(ctx, "ftp://x")
		var apiErr *IssuerAPIError
		if !errors.As(err, &apiErr) || apiErr.Code != "invalid_issuer" || apiErr.Status != http.StatusBadRequest {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the default client refuses a private address", func(t *testing.T) {
		guarded := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB})
		got, err := guarded.Check(ctx, "https://127.0.0.1:1")
		if err != nil {
			t.Fatal(err)
		}
		if got.Error != "discovery_unreachable" {
			t.Fatalf("check = %+v; a private address is not told apart (no internal-DNS oracle)", got)
		}
	})
	t.Run("discovery does not follow redirects", func(t *testing.T) {
		target := issuerServer(t, "", http.StatusOK, testJWKS(t, "k1"))
		var redirector *httptest.Server
		redirector = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
		}))
		defer redirector.Close()
		got, _ := svc.Check(ctx, redirector.URL)
		if got.Error != "discovery_unreachable" {
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

func TestUniquenessConflict_SharedOverlap(t *testing.T) {
	row := func(id, acct string, c map[string][]string) *domain.ExternalIssuer {
		return &domain.ExternalIssuer{ID: id, AccountID: acct, Kind: domain.IssuerKindPerson, ClaimConstraints: c}
	}
	a := row("1", "a", map[string][]string{"hd": {"acme.com"}})
	for name, tc := range map[string]struct {
		c    map[string][]string
		want bool
	}{
		"same set":                        {map[string][]string{"hd": {"acme.com"}}, true},
		"superset on another claim":       {map[string][]string{"hd": {"acme.com"}, "email_verified": {"true"}}, true},
		"values intersect":                {map[string][]string{"hd": {"acme.com", "beta.com"}}, true},
		"different claim only":            {map[string][]string{"tid": {"t1"}}, true},
		"disjoint values on shared claim": {map[string][]string{"hd": {"beta.com"}}, false},
		"disjoint and another claim":      {map[string][]string{"hd": {"beta.com"}, "tid": {"t1"}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := uniquenessConflict([]*domain.ExternalIssuer{a}, row("", "b", tc.c), true); got != tc.want {
				t.Fatalf("conflict = %v, want %v", got, tc.want)
			}
		})
	}
}
