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
	"time"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/jwks"
)

const (
	verifyRowID    = "11111111-2222-3333-4444-555555555555"
	verifyIssuer   = "https://idp.verify.example"
	verifyClientID = "verify-app"
	verifyNonce    = "n-0123456789abcdef"
)

// verifyFixture is one person issuer row, its key, and the service the
// ownership proof runs on.
type verifyFixture struct {
	jwks *fakeJWKSServer
	row  *domain.ExternalIssuer
	svc  *ExternalIssuerService
}

func newVerifyFixture(t *testing.T, shared []domain.SharedIssuer) *verifyFixture {
	t.Helper()
	srv := newFakeJWKSServer(t, "k1")
	t.Cleanup(srv.Close)
	row := issuerRow(verifyRowID, "acct-a", verifyIssuer, domain.IssuerKindPerson, srv.URL())
	row.Audiences = nil
	row.ClaimMapping = map[string]string{"user_id": "sub", "email": "email", "email_verified": "email_verified"}
	reg := NewDBExternalIssuerRegistry(&fakeIssuerRows{rows: []*domain.ExternalIssuer{row}}, true, shared,
		jwks.WithHTTPClient(insecureHTTPClient(2*time.Second)))
	t.Cleanup(reg.Close)
	svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB, Registry: reg})
	return &verifyFixture{jwks: srv, row: row, svc: svc}
}

func (f *verifyFixture) claims(extra map[string]any) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss": verifyIssuer, "sub": "person-1", "aud": verifyClientID,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"nonce": verifyNonce, "email": "owner@acme.example", "email_verified": true,
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func (f *verifyFixture) token(t *testing.T, extra map[string]any) string {
	t.Helper()
	return signWithTyp(t, f.jwks.curPriv, "k1", "JWT", f.claims(extra))
}

func (f *verifyFixture) verify(t *testing.T, row *domain.ExternalIssuer, tok string) (*IDTokenVerification, error) {
	t.Helper()
	return f.svc.verifyIDTokenForRow(context.Background(), row, VerifyIDTokenInput{IDToken: tok, ClientID: verifyClientID, Nonce: verifyNonce})
}

func requireIssuerCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	var apiErr *IssuerAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != code || apiErr.Status != status {
		t.Fatalf("err = %v (%#v), want %d %s", err, apiErr, status, code)
	}
}

func TestVerifyIDToken_HappyPath(t *testing.T) {
	f := newVerifyFixture(t, nil)
	got, err := f.verify(t, f.row, f.token(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := IDTokenVerification{IssuerID: verifyRowID, Issuer: verifyIssuer, Subject: "person-1", Email: "owner@acme.example", EmailVerified: true}
	if *got != want {
		t.Fatalf("got %+v, want %+v", *got, want)
	}
	raw, _ := json.Marshal(got)
	if string(raw) != `{"issuer_id":"`+verifyRowID+`","issuer":"`+verifyIssuer+`","subject":"person-1","email":"owner@acme.example","email_verified":true}` {
		t.Fatalf("wire shape = %s", raw)
	}
}

func TestVerifyIDToken_Refusals(t *testing.T) {
	f := newVerifyFixture(t, nil)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	cases := []struct {
		name  string
		token func() string
		code  string
	}{
		{"no nonce", func() string { return f.token(t, map[string]any{"nonce": nil}) }, "nonce_mismatch"},
		{"another nonce", func() string { return f.token(t, map[string]any{"nonce": verifyNonce + "x"}) }, "nonce_mismatch"},
		{"a non-string nonce", func() string { return f.token(t, map[string]any{"nonce": 7}) }, "nonce_mismatch"},
		{"wrong aud", func() string { return f.token(t, map[string]any{"aud": "another-app"}) }, "audience_mismatch"},
		{"azp names another party", func() string { return f.token(t, map[string]any{"azp": "another-app"}) }, "audience_mismatch"},
		{"azp is not a string", func() string {
			return f.token(t, map[string]any{"azp": []string{"another-app"}})
		}, "audience_mismatch"},
		{"azp is not a string, several audiences", func() string {
			return f.token(t, map[string]any{"aud": []string{verifyClientID, "another-app"}, "azp": []string{verifyClientID}})
		}, "audience_mismatch"},
		{"several audiences, no azp", func() string {
			return f.token(t, map[string]any{"aud": []string{verifyClientID, "another-app"}})
		}, "audience_mismatch"},
		{"expired", func() string {
			return f.token(t, map[string]any{"exp": time.Now().Add(-10 * time.Minute).Unix()})
		}, "token_invalid"},
		{"not yet valid", func() string {
			return f.token(t, map[string]any{"nbf": time.Now().Add(10 * time.Minute).Unix()})
		}, "token_invalid"},
		{"older than max_token_age", func() string {
			return f.token(t, map[string]any{"iat": old.Unix(), "nbf": old.Unix()})
		}, "token_invalid"},
		{"no iat", func() string { return f.token(t, map[string]any{"iat": nil}) }, "token_invalid"},
		{"signed by an unknown key", func() string { return signWithTyp(t, other, "k-unknown", "JWT", f.claims(nil)) }, "token_invalid"},
		{"signed by another key under the known kid", func() string { return signWithTyp(t, other, "k1", "JWT", f.claims(nil)) }, "token_invalid"},
		{"another issuer", func() string { return f.token(t, map[string]any{"iss": "https://evil.example"}) }, "token_invalid"},
		{"malformed", func() string { return "not.a.jwt" }, "token_invalid"},
		{"an access token (scp)", func() string { return f.token(t, map[string]any{"scp": "User.Read"}) }, "token_invalid"},
		{"an access token (typ at+jwt)", func() string { return signWithTyp(t, f.jwks.curPriv, "k1", "at+jwt", f.claims(nil)) }, "token_invalid"},
		{"a workload subject", func() string {
			return f.token(t, map[string]any{"sub": "system:serviceaccount:default:agent"})
		}, "token_invalid"},
		{"an app-only token", func() string { return f.token(t, map[string]any{"idtyp": "app"}) }, "token_invalid"},
		{"no sub", func() string { return f.token(t, map[string]any{"sub": nil}) }, "token_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := tc.token()
			_, err := f.verify(t, f.row, tok)
			requireIssuerCode(t, err, http.StatusUnprocessableEntity, tc.code)
			if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "owner@acme.example") || strings.Contains(err.Error(), "person-1") {
				t.Fatalf("refusal echoes the token or its claims: %v", err)
			}
		})
	}
}

func TestVerifyIDToken_RowState(t *testing.T) {
	f := newVerifyFixture(t, nil)
	tok := f.token(t, nil)
	t.Run("a disabled row", func(t *testing.T) {
		row := *f.row
		row.Enabled = false
		_, err := f.verify(t, &row, tok)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "issuer_disabled")
	})
	t.Run("a workload row", func(t *testing.T) {
		row := *f.row
		row.Kind = domain.IssuerKindWorkload
		row.Audiences = []string{verifyClientID}
		_, err := f.verify(t, &row, tok)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "wrong_kind")
	})
	t.Run("a disabled workload row is wrong_kind first", func(t *testing.T) {
		row := *f.row
		row.Kind, row.Enabled = domain.IssuerKindWorkload, false
		_, err := f.verify(t, &row, tok)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "wrong_kind")
	})
	t.Run("an unloadable key set", func(t *testing.T) {
		dead := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer dead.Close()
		row := *f.row
		row.JWKSURI = dead.URL
		_, err := f.verify(t, &row, tok)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "jwks_unreachable")
	})
	t.Run("no registry", func(t *testing.T) {
		svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB})
		_, err := svc.verifyIDTokenForRow(context.Background(), f.row, VerifyIDTokenInput{IDToken: tok, ClientID: verifyClientID, Nonce: verifyNonce})
		var apiErr *IssuerAPIError
		if err == nil || errors.As(err, &apiErr) {
			t.Fatalf("err = %v, want an internal error", err)
		}
	})
}

func TestVerifyIDToken_Constraints(t *testing.T) {
	t.Run("a row's claim constraints hold on the verified claims", func(t *testing.T) {
		f := newVerifyFixture(t, nil)
		row := *f.row
		row.ClaimConstraints = map[string][]string{"tid": {"tenant-a"}}
		if _, err := f.verify(t, &row, f.token(t, map[string]any{"tid": "tenant-a"})); err != nil {
			t.Fatal(err)
		}
		_, err := f.verify(t, &row, f.token(t, map[string]any{"tid": "tenant-b"}))
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "constraint_mismatch")
		_, err = f.verify(t, &row, f.token(t, nil))
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "constraint_mismatch")
	})
	t.Run("a shared issuer's pinning claim must be a single matching string", func(t *testing.T) {
		f := newVerifyFixture(t, []domain.SharedIssuer{{Issuer: verifyIssuer, PinClaim: "hd"}})
		row := *f.row
		row.ClaimConstraints = map[string][]string{"hd": {"acme.example"}}
		if _, err := f.verify(t, &row, f.token(t, map[string]any{"hd": "acme.example"})); err != nil {
			t.Fatal(err)
		}
		_, err := f.verify(t, &row, f.token(t, map[string]any{"hd": []string{"acme.example", "other.example"}}))
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "constraint_mismatch")
		_, err = f.verify(t, &row, f.token(t, map[string]any{"hd": "other.example"}))
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "constraint_mismatch")
	})
}

// A row's own audiences admit a token past the signature checks, but the
// token must still name client_id: idTokenIssuedTo is the check that refuses
// it, not validateExternalAssertion's audience gate.
func TestVerifyIDToken_RowAudienceIsNotTheClient(t *testing.T) {
	f := newVerifyFixture(t, nil)
	row := *f.row
	row.Audiences = []string{"row-aud"}
	if _, err := f.verify(t, &row, f.token(t, map[string]any{"aud": []string{"row-aud", verifyClientID}, "azp": verifyClientID})); err != nil {
		t.Fatal(err)
	}
	_, err := f.verify(t, &row, f.token(t, map[string]any{"aud": "row-aud"}))
	requireIssuerCode(t, err, http.StatusUnprocessableEntity, "audience_mismatch")
}

// verifyPersonIDToken accepts the client as an extra audience only on an
// issuer row (where a binding is required next). A static issuer accepts its
// configured audiences only, exactly as the exchange did before the routine
// was shared.
func TestVerifyPersonIDToken_StaticIssuerAddsNoAudience(t *testing.T) {
	srv := newFakeJWKSServer(t, "k1")
	t.Cleanup(srv.Close)
	reg, err := NewExternalIssuerRegistry(context.Background(), []domain.ExternalIssuerConfig{{
		Issuer: verifyIssuer, JWKSURI: srv.URL(), Audience: "configured-aud",
		Algorithms: []string{"ES256"}, JWKSCacheTTL: time.Minute, MaxTokenAge: time.Hour,
		ClaimMapping: map[string]string{"user_id": "sub"},
	}}, jwks.WithHTTPClient(insecureHTTPClient(2*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)
	entry, err := reg.ResolvePerson(context.Background(), verifyIssuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &verifyFixture{jwks: srv}
	sign := func(extra map[string]any) string { return signWithTyp(t, srv.curPriv, "k1", "JWT", f.claims(extra)) }

	if _, err := verifyPersonIDToken(context.Background(), sign(map[string]any{"aud": []string{"configured-aud", verifyClientID}, "azp": verifyClientID}), entry, verifyClientID); err != nil {
		t.Fatalf("a token for the configured audience and the client: %v", err)
	}
	_, err = verifyPersonIDToken(context.Background(), sign(map[string]any{"aud": verifyClientID}), entry, verifyClientID)
	if !errors.Is(err, errAssertionAudience) {
		t.Fatalf("a static issuer accepted the client as an audience it was not configured for: %v", err)
	}
}

func TestVerifyIDToken_ClaimMapping(t *testing.T) {
	f := newVerifyFixture(t, nil)
	t.Run("Entra: user key oid, email_verified from xms_edov", func(t *testing.T) {
		row := *f.row
		row.ClaimMapping = map[string]string{"user_id": "oid", "email": "email", "email_verified": "xms_edov"}
		got, err := f.verify(t, &row, f.token(t, map[string]any{"oid": "oid-1", "xms_edov": true, "email_verified": nil}))
		if err != nil {
			t.Fatal(err)
		}
		if got.Subject != "oid-1" || !got.EmailVerified {
			t.Fatalf("got %+v", got)
		}
		got, err = f.verify(t, &row, f.token(t, map[string]any{"oid": "oid-1", "email_verified": true}))
		if err != nil {
			t.Fatal(err)
		}
		if got.EmailVerified {
			t.Fatal("email_verified is read only from the mapped claim (xms_edov), never from email_verified")
		}
	})
	t.Run("email_verified false or absent", func(t *testing.T) {
		got, err := f.verify(t, f.row, f.token(t, map[string]any{"email_verified": false}))
		if err != nil || got.EmailVerified {
			t.Fatalf("got %+v, %v", got, err)
		}
		got, err = f.verify(t, f.row, f.token(t, map[string]any{"email_verified": nil, "email": nil}))
		if err != nil || got.EmailVerified || got.Email != "" {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("the mapped user key is required", func(t *testing.T) {
		row := *f.row
		row.ClaimMapping = map[string]string{"user_id": "oid"}
		_, err := f.verify(t, &row, f.token(t, nil))
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "token_invalid")
	})
}

func TestVerifyIDToken_Input(t *testing.T) {
	svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB})
	ok := VerifyIDTokenInput{IDToken: "x", ClientID: "c", Nonce: "n"}
	cases := map[string]func(*VerifyIDTokenInput){
		"no id_token":         func(in *VerifyIDTokenInput) { in.IDToken = "" },
		"no client_id":        func(in *VerifyIDTokenInput) { in.ClientID = "" },
		"no nonce":            func(in *VerifyIDTokenInput) { in.Nonce = "" },
		"oversized id_token":  func(in *VerifyIDTokenInput) { in.IDToken = strings.Repeat("a", maxVerifyIDTokenBytes+1) },
		"oversized client_id": func(in *VerifyIDTokenInput) { in.ClientID = strings.Repeat("a", maxVerifyClientIDBytes+1) },
		"oversized nonce":     func(in *VerifyIDTokenInput) { in.Nonce = strings.Repeat("a", maxVerifyNonceBytes+1) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			in := ok
			mut(&in)
			// Refused before the row is read (the service has no repo).
			_, err := svc.VerifyIDToken(context.Background(), "acct-a", verifyRowID, in)
			requireIssuerCode(t, err, http.StatusBadRequest, "invalid_request")
		})
	}
	t.Run("a config-mode server refuses", func(t *testing.T) {
		cfgSvc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreConfig})
		_, err := cfgSvc.VerifyIDToken(context.Background(), "acct-a", verifyRowID, ok)
		requireIssuerCode(t, err, http.StatusConflict, "issuer_store_config")
		_, err = cfgSvc.Discovery(context.Background(), "acct-a", verifyRowID)
		requireIssuerCode(t, err, http.StatusConflict, "issuer_store_config")
	})
}

func TestNonceMatches(t *testing.T) {
	cases := []struct {
		got, want string
		match     bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "abcd", false},
		{"", "", false},
		{"", "abc", false},
	}
	for _, tc := range cases {
		if nonceMatches(tc.got, tc.want) != tc.match {
			t.Errorf("nonceMatches(%q, %q) != %v", tc.got, tc.want, tc.match)
		}
	}
}

// discoveryServer serves a TLS discovery document; doc fields override the
// defaults, and an empty value drops one.
func discoveryServer(t *testing.T, doc map[string]string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		out := map[string]string{
			"issuer": srv.URL, "jwks_uri": srv.URL + "/keys",
			"authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
		}
		for k, v := range doc {
			if v == "" {
				delete(out, k)
				continue
			}
			out[k] = strings.ReplaceAll(v, "{base}", srv.URL)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIssuerDiscovery(t *testing.T) {
	ctx := context.Background()
	run := func(t *testing.T, doc map[string]string, kind domain.IssuerKind) (*IssuerDiscovery, error) {
		t.Helper()
		srv := discoveryServer(t, doc)
		// HTTPClient bypasses the SSRF guard to reach the test server; the
		// https rule on the endpoints is the one under test.
		svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB, HTTPClient: srv.Client()})
		row := issuerRow(verifyRowID, "acct-a", srv.URL, kind, srv.URL+"/keys")
		return svc.discoveryForRow(ctx, row)
	}

	t.Run("the sign-in endpoints", func(t *testing.T) {
		got, err := run(t, nil, domain.IssuerKindPerson)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(got.AuthorizationEndpoint, "/authorize") || !strings.HasSuffix(got.TokenEndpoint, "/token") ||
			!strings.HasPrefix(got.Issuer, "https://") {
			t.Fatalf("got %+v", got)
		}
		raw, _ := json.Marshal(got)
		var keys map[string]any
		_ = json.Unmarshal(raw, &keys)
		if len(keys) != 3 || keys["issuer"] == nil || keys["authorization_endpoint"] == nil || keys["token_endpoint"] == nil {
			t.Fatalf("wire shape = %s", raw)
		}
	})
	refusals := []struct {
		name string
		doc  map[string]string
		code string
	}{
		{"an http authorization endpoint", map[string]string{"authorization_endpoint": "http://idp.example/authorize"}, "discovery_invalid"},
		{"an http token endpoint", map[string]string{"token_endpoint": "http://idp.example/token"}, "discovery_invalid"},
		{"no authorization endpoint", map[string]string{"authorization_endpoint": ""}, "discovery_invalid"},
		{"no token endpoint", map[string]string{"token_endpoint": ""}, "discovery_invalid"},
		{"an endpoint with userinfo", map[string]string{"token_endpoint": "https://user:pw@idp.example/token"}, "discovery_invalid"},
		{"an endpoint with a fragment", map[string]string{"authorization_endpoint": "{base}/authorize#x"}, "discovery_invalid"},
		{"a relative endpoint", map[string]string{"authorization_endpoint": "/authorize"}, "discovery_invalid"},
		{"a document naming another issuer", map[string]string{"issuer": "https://victim.example"}, "discovery_issuer_mismatch"},
		{"no jwks_uri", map[string]string{"jwks_uri": ""}, "discovery_invalid"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(t, tc.doc, domain.IssuerKindPerson)
			requireIssuerCode(t, err, http.StatusUnprocessableEntity, tc.code)
		})
	}
	t.Run("a workload row", func(t *testing.T) {
		_, err := run(t, nil, domain.IssuerKindWorkload)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "wrong_kind")
	})
	t.Run("the default client refuses a private address", func(t *testing.T) {
		svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{Store: IssuerStoreDB})
		row := issuerRow(verifyRowID, "acct-a", "https://127.0.0.1:1", domain.IssuerKindPerson, "https://127.0.0.1:1/keys")
		_, err := svc.discoveryForRow(ctx, row)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "discovery_unreachable")
	})
}
