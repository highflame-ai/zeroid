package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/jwks"
)

const (
	workloadVerifyIssuer    = "https://oidc.eks.verify.example/id/ABC"
	workloadVerifyChallenge = "highflame-issuer-verification:0123456789abcdef"
	workloadVerifySubject   = "system:serviceaccount:agents:planner"
	workloadVerifySelf      = "https://auth.zeroid.example"
)

// newWorkloadVerifyFixture is one disabled workload issuer row (rows wait
// disabled for this proof), its key, and the service the proof runs on.
func newWorkloadVerifyFixture(t *testing.T, shared []domain.SharedIssuer) *verifyFixture {
	t.Helper()
	srv := newFakeJWKSServer(t, "k1")
	t.Cleanup(srv.Close)
	row := issuerRow(verifyRowID, "acct-a", workloadVerifyIssuer, domain.IssuerKindWorkload, srv.URL())
	row.Audiences = []string{workloadVerifySelf}
	row.Enabled = false
	reg := NewDBExternalIssuerRegistry(&fakeIssuerRows{rows: []*domain.ExternalIssuer{row}}, true, shared,
		jwks.WithHTTPClient(insecureHTTPClient(2*time.Second)))
	t.Cleanup(reg.Close)
	svc := NewExternalIssuerService(nil, nil, nil, ExternalIssuerServiceConfig{
		Store: IssuerStoreDB, Registry: reg, SelfIssuer: workloadVerifySelf,
	})
	return &verifyFixture{jwks: srv, row: row, svc: svc}
}

func (f *verifyFixture) workloadToken(t *testing.T, extra map[string]any) string {
	t.Helper()
	now := time.Now()
	c := map[string]any{
		"iss": workloadVerifyIssuer, "sub": workloadVerifySubject, "aud": workloadVerifyChallenge,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return signWithTyp(t, f.jwks.curPriv, "k1", "JWT", c)
}

func (f *verifyFixture) verifyWorkload(row *domain.ExternalIssuer, tok, audience string) (*WorkloadTokenVerification, error) {
	return f.svc.verifyWorkloadTokenForRow(context.Background(), row, VerifyWorkloadTokenInput{Token: tok, Audience: audience})
}

func TestVerifyWorkloadToken_HappyPathOnADisabledRow(t *testing.T) {
	f := newWorkloadVerifyFixture(t, nil)
	got, err := f.verifyWorkload(f.row, f.workloadToken(t, nil), workloadVerifyChallenge)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	if string(raw) != `{"issuer_id":"`+verifyRowID+`","issuer":"`+workloadVerifyIssuer+`","subject":"`+workloadVerifySubject+`"}` {
		t.Fatalf("wire shape = %s", raw)
	}
}

func TestVerifyWorkloadToken_Refusals(t *testing.T) {
	f := newWorkloadVerifyFixture(t, nil)
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
		{"another audience", func() string { return f.workloadToken(t, map[string]any{"aud": "sts.amazonaws.com"}) }, "audience_mismatch"},
		// A P2 assertion names the row's audience: captured in transit, it
		// must not stand in for the proof.
		{"the row's own audience", func() string { return f.workloadToken(t, map[string]any{"aud": workloadVerifySelf}) }, "audience_mismatch"},
		{"the challenge among several audiences", func() string {
			return f.workloadToken(t, map[string]any{"aud": []string{workloadVerifyChallenge, "sts.amazonaws.com"}})
		}, "audience_mismatch"},
		{"the challenge and the row's audience", func() string {
			return f.workloadToken(t, map[string]any{"aud": []string{workloadVerifyChallenge, workloadVerifySelf}})
		}, "audience_mismatch"},
		{"expired", func() string {
			return f.workloadToken(t, map[string]any{"exp": time.Now().Add(-10 * time.Minute).Unix()})
		}, "token_invalid"},
		{"older than max_token_age", func() string {
			return f.workloadToken(t, map[string]any{"iat": old.Unix(), "nbf": old.Unix()})
		}, "token_invalid"},
		{"a lifetime over max_token_age", func() string {
			return f.workloadToken(t, map[string]any{"exp": time.Now().Add(2 * time.Hour).Unix()})
		}, "token_invalid"},
		{"no iat", func() string { return f.workloadToken(t, map[string]any{"iat": nil}) }, "token_invalid"},
		{"no exp", func() string { return f.workloadToken(t, map[string]any{"exp": nil}) }, "token_invalid"},
		{"no sub", func() string { return f.workloadToken(t, map[string]any{"sub": nil}) }, "token_invalid"},
		{"signed by an unknown key", func() string {
			return signWithTyp(t, other, "k-unknown", "JWT", map[string]any{
				"iss": workloadVerifyIssuer, "sub": workloadVerifySubject, "aud": workloadVerifyChallenge,
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
			})
		}, "token_invalid"},
		{"signed by another key under the known kid", func() string {
			return signWithTyp(t, other, "k1", "JWT", map[string]any{
				"iss": workloadVerifyIssuer, "sub": workloadVerifySubject, "aud": workloadVerifyChallenge,
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
			})
		}, "token_invalid"},
		{"another issuer", func() string { return f.workloadToken(t, map[string]any{"iss": "https://evil.example"}) }, "token_invalid"},
		{"malformed", func() string { return "not.a.jwt" }, "token_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := tc.token()
			_, err := f.verifyWorkload(f.row, tok, workloadVerifyChallenge)
			requireIssuerCode(t, err, http.StatusUnprocessableEntity, tc.code)
			if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), workloadVerifySubject) {
				t.Fatalf("refusal echoes the token or its claims: %v", err)
			}
		})
	}
}

func TestVerifyWorkloadToken_TheChallengeMustBeOneNoAssertionCarries(t *testing.T) {
	f := newWorkloadVerifyFixture(t, nil)
	for _, aud := range []string{workloadVerifySelf, workloadVerifySelf + "/"} {
		_, err := f.verifyWorkload(f.row, f.workloadToken(t, map[string]any{"aud": aud}), aud)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "audience_not_a_challenge")
	}
}

func TestVerifyWorkloadToken_RowState(t *testing.T) {
	f := newWorkloadVerifyFixture(t, nil)
	tok := f.workloadToken(t, nil)
	t.Run("an enabled row verifies too", func(t *testing.T) {
		row := *f.row
		row.Enabled = true
		if _, err := f.verifyWorkload(&row, tok, workloadVerifyChallenge); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a person row", func(t *testing.T) {
		row := *f.row
		row.Kind = domain.IssuerKindPerson
		_, err := f.verifyWorkload(&row, tok, workloadVerifyChallenge)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "wrong_kind")
	})
}

func TestVerifyWorkloadToken_Constraints(t *testing.T) {
	t.Run("a row's claim constraints hold on the verified claims", func(t *testing.T) {
		f := newWorkloadVerifyFixture(t, nil)
		row := *f.row
		row.ClaimConstraints = map[string][]string{"kubernetes.io/namespace": {"agents"}}
		if _, err := f.verifyWorkload(&row, f.workloadToken(t, map[string]any{"kubernetes.io/namespace": "agents"}), workloadVerifyChallenge); err != nil {
			t.Fatal(err)
		}
		_, err := f.verifyWorkload(&row, f.workloadToken(t, map[string]any{"kubernetes.io/namespace": "other"}), workloadVerifyChallenge)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "constraint_mismatch")
	})
	// A shared issuer is squatted by pinning another customer's value
	// (repository_owner on GitHub Actions): only a token carrying that value,
	// one the squatter cannot obtain, proves the row.
	t.Run("a shared issuer's pin must match", func(t *testing.T) {
		f := newWorkloadVerifyFixture(t, []domain.SharedIssuer{{Issuer: workloadVerifyIssuer, PinClaim: "repository_owner"}})
		row := *f.row
		row.ClaimConstraints = map[string][]string{"repository_owner": {"acme"}}
		if _, err := f.verifyWorkload(&row, f.workloadToken(t, map[string]any{"repository_owner": "acme"}), workloadVerifyChallenge); err != nil {
			t.Fatal(err)
		}
		_, err := f.verifyWorkload(&row, f.workloadToken(t, map[string]any{"repository_owner": "squatter"}), workloadVerifyChallenge)
		requireIssuerCode(t, err, http.StatusUnprocessableEntity, "constraint_mismatch")
	})
}

func TestVerifyWorkloadToken_InputCaps(t *testing.T) {
	cases := []VerifyWorkloadTokenInput{
		{Token: "", Audience: "a"},
		{Token: "t", Audience: ""},
		{Token: strings.Repeat("a", maxVerifyWorkloadTokenBytes+1), Audience: "a"},
		{Token: "t", Audience: strings.Repeat("a", maxVerifyAudienceBytes+1)},
	}
	for _, in := range cases {
		requireIssuerCode(t, validateVerifyWorkloadTokenInput(in), http.StatusBadRequest, "invalid_request")
	}
}
