package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// TestExtractMappedClaimString covers the v1 claim-mapping shapes the three
// reference IdPs (Okta, Entra, Google) emit. v1 is single-level only — no
// JSONPath, no expressions.
func TestExtractMappedClaimString(t *testing.T) {
	t.Run("string sub from Okta", func(t *testing.T) {
		got, ok := extractMappedClaimString(map[string]any{"sub": "00uABC"}, "sub")
		if !ok || got != "00uABC" {
			t.Fatalf("expected (00uABC, true), got (%q, %v)", got, ok)
		}
	})

	t.Run("numeric oid from Entra is stringified", func(t *testing.T) {
		got, ok := extractMappedClaimString(map[string]any{"oid": float64(42)}, "oid")
		if !ok || got != "42" {
			t.Fatalf("expected (42, true), got (%q, %v)", got, ok)
		}
	})

	t.Run("large numeric subject avoids scientific notation", func(t *testing.T) {
		// JSON unmarshals a 16-digit integer literal into float64. %v / %g
		// would render this as 1.234567890123456e+15 and break downstream
		// equality checks against the upstream's stable subject identifier.
		got, ok := extractMappedClaimString(map[string]any{"sub": float64(1234567890123456)}, "sub")
		if !ok {
			t.Fatalf("expected ok=true for large numeric subject")
		}
		if got != "1234567890123456" {
			t.Fatalf("expected plain decimal %q, got %q", "1234567890123456", got)
		}
	})

	t.Run("missing path returns false", func(t *testing.T) {
		_, ok := extractMappedClaimString(map[string]any{"sub": "x"}, "email")
		if ok {
			t.Fatalf("expected ok=false for missing claim")
		}
	})

	t.Run("empty path returns false", func(t *testing.T) {
		_, ok := extractMappedClaimString(map[string]any{"sub": "x"}, "")
		if ok {
			t.Fatalf("empty path means no mapping configured; should be ok=false")
		}
	})

	t.Run("non-stringifiable value returns false", func(t *testing.T) {
		_, ok := extractMappedClaimString(map[string]any{"sub": map[string]any{}}, "sub")
		if ok {
			t.Fatalf("nested object cannot be coerced to string in v1; should be ok=false")
		}
	})
}

// TestRefuseWorkloadSubject covers the workload markers the ID-token exchange
// refuses, so a machine token is never minted as principal_type=user, and the
// person shapes it must keep accepting.
func TestRefuseWorkloadSubject(t *testing.T) {
	cases := []struct {
		name    string
		claims  map[string]any
		userID  string
		refused bool
	}{
		{"person sub", map[string]any{"sub": "00uABC"}, "00uABC", false},
		{"Entra delegated token (idtyp=user)", map[string]any{"sub": "abc", "idtyp": "user"}, "abc", false},
		{"Entra app-only token", map[string]any{"sub": "sp-object-id", "idtyp": "app"}, "sp-object-id", true},
		{"idtyp compared case-insensitively", map[string]any{"sub": "x", "idtyp": "App"}, "x", true},
		{"Kubernetes service account sub", map[string]any{"sub": "system:serviceaccount:ns:builder"}, "system:serviceaccount:ns:builder", true},
		{"Kubernetes service account in mapped user_id only", map[string]any{"sub": "opaque", "uid": "system:serviceaccount:ns:builder"}, "system:serviceaccount:ns:builder", true},
		{"SPIFFE ID sub", map[string]any{"sub": "spiffe://example.org/ns/prod/sa/api"}, "spiffe://example.org/ns/prod/sa/api", true},
		{"GitHub Actions workflow sub", map[string]any{"sub": "repo:acme/app:ref:refs/heads/main"}, "repo:acme/app:ref:refs/heads/main", true},
		{"SPIFFE scheme compared case-insensitively", map[string]any{"sub": "SPIFFE://example.org/w"}, "SPIFFE://example.org/w", true},
		{"SPIFFE ID in sub, person in mapped user_id", map[string]any{"sub": "spiffe://example.org/w", "oid": "person"}, "person", true},
		{"lookalike that is not a marker", map[string]any{"sub": "user:system:serviceaccount:x"}, "user:system:serviceaccount:x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseWorkloadSubject(tc.claims, tc.userID)
			if !tc.refused {
				if err != nil {
					t.Fatalf("expected a person token to be accepted, got %v", err)
				}
				return
			}
			var oauthErr *OAuthError
			if !errors.As(err, &oauthErr) {
				t.Fatalf("expected *OAuthError, got %T: %v", err, err)
			}
			if oauthErr.Code != "invalid_grant" || oauthErr.HTTPStatus != http.StatusBadRequest {
				t.Errorf("got %s/%d, want invalid_grant/400", oauthErr.Code, oauthErr.HTTPStatus)
			}
		})
	}
}

// TestCheckExternalIDTokenAlg verifies that the algorithm gate refuses
// none/HS* family tokens up front and respects the configured allow-list.
//
// We exercise it with crafted JWS strings rather than spinning up a real
// signer — the function only reads the protected header.
func TestCheckExternalIDTokenAlg(t *testing.T) {
	// alg=none token: header={"alg":"none","typ":"JWT"}, no signature.
	// Build by hand — base64url("{\"alg\":\"none\",\"typ\":\"JWT\"}") + ".eyJ9." (empty body, empty sig)
	// We don't bother — jws.Parse rejects unsigned tokens.
	// Instead we test alg=HS256 which has the same payload structure but is rejected.
	// HS256 header: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
	hs256 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4In0.AAAA"
	if err := checkExternalIDTokenAlg(hs256, []string{"RS256", "ES256"}); err == nil {
		t.Fatalf("expected HS256 to be rejected as non-asymmetric, got nil")
	}

	// RS256 with explicit allow-list match — header eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
	rs256 := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4In0.AAAA"
	if err := checkExternalIDTokenAlg(rs256, []string{"RS256"}); err != nil {
		t.Fatalf("expected RS256 to pass with allow-list [RS256], got %v", err)
	}

	// RS256 with an allow-list that excludes it.
	if err := checkExternalIDTokenAlg(rs256, []string{"ES256"}); err == nil {
		t.Fatalf("expected RS256 to be rejected when allow-list is [ES256]")
	}

	// Empty allow-list → defaults to the hard whitelist of asymmetric algs.
	if err := checkExternalIDTokenAlg(rs256, nil); err != nil {
		t.Fatalf("expected RS256 to pass with empty allow-list, got %v", err)
	}
}

// TestResolvePersonIssuer_OneGenericRefusal pins that an unverified
// token's issuer refusals are indistinguishable on the wire (one
// invalid_grant) while the cause stays in the chain for logs and callers.
func TestResolvePersonIssuer_OneGenericRefusal(t *testing.T) {
	jwksSrv := newFakeJWKSServer(t, "kid-1")
	defer jwksSrv.Close()
	const iss = "https://idp.example.test"
	rows := &fakeIssuerRows{rows: []*domain.ExternalIssuer{issuerRow("r1", "acct", iss, domain.IssuerKindPerson, jwksSrv.URL())}}
	svc := &OAuthService{externalIssuerRegistry: NewDBExternalIssuerRegistry(rows, true, nil, authjwt.WithHTTPClient(insecureHTTPClient(2*time.Second)))}
	defer svc.externalIssuerRegistry.Close()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := func(issuer string) string {
		tok, _ := jwt.NewBuilder().Issuer(issuer).Subject("alice").IssuedAt(time.Now()).Expiration(time.Now().Add(time.Minute)).Build()
		signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv))
		return string(signed)
	}
	var descriptions []string
	check := func(name, issuer string, sentinel error) {
		t.Helper()
		_, _, err := svc.resolvePersonIssuer(context.Background(), token(issuer), "subject_token")
		var oe *OAuthError
		if !errors.As(err, &oe) || oe.Code != "invalid_grant" || oe.HTTPStatus != http.StatusBadRequest {
			t.Fatalf("%s: err = %v", name, err)
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("%s: cause %v not in chain", name, sentinel)
		}
		descriptions = append(descriptions, oe.Description)
	}
	check("unknown", "https://stranger.example.test", ErrUnknownExternalIssuer)
	rows.set(func(r []*domain.ExternalIssuer) { r[0].Enabled = false })
	check("disabled", iss, errIssuerDisabled)
	rows.set(func(r []*domain.ExternalIssuer) { r[0].Enabled, r[0].Kind = true, domain.IssuerKindWorkload })
	check("workload", iss, errIssuerNotPerson)
	rows.set(func(r []*domain.ExternalIssuer) {
		r[0].Kind = domain.IssuerKindPerson
		r[0].ClaimConstraints = map[string][]string{"tid": {"t"}}
	})
	check("constraints", iss, errIssuerConstraints)
	for _, d := range descriptions[1:] {
		if d != descriptions[0] {
			t.Fatalf("refusals differ on the wire: %q vs %q", d, descriptions[0])
		}
	}
}

// TestRequireIDToken is ADR 0042 D3a rule 2: a token from a trusted issuer is
// accepted on the ID-token exchange only when it is positively an ID token.
func TestRequireIDToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(typ string, claims map[string]any) (string, jwt.Token) {
		tok := jwt.New()
		for k, v := range claims {
			_ = tok.Set(k, v)
		}
		hdr := jws.NewHeaders()
		if typ != "" {
			_ = hdr.Set(jws.TypeKey, typ)
		}
		raw, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdr)))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := jwt.ParseInsecure(raw)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw), parsed
	}
	idToken := func() map[string]any {
		now := time.Now()
		return map[string]any{"iss": "https://idp", "sub": "u", "aud": "client", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix()}
	}

	raw, tok := sign("JWT", idToken())
	if err := requireIDToken(raw, tok); err != nil {
		t.Fatalf("an ID token is accepted: %v", err)
	}
	c := idToken()
	c["roles"] = []string{"Approver"}
	if raw, tok := sign("JWT", c); requireIDToken(raw, tok) != nil {
		t.Fatal("an ID token may carry the user's app roles")
	}
	for _, typ := range []string{"at+jwt", "application/at+jwt", "AT+JWT", "oauth-id-jag+jwt"} {
		raw, tok := sign(typ, idToken())
		if err := requireIDToken(raw, tok); err == nil {
			t.Fatalf("typ %s marks an access token", typ)
		}
	}
	for _, claim := range []string{"scp", "scope", "azpacr", "appidacr"} {
		c := idToken()
		c[claim] = "mail.read"
		raw, tok := sign("JWT", c)
		if err := requireIDToken(raw, tok); err == nil {
			t.Fatalf("%s marks an access token", claim)
		}
	}
	for _, claim := range []string{"iss", "sub", "aud", "exp", "iat"} {
		c := idToken()
		delete(c, claim)
		raw, tok := sign("JWT", c)
		err := requireIDToken(raw, tok)
		var oe *OAuthError
		if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
			t.Fatalf("missing %s must be invalid_grant, got %v", claim, err)
		}
	}
}

// TestExternalIDTokenExchange_IssuerNotResolvedBeforeClientAuth: an
// anonymous exchange is invalid_client before any issuer lookup.
func TestExternalIDTokenExchange_IssuerNotResolvedBeforeClientAuth(t *testing.T) {
	rows := &fakeIssuerRows{}
	svc := &OAuthService{externalIssuerRegistry: NewDBExternalIssuerRegistry(rows, true, nil)}
	defer svc.externalIssuerRegistry.Close()
	tok, _ := jwt.NewBuilder().Issuer("https://probe.example.test").Subject("alice").Build()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv))
	_, err := svc.externalIDTokenExchange(context.Background(), TokenRequest{SubjectToken: string(signed)})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_client" {
		t.Fatalf("err = %v, want invalid_client", err)
	}
	if rows.calls != 0 {
		t.Fatalf("issuer looked up %d times before client authentication", rows.calls)
	}
}
