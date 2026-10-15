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

// signWithTyp serialises the given claim map as an ES256 JWT whose protected
// header carries the supplied typ — used to mint ID-JAG-shaped (typ:
// oauth-id-jag+jwt) and ordinary assertions for the typ-branch tests.
func signWithTyp(t *testing.T, priv *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		if err := tok.Set(k, v); err != nil {
			t.Fatalf("set claim %q: %v", k, err)
		}
	}
	hdr := jws.NewHeaders()
	if kid != "" {
		_ = hdr.Set(jws.KeyIDKey, kid)
	}
	if typ != "" {
		_ = hdr.Set(jws.TypeKey, typ)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// TestIsIDJAGAssertion verifies the typ-branch discriminator: only an assertion
// whose JWS typ header is exactly oauth-id-jag+jwt routes to the ID-JAG path.
// Everything else (a JWT typ, no typ, a malformed token) stays on the NHI
// self-signed path. This is the gate the whole ADR 0010 D2 branch hinges on.
func TestIsIDJAGAssertion(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	base := map[string]any{"iss": "https://idp.test", "sub": "alice"}

	t.Run("typ oauth-id-jag+jwt is an ID-JAG", func(t *testing.T) {
		tok := signWithTyp(t, priv, "kid", idJAGTyp, base)
		if !isIDJAGAssertion(tok) {
			t.Fatalf("expected oauth-id-jag+jwt assertion to be detected as ID-JAG")
		}
	})

	t.Run("typ JWT is NOT an ID-JAG (NHI path)", func(t *testing.T) {
		tok := signWithTyp(t, priv, "kid", "JWT", base)
		if isIDJAGAssertion(tok) {
			t.Fatalf("a typ=JWT assertion must NOT be treated as an ID-JAG")
		}
	})

	t.Run("no typ header is NOT an ID-JAG (NHI path)", func(t *testing.T) {
		tok := signWithTyp(t, priv, "kid", "", base)
		if isIDJAGAssertion(tok) {
			t.Fatalf("an assertion without a typ header must NOT be treated as an ID-JAG")
		}
	})

	t.Run("garbage is NOT an ID-JAG", func(t *testing.T) {
		if isIDJAGAssertion("not-a-jwt") {
			t.Fatalf("a malformed assertion must NOT be treated as an ID-JAG")
		}
		if isIDJAGAssertion("") {
			t.Fatalf("an empty assertion must NOT be treated as an ID-JAG")
		}
	})
}

// TestExtractMappedClaimStrings covers the two multi-valued claim shapes the
// ID-JAG path reads: a space-delimited `scope` string and an array-valued
// claim (groups / privilege_scope). Numeric array entries are stringified.
func TestExtractMappedClaimStrings(t *testing.T) {
	t.Run("space-delimited scope string", func(t *testing.T) {
		got, ok := extractMappedClaimStrings(map[string]any{"scope": "read write admin"}, "scope")
		if !ok {
			t.Fatalf("expected ok=true")
		}
		if len(got) != 3 || got[0] != "read" || got[2] != "admin" {
			t.Fatalf("expected [read write admin], got %v", got)
		}
	})

	t.Run("string array", func(t *testing.T) {
		got, ok := extractMappedClaimStrings(map[string]any{"groups": []any{"eng", "admin"}}, "groups")
		if !ok || len(got) != 2 || got[0] != "eng" || got[1] != "admin" {
			t.Fatalf("expected [eng admin], got %v (ok=%v)", got, ok)
		}
	})

	t.Run("numeric array entries stringified", func(t *testing.T) {
		got, ok := extractMappedClaimStrings(map[string]any{"ids": []any{float64(1), float64(2)}}, "ids")
		if !ok || len(got) != 2 || got[0] != "1" || got[1] != "2" {
			t.Fatalf("expected [1 2], got %v (ok=%v)", got, ok)
		}
	})

	t.Run("missing claim returns false", func(t *testing.T) {
		if _, ok := extractMappedClaimStrings(map[string]any{"scope": "x"}, "groups"); ok {
			t.Fatalf("expected ok=false for missing claim")
		}
	})

	t.Run("empty path returns false", func(t *testing.T) {
		if _, ok := extractMappedClaimStrings(map[string]any{"scope": "x"}, ""); ok {
			t.Fatalf("expected ok=false for empty path (no mapping configured)")
		}
	})
}

// TestExtractResourceClaim verifies the ID-JAG `resource` claim is read per
// RFC 8707: a string is ONE resource taken ATOMICALLY (never space-split like a
// scope string), and an array is multi-valued. This is the bug-guard for the
// audience-restriction path (D4) — splitting a string resource would forge
// bogus audiences.
func TestExtractResourceClaim(t *testing.T) {
	t.Run("string resource is atomic, not space-split", func(t *testing.T) {
		// A scope-style split would wrongly yield two entries here.
		got, ok := extractResourceClaim(map[string]any{"resource": "https://mcp.example.com/a b"})
		if !ok || len(got) != 1 || got[0] != "https://mcp.example.com/a b" {
			t.Fatalf("string resource must be a single atomic value, got %v (ok=%v)", got, ok)
		}
	})

	t.Run("array resource preserved", func(t *testing.T) {
		got, ok := extractResourceClaim(map[string]any{"resource": []any{"https://a", "https://b"}})
		if !ok || len(got) != 2 || got[0] != "https://a" || got[1] != "https://b" {
			t.Fatalf("array resource must be preserved, got %v (ok=%v)", got, ok)
		}
	})

	t.Run("absent resource returns false", func(t *testing.T) {
		if _, ok := extractResourceClaim(map[string]any{}); ok {
			t.Fatalf("expected ok=false when resource is absent")
		}
	})
}

// idJAGTestRegistry builds a single-issuer registry pointed at a fake JWKS,
// returning the registry plus the upstream signer so a test can mint a
// validly-signed ID-JAG.
func idJAGTestRegistry(t *testing.T, accountID string) (*ExternalIssuerRegistry, *fakeJWKSServer, string, string) {
	t.Helper()
	const kid = "idjag-kid-1"
	jwks := newFakeJWKSServer(t, kid)
	t.Cleanup(jwks.Close)

	const iss = "https://corp-idp.example.test"
	const aud = "https://zeroid.example.test"
	cfg := domain.ExternalIssuerConfig{
		Issuer:          iss,
		JWKSURI:         jwks.URL(),
		Audience:        aud,
		ClaimMapping:    map[string]string{"user_id": "sub", "email": "email"},
		AllowedAccounts: []string{accountID},
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate cfg: %v", err)
	}
	registry, err := NewExternalIssuerRegistry(
		context.Background(),
		[]domain.ExternalIssuerConfig{cfg},
		authjwt.WithHTTPClient(insecureHTTPClient(2*time.Second)),
	)
	if err != nil {
		t.Fatalf("NewExternalIssuerRegistry: %v", err)
	}
	t.Cleanup(registry.Close)
	return registry, jwks, iss, aud
}

// signIDJAG mints a validly-signed ID-JAG (typ oauth-id-jag+jwt) against the
// fake JWKS server's current key.
func signIDJAG(t *testing.T, jwks *fakeJWKSServer, claims map[string]any) string {
	t.Helper()
	return signWithTyp(t, jwks.curPriv, "idjag-kid-1", idJAGTyp, claims)
}

// requireOAuthError asserts the error carries an *OAuthError with the given code
// and HTTP status — the fail-closed contract for the ID-JAG path.
func requireOAuthError(t *testing.T, err error, wantCode string, wantStatus int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", wantCode)
	}
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError in chain, got %T: %v", err, err)
	}
	if oauthErr.Code != wantCode {
		t.Errorf("Code = %q, want %s; err=%v", oauthErr.Code, wantCode, err)
	}
	if oauthErr.HTTPStatus != wantStatus {
		t.Errorf("HTTPStatus = %d, want %d", oauthErr.HTTPStatus, wantStatus)
	}
}

// requireInvalidGrant asserts the error is invalid_grant / 400.
func requireInvalidGrant(t *testing.T, err error) {
	t.Helper()
	requireOAuthError(t, err, "invalid_grant", http.StatusBadRequest)
}

// requireInvalidClient asserts the error is invalid_client / 401 — the D2b
// confidential-client-auth fail-closed contract.
func requireInvalidClient(t *testing.T, err error) {
	t.Helper()
	requireOAuthError(t, err, "invalid_client", http.StatusUnauthorized)
}

// The following tests exercise idJAGBearer's fail-closed gates that fire BEFORE
// any token mint — so they need only a registry, no DB / CredentialService.
//
// Gate order (idJAGBearer): external-issuers configured → issuer lookup → D2b
// confidential client auth → derived tenant (ADR 0042 D5, deriveIDJAGTenant)
// → ID-JAG signature/claim validation → D2b client_id binding → identity
// mapping → resource (D4) → … → D2a single-use jti (consumed LAST). The
// UnknownIssuer gate fires BEFORE client auth, so it needs no client; the
// tenant derivation is pure and is covered row by row in
// oauth_id_jag_tenant_test.go. Everything from ID-JAG validation onward (bad signature,
// missing resource, unmappable identity, client_id binding, jti replay) is now
// gated behind D2b client auth, which requires a real oauth_clients row — so the
// fail-closed coverage for those gates lives in the integration suite
// (tests/integration/id_jag_test.go) where a full server with a real DB is
// available. The unit tests here pin the DB-free gates plus the D2b client-auth
// gate itself.

// TestIDJAGBearer_IssuerNotResolvedBeforeClientAuth pins the order: an
// unauthenticated redemption is invalid_client before ZeroID looks up the
// assertion's issuer, so an anonymous probe learns nothing about which IdPs
// are trusted and costs no lookup.
func TestIDJAGBearer_IssuerNotResolvedBeforeClientAuth(t *testing.T) {
	rows := &fakeIssuerRows{}
	svc := &OAuthService{externalIssuerRegistry: NewDBExternalIssuerRegistry(rows, true, nil)}
	defer svc.externalIssuerRegistry.Close()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	assertion := signWithTyp(t, priv, "kid", idJAGTyp, map[string]any{
		"iss": "https://probe.example.test", "sub": "alice", "aud": "x",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	_, err := svc.idJAGBearer(context.Background(), TokenRequest{Assertion: assertion})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_client" {
		t.Fatalf("err = %v, want invalid_client", err)
	}
	if rows.calls != 0 {
		t.Fatalf("issuer looked up %d times before client authentication", rows.calls)
	}
}

// TestIDJAGBearer_NoClientAuth_InvalidClient pins the D2b confidential-client
// gate: a redemption that presents NO client_id is rejected with invalid_client
// (401) BEFORE any ID-JAG validation or mint. Fail-closed proof that a leaked
// ID-JAG cannot be redeemed without authenticating a confidential client. This
// gate fires after the tenant binding and before ID-JAG signature validation, so
// it needs only a registry (no DB).
func TestIDJAGBearer_NoClientAuth_InvalidClient(t *testing.T) {
	const acct = "acct-idjag"
	registry, jwks, iss, aud := idJAGTestRegistry(t, acct)

	now := time.Now()
	idjag := signIDJAG(t, jwks, map[string]any{
		"iss":      iss,
		"sub":      "alice",
		"aud":      aud,
		"resource": "https://mcp.example.test",
		"iat":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
	})

	svc := &OAuthService{externalIssuerRegistry: registry}
	// No ClientID presented → invalid_client, before any signature/JWKS work.
	_, err := svc.idJAGBearer(context.Background(), TokenRequest{
		Assertion: idjag,
		AccountID: acct,
		ProjectID: "proj",
	})
	requireInvalidClient(t, err)
}

// TestIDJAGBearer_NoTenantFieldsRequired pins #630: a request carrying no
// account_id / project_id — the only shape a conformant client sends (draft
// §4.4, MCP EMA §5) — is no longer refused for omitting them. It proceeds to
// client authentication, which is the first gate it can fail here.
func TestIDJAGBearer_NoTenantFieldsRequired(t *testing.T) {
	const acct = "acct-idjag"
	registry, jwks, iss, aud := idJAGTestRegistry(t, acct)

	now := time.Now()
	idjag := signIDJAG(t, jwks, map[string]any{
		"iss":      iss,
		"sub":      "alice",
		"aud":      aud,
		"resource": "https://mcp.example.test",
		"iat":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
	})

	svc := &OAuthService{externalIssuerRegistry: registry}
	_, err := svc.idJAGBearer(context.Background(), TokenRequest{Assertion: idjag})
	var oe *OAuthError
	if errors.As(err, &oe) && oe.Code == "invalid_request" {
		t.Fatalf("a request without account_id/project_id must not be invalid_request: %v", err)
	}
	requireInvalidClient(t, err)
}

// NOTE: the deep-gate fail-closed unit tests that previously lived here —
// bad signature, missing resource (D4), and unmappable identity (D3) — exercised
// gates that now sit BEHIND the D2b confidential-client-auth gate. Driving them
// requires a real oauth_clients row (VerifyClientSecret), which the DB-free
// service unit harness cannot provide. Their fail-closed coverage moved to the
// integration suite (tests/integration/id_jag_test.go: "bad signature fails
// closed", "missing resource fails closed", plus the D2a replay / missing-jti
// and D2b bad-secret / client_id-mismatch cases), where a full server with a
// real DB authenticates the client first and then reaches each deeper gate.

// TestRequireCIMDClientFitForIDJAG pins the document-level gates a CIMD
// client must pass to redeem an ID-JAG (firehog#701).
func TestRequireCIMDClientFitForIDJAG(t *testing.T) {
	fit := func() *domain.OAuthClient {
		return &domain.OAuthClient{
			ClientID:                "https://client.example.test/client.json",
			RegistrationSource:      domain.RegistrationSourceCIMD,
			TokenEndpointAuthMethod: clientAuthMethodPrivateKeyJWT,
			GrantTypes:              []string{"authorization_code", grantTypeJWTBearerURN},
			IsActive:                true,
		}
	}

	if err := requireCIMDClientFitForIDJAG(fit()); err != nil {
		t.Fatalf("a private_key_jwt document listing jwt-bearer must pass: %v", err)
	}

	t.Run("auth method none is refused (draft §9.1, ADR 0010 D2b)", func(t *testing.T) {
		c := fit()
		c.TokenEndpointAuthMethod = "none"
		requireInvalidClient(t, requireCIMDClientFitForIDJAG(c))
	})

	// WSO2's MCP playground publishes exactly this grant list and redeems
	// ID-JAGs with it. The list is the publisher's own unauthenticated claim,
	// so leaving jwt-bearer out is not a reason to refuse.
	t.Run("a document that does not list jwt-bearer passes", func(t *testing.T) {
		c := fit()
		c.GrantTypes = []string{"authorization_code", "refresh_token"}
		if err := requireCIMDClientFitForIDJAG(c); err != nil {
			t.Fatalf("must pass: %v", err)
		}
	})

	t.Run("a document contradicting its ID-JAG profile claim is unauthorized_client (draft §8)", func(t *testing.T) {
		c := fit()
		c.IDJAGProfileContradicted = true
		requireOAuthError(t, requireCIMDClientFitForIDJAG(c), "unauthorized_client", http.StatusBadRequest)
	})
}
