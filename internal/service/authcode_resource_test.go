package service

import (
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// Tests for the `rsc` claim — the consented RFC 8707 resource ceiling carried on
// the authorization code (CAP-IDN-027).
//
// These exist because the ceiling's decode path is FAIL-CLOSED in a way `scp`'s
// is not, and the asymmetry is security-load-bearing rather than stylistic. An
// ABSENT ceiling means "none was recorded", which permits the token request to
// bind to any resource it names (CAP-IDN-026). So any shape that reads as an
// EMPTY ceiling silently widens what the code allows — the opposite of a skipped
// scope, which narrows. Everything below is a statement about which shapes are
// allowed to become "no ceiling".

// mintRawAuthCode signs an auth code with an arbitrary `rsc` value, so the
// decoder can be tested against shapes mintAuthCodeJWT would never produce.
// A forged or hand-crafted code needs the HMAC secret, so these are not
// attacker-reachable inputs — they are our own future bugs and other
// implementations' output.
func mintRawAuthCode(t *testing.T, rsc any) string {
	t.Helper()
	now := time.Now()
	b := jwt.NewBuilder().
		Issuer(testMintIssuer).
		Subject(AuthCodeSubject).
		JwtID("jti-rsc-test").
		IssuedAt(now).
		Expiration(now.Add(5*time.Minute)).
		Claim("cid", "test-cli").
		Claim("cc", strings.Repeat("a", 43)).
		Claim("ruri", "http://localhost:17580/callback").
		Claim("aid", "acct-001")
	if rsc != nil {
		b = b.Claim("rsc", rsc)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), []byte(testMintHMAC)))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

func TestAuthCodeResourceCeiling_DecodeShapes(t *testing.T) {
	t.Parallel()

	const (
		github = "https://gw.example.com/mcp/github"
		slack  = "https://gw.example.com/mcp/slack"
	)

	t.Run("array of strings is the shape we mint", func(t *testing.T) {
		claims, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, []any{github}), testMintHMAC, testMintIssuer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(claims.Resources) != 1 || claims.Resources[0] != github {
			t.Fatalf("ceiling not decoded: %#v", claims.Resources)
		}
	})

	t.Run("multi-valued array round-trips", func(t *testing.T) {
		// The authorize LEG caps the ceiling at one value, but the claim itself
		// must carry more than one — cardinality is a constant, not a shape
		// (ADR 0037 D2). If this ever fails, raising the cap has become a
		// wire-format change.
		claims, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, []any{github, slack}), testMintHMAC, testMintIssuer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(claims.Resources) != 2 {
			t.Fatalf("multi-valued ceiling did not survive decode: %#v", claims.Resources)
		}
	})

	t.Run("bare string is accepted as a single-value ceiling", func(t *testing.T) {
		// Tolerated deliberately: unambiguous, what a JSON layer collapsing
		// one-element arrays produces, and strictly NARROWER than the absent
		// case — so accepting costs nothing and rejecting would fail a flow for
		// no security gain.
		claims, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, github), testMintHMAC, testMintIssuer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(claims.Resources) != 1 || claims.Resources[0] != github {
			t.Fatalf("bare-string ceiling not decoded: %#v", claims.Resources)
		}
	})

	t.Run("absent claim means no ceiling", func(t *testing.T) {
		claims, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, nil), testMintHMAC, testMintIssuer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims.Resources != nil {
			t.Fatalf("expected no ceiling, got %#v", claims.Resources)
		}
	})

	// ── The fail-closed half. Each of these would otherwise read as an empty
	// ceiling, which permits binding to anything.

	t.Run("array containing a non-string is rejected", func(t *testing.T) {
		_, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, []any{github, 42}), testMintHMAC, testMintIssuer)
		if err == nil {
			t.Fatal("a malformed rsc element must reject the code, not be skipped: " +
				"skipping narrows scopes but WIDENS a resource ceiling")
		}
		if !strings.Contains(err.Error(), "rsc") {
			t.Fatalf("error should name the claim, got: %v", err)
		}
	})

	t.Run("a JSON object is rejected", func(t *testing.T) {
		_, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, map[string]any{"resource": github}), testMintHMAC, testMintIssuer)
		if err == nil {
			t.Fatal("an object-shaped rsc must reject the code rather than read as no ceiling")
		}
	})

	t.Run("a number is rejected", func(t *testing.T) {
		_, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, 42), testMintHMAC, testMintIssuer)
		if err == nil {
			t.Fatal("a numeric rsc must reject the code rather than read as no ceiling")
		}
	})

	// The shapes below are PRESENT but name nothing. Each one has to be an
	// error rather than an empty ceiling, because an empty ceiling is
	// indistinguishable from "no ceiling was ever recorded" — which permits the
	// token request to bind to anything (CAP-IDN-026). Presence is therefore
	// tested with token.Has, not by whether a typed read succeeds.

	t.Run("empty array is rejected, not read as no ceiling", func(t *testing.T) {
		_, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, []any{}), testMintHMAC, testMintIssuer)
		if err == nil {
			t.Fatal("a present-but-empty rsc claim must fail: silently reading it as " +
				"\"no ceiling\" converts a corrupt consent record into an unconstrained one")
		}
	})

	t.Run("JSON null is rejected", func(t *testing.T) {
		// The shape that motivated switching to token.Has. `null` is present,
		// but decodes to nil through EVERY typed accessor including
		// jwt.Get[any] — so a "did any read succeed?" test treats it as absent.
		_, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, nil2()), testMintHMAC, testMintIssuer)
		if err == nil {
			t.Fatal("a null rsc claim must fail rather than read as no ceiling")
		}
	})

	t.Run("an empty-string resource is rejected", func(t *testing.T) {
		// validateResourceIndicators rejects "" at issuance; without
		// re-validating on decode, a ceiling of [""] would mint a token bound
		// to the empty string.
		for name, shape := range map[string]any{
			"bare empty string":         "",
			"array of one empty string": []any{""},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := decodeAuthCodeJWT(
					mintRawAuthCode(t, shape), testMintHMAC, testMintIssuer)
				if err == nil {
					t.Fatal("an empty resource identifier must fail on decode, not be bound")
				}
			})
		}
	})

	t.Run("a syntactically invalid resource is rejected on decode", func(t *testing.T) {
		// Re-validation on the way in. The ceiling was checked at issuance, but
		// that is a different process and possibly a different release, and
		// these values are about to be stamped into a signed token that Shield
		// enforces on.
		_, err := decodeAuthCodeJWT(
			mintRawAuthCode(t, []any{"/mcp/github"}), testMintHMAC, testMintIssuer)
		if err == nil {
			t.Fatal("a relative-reference ceiling must fail on decode (RFC 8707 §2)")
		}
	})
}

// nil2 returns a typed nil inside an interface, so the claim is SET to JSON
// null rather than omitted — mintRawAuthCode skips the claim on a plain nil.
func nil2() any {
	var v []string
	return v
}

// TestAuthCodeResourceCeiling_MintRoundTrip pins the mint/decode symmetry for
// the ceiling specifically, mirroring what
// TestMintAuthCodeJWT_RoundTripsThroughDecoder does for the rest of the claim
// set. A rename or shape change on either side breaks here first.
func TestAuthCodeResourceCeiling_MintRoundTrip(t *testing.T) {
	t.Parallel()

	const github = "https://gw.example.com/mcp/github"

	in := &AuthCodeClaims{
		ClientID:      "test-cli",
		CodeChallenge: strings.Repeat("a", 43),
		RedirectURI:   "http://localhost:17580/callback",
		AccountID:     "acct-001",
		Resources:     []string{github},
	}
	code, err := mintAuthCodeJWT(in, testMintHMAC, testMintIssuer, time.Now())
	if err != nil {
		t.Fatalf("mint failed: %v", err)
	}
	out, err := decodeAuthCodeJWT(code, testMintHMAC, testMintIssuer)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(out.Resources) != 1 || out.Resources[0] != github {
		t.Fatalf("ceiling did not round-trip: %#v", out.Resources)
	}

	t.Run("an empty ceiling emits no claim at all", func(t *testing.T) {
		in := &AuthCodeClaims{
			ClientID:      "test-cli",
			CodeChallenge: strings.Repeat("a", 43),
			RedirectURI:   "http://localhost:17580/callback",
			AccountID:     "acct-001",
		}
		code, err := mintAuthCodeJWT(in, testMintHMAC, testMintIssuer, time.Now())
		if err != nil {
			t.Fatalf("mint failed: %v", err)
		}
		parsed, err := jwt.Parse([]byte(code),
			jwt.WithKey(jwa.HS256(), []byte(testMintHMAC)), jwt.WithValidate(false))
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if _, err := jwt.Get[any](parsed, "rsc"); err == nil {
			t.Fatal("an unbound code must carry no rsc claim at all — an empty one is " +
				"an extra shape for the decoder to interpret")
		}
	})
}
