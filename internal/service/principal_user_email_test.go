package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/highflame-ai/zeroid/domain"
)

func TestSanitizePrincipalAttribute(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"plain email", "ada@example.com", MaxPrincipalUserEmailLength, "ada@example.com"},
		{"non-ASCII name", "Zoë Ångström 李", MaxPrincipalUserNameLength, "Zoë Ångström 李"},
		{"empty", "", MaxPrincipalUserEmailLength, ""},
		{"at the limit", strings.Repeat("a", 254), MaxPrincipalUserEmailLength, strings.Repeat("a", 254)},
		{"over the limit", strings.Repeat("a", 255), MaxPrincipalUserEmailLength, ""},
		{"invalid UTF-8", "ada\xff@example.com", MaxPrincipalUserEmailLength, ""},
		{"newline", "ada@example.com\nX-Injected: 1", MaxPrincipalUserEmailLength, ""},
		{"escape sequence", "\x1b[31mada@example.com", MaxPrincipalUserEmailLength, ""},
		{"bidi override", "ada\u202e@example.com", MaxPrincipalUserEmailLength, ""},
		{"zero-width space", "ada\u200b@example.com", MaxPrincipalUserEmailLength, ""},
		{"NUL", "Ada\x00", MaxPrincipalUserNameLength, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sanitizePrincipalAttribute(tc.in, tc.max); got != tc.want {
				t.Fatalf("sanitizePrincipalAttribute(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The display attributes round-trip through the code, and are omitted from it
// entirely when empty (so codes minted without them are byte-for-byte the
// shape they were before).
func TestMintAuthCodeJWT_UserDisplayAttributes(t *testing.T) {
	t.Parallel()

	base := AuthCodeClaims{
		ClientID:      "test-cli",
		CodeChallenge: "challenge",
		RedirectURI:   "http://localhost:17580/callback",
		AccountID:     "acct-001",
		UserID:        "user-42",
	}

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		in := base
		in.UserEmail = "ada@example.com"
		in.UserName = "Ada Lovelace"

		code, err := mintAuthCodeJWT(&in, testMintHMAC, testMintIssuer, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		out, err := decodeAuthCodeJWT(code, testMintHMAC, testMintIssuer)
		if err != nil {
			t.Fatal(err)
		}
		if out.UserEmail != in.UserEmail || out.UserName != in.UserName {
			t.Fatalf("got (%q, %q), want (%q, %q)", out.UserEmail, out.UserName, in.UserEmail, in.UserName)
		}
	})

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		in := base

		code, err := mintAuthCodeJWT(&in, testMintHMAC, testMintIssuer, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jwt.ParseInsecure([]byte(code))
		if err != nil {
			t.Fatal(err)
		}
		if raw.Has("uem") || raw.Has("unm") {
			t.Fatal("empty display attributes must not be written as empty claims")
		}
	})

	// A code signed by a release that did not sanitize (or a forgery against
	// a leaked HMAC secret) must not get an unprintable value into the access
	// token: the decoder drops it rather than failing the exchange.
	t.Run("unprintable value in a signed code is dropped on decode", func(t *testing.T) {
		t.Parallel()
		in := base
		in.UserEmail = "ada\u202e@example.com"
		in.UserName = "Ada\x1b[2J"

		code, err := mintAuthCodeJWT(&in, testMintHMAC, testMintIssuer, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		out, err := decodeAuthCodeJWT(code, testMintHMAC, testMintIssuer)
		if err != nil {
			t.Fatalf("an unprintable display attribute must not fail the exchange: %v", err)
		}
		if out.UserEmail != "" || out.UserName != "" {
			t.Fatalf("got (%q, %q), want both dropped", out.UserEmail, out.UserName)
		}
	})
}

// IssueAuthCode carries the request's display attributes into the code, and
// drops (does not refuse over) one that fails the sanitizer.
func TestIssueAuthCode_UserDisplayAttributes(t *testing.T) {
	svc := &OAuthService{
		hmacSecret:     "test-hmac-secret-at-least-32-bytes-long",
		authCodeIssuer: "https://as.example.test",
	}
	client := &domain.OAuthClient{
		ClientID:     "cli-client",
		ClientType:   "public",
		IsActive:     true,
		GrantTypes:   []string{string(domain.GrantTypeAuthorizationCode)},
		RedirectURIs: []string{"http://127.0.0.1:3000/callback"},
	}
	base := IssueAuthCodeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "http://127.0.0.1:3000/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		AccountID:           "acct-1",
		UserID:              "user-1",
		Client:              client,
	}

	issue := func(t *testing.T, req IssueAuthCodeRequest) *AuthCodeClaims {
		t.Helper()
		code, err := svc.IssueAuthCode(context.Background(), req)
		if err != nil {
			t.Fatalf("IssueAuthCode: %v", err)
		}
		claims, err := decodeAuthCodeJWT(code, svc.hmacSecret, svc.authCodeIssuer)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		return claims
	}

	t.Run("carried", func(t *testing.T) {
		req := base
		req.UserEmail = "ada@example.com"
		req.UserName = "Ada Lovelace"

		claims := issue(t, req)
		if claims.UserEmail != "ada@example.com" || claims.UserName != "Ada Lovelace" {
			t.Fatalf("got (%q, %q)", claims.UserEmail, claims.UserName)
		}
	})

	t.Run("bad values dropped, code still issued", func(t *testing.T) {
		req := base
		req.UserEmail = strings.Repeat("a", MaxPrincipalUserEmailLength) + "@x"
		req.UserName = "Ada\u200f"

		claims := issue(t, req)
		if claims.UserEmail != "" || claims.UserName != "" {
			t.Fatalf("got (%q, %q), want both dropped", claims.UserEmail, claims.UserName)
		}
		if claims.UserID != "user-1" {
			t.Fatalf("UserID = %q", claims.UserID)
		}
	})
}
