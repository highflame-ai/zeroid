package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// wantOAuthError asserts the error is an *OAuthError carrying the given code.
func wantOAuthError(t *testing.T, err error, code string) *OAuthError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil error", code)
	}
	var oe *OAuthError
	if !errors.As(err, &oe) {
		t.Fatalf("expected *OAuthError(%s), got %T: %v", code, err, err)
	}
	if oe.Code != code {
		t.Fatalf("expected code %s, got %s (%s)", code, oe.Code, oe.Description)
	}
	return oe
}

func TestValidateResourceIndicators(t *testing.T) {
	t.Run("absent parameter is not an error", func(t *testing.T) {
		got, err := validateResourceIndicators(nil)
		if err != nil || got != nil {
			t.Fatalf("want (nil, nil), got (%v, %v)", got, err)
		}
	})

	t.Run("accepts an absolute https URI", func(t *testing.T) {
		got, err := validateResourceIndicators([]string{"https://gw.example.com/mcp/github"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != "https://gw.example.com/mcp/github" {
			t.Fatalf("value was not preserved verbatim: %#v", got)
		}
	})

	t.Run("accepts a query component", func(t *testing.T) {
		// RFC 8707 §2 permits a query; only the fragment is forbidden.
		if _, err := validateResourceIndicators([]string{"https://gw.example.com/mcp?tenant=acme"}); err != nil {
			t.Fatalf("query component rejected: %v", err)
		}
	})

	t.Run("accepts a non-http scheme", func(t *testing.T) {
		// The spec says "absolute URI", not "http(s) URL". A resource server
		// identified by urn: or a custom scheme is legitimate.
		if _, err := validateResourceIndicators([]string{"urn:example:mcp:github"}); err != nil {
			t.Fatalf("urn rejected: %v", err)
		}
	})

	t.Run("de-duplicates rather than rejecting", func(t *testing.T) {
		got, err := validateResourceIndicators([]string{
			"https://a.example/mcp", "https://a.example/mcp", "https://b.example/mcp",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("duplicates not collapsed: %#v", got)
		}
	})

	t.Run("preserves order of first appearance", func(t *testing.T) {
		got, _ := validateResourceIndicators([]string{"https://b.example", "https://a.example", "https://b.example"})
		if got[0] != "https://b.example" || got[1] != "https://a.example" {
			t.Fatalf("order not preserved: %#v", got)
		}
	})

	t.Run("does not normalize", func(t *testing.T) {
		// Two values that a normalizing implementation would collapse must stay
		// distinct: the client's identifier has to match what the resource
		// server advertises, byte for byte.
		got, err := validateResourceIndicators([]string{
			"https://GW.example.com/mcp", "https://gw.example.com/mcp",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("host case was normalized away: %#v", got)
		}
	})

	rejects := []struct {
		name  string
		value string
		want  string
	}{
		{"relative reference", "/mcp/github", "absolute"},
		{"scheme-relative", "//gw.example.com/mcp", "absolute"},
		{"bare host", "gw.example.com/mcp", "absolute"},
		{"empty string", "", "empty"},
		{"whitespace only", "   ", "empty"},
		{"non-empty fragment", "https://gw.example.com/mcp#frag", "fragment"},
		{"bare trailing fragment marker", "https://gw.example.com/mcp#", "fragment"},
		{"https with no host", "https://", "host"},
	}
	for _, tc := range rejects {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			_, err := validateResourceIndicators([]string{tc.value})
			oe := wantOAuthError(t, err, oautherror.InvalidTarget)
			if !strings.Contains(oe.Description, tc.want) {
				t.Fatalf("description %q does not explain the failure (want mention of %q)",
					oe.Description, tc.want)
			}
		})
	}

	t.Run("rejects more than the cap", func(t *testing.T) {
		many := make([]string, 0, maxResourceIndicators+1)
		for i := 0; i <= maxResourceIndicators; i++ {
			many = append(many, "https://gw.example.com/mcp/"+string(rune('a'+i)))
		}
		_, err := validateResourceIndicators(many)
		wantOAuthError(t, err, oautherror.InvalidTarget)
	})

	t.Run("cap counts values before de-duplication", func(t *testing.T) {
		// A caller cannot smuggle past the cap with repeats; the guard runs on
		// the raw list. Documents the choice rather than leaving it incidental.
		many := make([]string, maxResourceIndicators+1)
		for i := range many {
			many[i] = "https://gw.example.com/mcp/same"
		}
		if _, err := validateResourceIndicators(many); err == nil {
			t.Fatal("repeats of one value slipped past the cap")
		}
	})

	t.Run("one bad value rejects the whole request", func(t *testing.T) {
		// Fail closed: never mint bound to the good subset while dropping the
		// bad one, which would silently narrow differently than asked.
		_, err := validateResourceIndicators([]string{"https://good.example/mcp", "not-a-uri"})
		wantOAuthError(t, err, oautherror.InvalidTarget)
	})
}

func TestCheckResourceAudienceExclusive(t *testing.T) {
	t.Run("audience alone is fine", func(t *testing.T) {
		if err := checkResourceAudienceExclusive(TokenRequest{Audience: "codeoid"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("resource alone is fine", func(t *testing.T) {
		if err := checkResourceAudienceExclusive(TokenRequest{Resource: []string{"https://a.example"}}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("neither is fine", func(t *testing.T) {
		if err := checkResourceAudienceExclusive(TokenRequest{}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("both is invalid_request", func(t *testing.T) {
		err := checkResourceAudienceExclusive(TokenRequest{
			Audience: "codeoid",
			Resource: []string{"https://a.example"},
		})
		oe := wantOAuthError(t, err, oautherror.InvalidRequest)
		if !strings.Contains(oe.Description, "mutually exclusive") {
			t.Fatalf("description does not name the rule: %q", oe.Description)
		}
	})
}

func TestNarrowResourcesTo(t *testing.T) {
	authorized := []string{"https://gw.example/mcp/github", "https://gw.example/mcp/slack"}

	t.Run("no request keeps the full authorized set", func(t *testing.T) {
		got, err := narrowResourcesTo(authorized, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("authorized set was altered: %#v", got)
		}
	})

	t.Run("narrows to the requested subset", func(t *testing.T) {
		got, err := narrowResourcesTo(authorized, []string{"https://gw.example/mcp/slack"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != "https://gw.example/mcp/slack" {
			t.Fatalf("did not narrow to the request: %#v", got)
		}
	})

	t.Run("requesting everything is a no-op", func(t *testing.T) {
		got, err := narrowResourcesTo(authorized, authorized)
		if err != nil || len(got) != 2 {
			t.Fatalf("want the full set back, got (%#v, %v)", got, err)
		}
	})

	t.Run("cannot add a resource the grant did not authorize", func(t *testing.T) {
		_, err := narrowResourcesTo(authorized, []string{"https://gw.example/mcp/payroll"})
		wantOAuthError(t, err, oautherror.InvalidTarget)
	})

	t.Run("cannot smuggle an extra alongside a valid one", func(t *testing.T) {
		_, err := narrowResourcesTo(authorized, []string{
			"https://gw.example/mcp/github", "https://gw.example/mcp/payroll",
		})
		wantOAuthError(t, err, oautherror.InvalidTarget)
	})

	t.Run("match is exact, not prefix", func(t *testing.T) {
		// "github-admin" must not be satisfied by an authorization for "github".
		_, err := narrowResourcesTo(
			[]string{"https://gw.example/mcp/github"},
			[]string{"https://gw.example/mcp/github-admin"},
		)
		wantOAuthError(t, err, oautherror.InvalidTarget)
	})

	t.Run("match is exact, not origin", func(t *testing.T) {
		// Same origin, different server — an origin-level match would authorize
		// every MCP server behind one gateway.
		_, err := narrowResourcesTo(
			[]string{"https://gw.example/mcp/github"},
			[]string{"https://gw.example/mcp/slack"},
		)
		wantOAuthError(t, err, oautherror.InvalidTarget)
	})

	t.Run("empty authorized set authorizes nothing", func(t *testing.T) {
		_, err := narrowResourcesTo(nil, []string{"https://gw.example/mcp/github"})
		wantOAuthError(t, err, oautherror.InvalidTarget)
	})
}

func TestRejectUnsupportedResource(t *testing.T) {
	t.Run("no resource is a no-op", func(t *testing.T) {
		if err := rejectUnsupportedResource(TokenRequest{}, "client_credentials"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("resource on an unsupported grant is invalid_target", func(t *testing.T) {
		err := rejectUnsupportedResource(
			TokenRequest{Resource: []string{"https://a.example"}}, "client_credentials")
		oe := wantOAuthError(t, err, oautherror.InvalidTarget)
		if !strings.Contains(oe.Description, "client_credentials") {
			t.Fatalf("description does not name the grant: %q", oe.Description)
		}
	})
}

// TestRefreshTokenNeverSupportsResource pins the rule that a refresh can never
// take a NEW resource binding. It is a separate test from the table above
// because it is a durable security property, not a slice-by-slice rollout
// state: enabling it later would let a client re-target a token it already
// holds without a fresh authorization decision.
func TestRefreshTokenNeverSupportsResource(t *testing.T) {
	if grantSupportsResource("refresh_token") {
		t.Fatal("refresh_token must never accept a resource parameter")
	}
}
