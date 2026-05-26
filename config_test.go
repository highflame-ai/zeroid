package zeroid

import (
	"strings"
	"testing"
)

// TestValidateWIMSEDomain pins the SPIFFE §2.2 / RFC 1123 rules. The error
// substring assertions exist because operators read these messages — if the
// wording drifts we want the test to flag it, not just the missing reject.
// TestValidateIssuer pins RFC 8414 §2 shape constraints on Token.Issuer.
// The function is load-bearing: a malformed issuer produces silent client
// failures everywhere (discovery, JWT verification, endpoint URLs).
// Substring assertions match the test-style precedent from
// TestValidateWIMSEDomain — operators read these messages, so we pin the
// actionable substring rather than the exact text.
//
// Coverage: valid shapes (https + http for local dev, paths), and every
// rejection branch of validateIssuer (empty, trailing slash, parse failure,
// non-http(s) scheme, missing host, user-info, query, fragment).
// The user-info branch is the security-relevant case added in PR-167 —
// rejecting issuer URLs with embedded credentials prevents leaking them
// into the JWT iss claim and every published URI.
func TestValidateIssuer(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string // substring; "" means success
	}{
		// Valid shapes.
		{"https_bare_host", "https://auth.example.com", ""},
		{"https_with_path", "https://auth.example.com/v1/auth", ""},
		{"http_localhost_for_dev", "http://localhost:8899", ""},
		{"https_with_port", "https://auth.example.com:8443", ""},

		// Empty / trailing-slash.
		{"empty", "", "required"},
		{"trailing_slash", "https://auth.example.com/", "must not have a trailing slash"},
		{"trailing_slash_with_path", "https://auth.example.com/v1/", "must not have a trailing slash"},

		// Scheme.
		{"ftp_scheme", "ftp://auth.example.com", "must use http or https scheme"},
		{"missing_scheme", "auth.example.com", "must use http or https scheme"},
		{"schemeless_double_slash", "//auth.example.com", "must use http or https scheme"},

		// Host. "https://" would naturally trip the trailing-slash check
		// first, so use the opaque-URL shape that parses cleanly but
		// leaves Host empty.
		{"no_host_opaque", "https:foo", "must have a host"},

		// User-info (the security-relevant check added in PR-167).
		{"userinfo_with_password", "https://user:pass@auth.example.com", "must not contain user-info"},
		{"userinfo_user_only", "https://user@auth.example.com", "must not contain user-info"},

		// Query / fragment.
		{"with_query", "https://auth.example.com?foo=bar", "must not contain query parameters"},
		{"with_fragment", "https://auth.example.com#section", "must not contain a fragment"},

		// Parse-failure paths. url.Parse is permissive in Go — most "bad"
		// inputs parse cleanly as relative URLs and then fail downstream
		// checks (scheme, host). A control character in the URL is one of
		// the few inputs that produces a hard parse error.
		{"ctl_char_fails_parse", "https://auth.example.com\x00", "must be a valid URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIssuer(tc.input)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected ok, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q must mention %q so operators can act on it", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateWIMSEDomain(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string // substring; "" means success
	}{
		// Valid shapes.
		{"single_label", "highflame", ""},
		{"two_labels", "highflame.ai", ""},
		{"three_labels", "auth.highflame.ai", ""},
		{"with_digits", "auth1.example2.org", ""},
		{"with_internal_hyphen", "my-org.example.com", ""},

		// Issue's three explicit failure modes.
		{"empty", "", "required"},
		{"spiffe_prefix", "spiffe://highflame.ai", "drop the spiffe:// prefix"},
		{"uppercase", "Highflame.ai", "lowercase only"},

		// RFC 1123 edge cases.
		{"contains_space", "highflame ai", "lowercase only"},
		{"contains_underscore", "highflame_ai", "lowercase only"},
		{"contains_at", "user@highflame.ai", "lowercase only"},
		{"leading_dot", ".highflame.ai", "empty label"},
		{"trailing_dot", "highflame.ai.", "empty label"},
		{"double_dot", "highflame..ai", "empty label"},
		{"leading_hyphen", "-highflame.ai", "must not start or end with a hyphen"},
		{"trailing_hyphen", "highflame-.ai", "must not start or end with a hyphen"},
		{"label_too_long", strings.Repeat("a", 64) + ".ai", "exceeds 63 characters"},
		{"total_too_long", strings.Repeat("a.", 130) + "ai", "at most 253 characters"},
		// Non-ASCII rune — confirms the rune-aware loop reports the actual
		// character, not just its leading UTF-8 byte.
		{"non_ascii_rune", "café.example.com", `'é'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWIMSEDomain(tc.input)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected ok, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q must mention %q so operators can act on it", err.Error(), tc.wantErr)
			}
		})
	}
}
