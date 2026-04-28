package zeroid

import (
	"strings"
	"testing"
)

// TestValidateWIMSEDomain pins the SPIFFE §2.2 / RFC 1123 rules. The error
// substring assertions exist because operators read these messages — if the
// wording drifts we want the test to flag it, not just the missing reject.
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
