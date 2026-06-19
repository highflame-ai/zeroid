package domain

import (
	"strings"
	"testing"
	"time"
)

// TestExternalIssuerConfigValidate locks in the bare-minimum requirements
// for a usable external IdP entry. Each negative case names the field whose
// absence should fail validation; if the rule changes, the test must fail.
func TestExternalIssuerConfigValidate(t *testing.T) {
	good := func() ExternalIssuerConfig {
		return ExternalIssuerConfig{
			Issuer:       "https://auth.example.okta.com",
			JWKSURI:      "https://auth.example.okta.com/.well-known/jwks.json",
			Audience:     "https://zeroid.example.com",
			ClaimMapping: map[string]string{"user_id": "sub"},
		}
	}

	cases := []struct {
		name    string
		mutate  func(*ExternalIssuerConfig)
		wantErr string
	}{
		{name: "happy path", mutate: nil, wantErr: ""},
		{name: "missing issuer", mutate: func(c *ExternalIssuerConfig) { c.Issuer = "" }, wantErr: "issuer is required"},
		{name: "non-https issuer", mutate: func(c *ExternalIssuerConfig) { c.Issuer = "http://insecure" }, wantErr: "absolute https URL"},
		{name: "missing jwks_uri", mutate: func(c *ExternalIssuerConfig) { c.JWKSURI = "" }, wantErr: "jwks_uri is required"},
		{name: "missing audience", mutate: func(c *ExternalIssuerConfig) { c.Audience = "" }, wantErr: "audience is required"},
		{name: "missing user_id mapping", mutate: func(c *ExternalIssuerConfig) { c.ClaimMapping = map[string]string{} }, wantErr: "claim_mapping.user_id is required"},
		{name: "unsupported propagate claim", mutate: func(c *ExternalIssuerConfig) {
			c.PropagateClaims = []string{"groups"}
		}, wantErr: "propagate_claims entry"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good()
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected ok, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

// TestExternalIssuerConfigDefaults checks that the optional knobs receive
// sensible defaults so deployers can lean on omission for the common case.
func TestExternalIssuerConfigDefaults(t *testing.T) {
	cfg := ExternalIssuerConfig{}
	cfg.Defaults()
	if got, want := cfg.MaxTokenAge, 10*time.Minute; got != want {
		t.Errorf("MaxTokenAge default = %s, want %s", got, want)
	}
	if got, want := cfg.JWKSCacheTTL, 5*time.Minute; got != want {
		t.Errorf("JWKSCacheTTL default = %s, want %s", got, want)
	}
	if len(cfg.Algorithms) != 2 {
		t.Errorf("Algorithms default len = %d, want 2 (RS256, ES256)", len(cfg.Algorithms))
	}
}

func TestExternalIssuerConfigAccountAllowed(t *testing.T) {
	t.Run("empty allow-list permits any tenant", func(t *testing.T) {
		cfg := ExternalIssuerConfig{}
		if !cfg.AccountAllowed("any-tenant") {
			t.Fatalf("empty AllowedAccounts must permit any tenant")
		}
	})
	t.Run("non-empty allow-list gates membership", func(t *testing.T) {
		cfg := ExternalIssuerConfig{AllowedAccounts: []string{"a", "b"}}
		if !cfg.AccountAllowed("a") {
			t.Fatalf("a should be allowed")
		}
		if cfg.AccountAllowed("c") {
			t.Fatalf("c should be denied")
		}
	})
}
