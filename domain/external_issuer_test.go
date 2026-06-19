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
			Issuer:          "https://auth.example.okta.com",
			JWKSURI:         "https://auth.example.okta.com/.well-known/jwks.json",
			Audience:        "https://zeroid.example.com",
			ClaimMapping:    map[string]string{"user_id": "sub"},
			AllowedAccounts: []string{"acct-1"},
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
		{name: "missing allowed_accounts", mutate: func(c *ExternalIssuerConfig) { c.AllowedAccounts = nil }, wantErr: "allowed_accounts is required"},
		{name: "empty allowed_accounts entry", mutate: func(c *ExternalIssuerConfig) {
			c.AllowedAccounts = []string{""}
		}, wantErr: "must not contain empty entries"},
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
	if got, want := strings.Join(cfg.Algorithms, ","), "RS256,ES256,PS256"; got != want {
		t.Errorf("Algorithms default = %q, want %q", got, want)
	}
}

// TestExternalIssuerConfigValidateRejectsUnsupportedAlg locks in that the
// alg allow-list is enforced at config load (the doc promises it), and that
// a jwks_cache_ttl below the authjwt floor is rejected rather than silently
// clamped.
func TestExternalIssuerConfigValidateRejectsUnsupportedAlg(t *testing.T) {
	base := func() ExternalIssuerConfig {
		return ExternalIssuerConfig{
			Issuer:          "https://idp.example.com",
			JWKSURI:         "https://idp.example.com/jwks",
			Audience:        "https://zeroid.example.com",
			ClaimMapping:    map[string]string{"user_id": "sub"},
			AllowedAccounts: []string{"acct-1"},
		}
	}

	bad := base()
	bad.Algorithms = []string{"RS256", "HS256"}
	if err := bad.Validate(); err == nil {
		t.Errorf("Validate must reject unsupported algorithm HS256")
	}

	tooShort := base()
	tooShort.JWKSCacheTTL = 5 * time.Second
	if err := tooShort.Validate(); err == nil {
		t.Errorf("Validate must reject jwks_cache_ttl below the 30s floor")
	}

	ok := base()
	ok.Defaults()
	if err := ok.Validate(); err != nil {
		t.Errorf("default config must validate, got %v", err)
	}
}

func TestExternalIssuerConfigAccountAllowed(t *testing.T) {
	t.Run("empty allow-list denies all tenants (fail closed)", func(t *testing.T) {
		cfg := ExternalIssuerConfig{}
		if cfg.AccountAllowed("any-tenant") {
			t.Fatalf("empty AllowedAccounts must deny all tenants (fail closed)")
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
