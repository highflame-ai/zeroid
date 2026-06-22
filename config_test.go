package zeroid

import (
	"os"
	"path/filepath"
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

// writeTestKeys creates throwaway private/public key files so Validate()'s
// os.Stat checks pass. The contents don't matter — Validate only stats them.
func writeTestKeys(t *testing.T) (priv, pub string) {
	t.Helper()
	dir := t.TempDir()
	priv = filepath.Join(dir, "private.pem")
	pub = filepath.Join(dir, "public.pem")
	for _, p := range []string{priv, pub} {
		if err := os.WriteFile(p, []byte("test-key"), 0o600); err != nil {
			t.Fatalf("writing test key %s: %v", p, err)
		}
	}
	return priv, pub
}

// baseValidConfig returns a Config that passes Validate() in development.
// Tests mutate one field to exercise a single rejection branch.
func baseValidConfig(t *testing.T) Config {
	t.Helper()
	priv, pub := writeTestKeys(t)
	return Config{
		Server: ServerConfig{Port: "8899", Env: "development"},
		Database: DatabaseConfig{
			URL:          "postgres://u@localhost:5432/db",
			MaxOpenConns: 25,
			MaxIdleConns: 5,
		},
		Keys:        KeysConfig{PrivateKeyPath: priv, PublicKeyPath: pub},
		Token:       TokenConfig{Issuer: "https://auth.example.com"},
		WIMSEDomain: "example.com",
		Attestation: AttestationConfig{AllowUnsafeDevStub: true},
	}
}

// TestLoadEnvVarsBadTypedValues pins finding #1: a typo'd typed env var must
// fail loudly at startup, not silently retain the default. Before the fix the
// parse error was swallowed and ZEROID_ALLOW_UNSAFE_DEV_STUB=flase left the
// accept-any attestation stub ON.
func TestLoadEnvVarsBadTypedValues(t *testing.T) {
	cases := []struct {
		name    string
		envVar  string
		value   string
		wantErr string
	}{
		{"bad_bool_dev_stub", "ZEROID_ALLOW_UNSAFE_DEV_STUB", "flase", "not a valid bool"},
		{"bad_bool_trust_fwd", "ZEROID_TRUST_FORWARDED_HEADERS", "yepp", "not a valid bool"},
		{"bad_bool_backchannel", "ZEROID_BACKCHANNEL_ALLOW_PRIVATE_ENDPOINTS", "maybe", "not a valid bool"},
		{"bad_bool_private_issuer", "ZEROID_ATTESTATION_ALLOW_PRIVATE_ISSUER_ENDPOINTS", "nah", "not a valid bool"},
		{"bad_bool_unauth_inspect", "ZEROID_ALLOW_UNAUTHENTICATED_TOKEN_INSPECTION", "nope", "not a valid bool"},
		{"bad_int_ttl", "ZEROID_TOKEN_TTL_SECONDS", "soon", "not a valid integer"},
		{"bad_float_sampling", "OTEL_TRACES_SAMPLER_ARG", "lots", "not a valid float"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envVar, tc.value)
			_, err := LoadConfig("")
			if err == nil {
				t.Fatalf("expected LoadConfig to fail on %s=%q, got nil", tc.envVar, tc.value)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q must mention %q so operators can act on it", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestLoadEnvVarsGoodTypedValues confirms the corrected parser still accepts
// valid values and that the new env mappings actually reach the struct.
func TestLoadEnvVarsGoodTypedValues(t *testing.T) {
	t.Setenv("ZEROID_TRUST_FORWARDED_HEADERS", "true")
	t.Setenv("ZEROID_BACKCHANNEL_ALLOW_PRIVATE_ENDPOINTS", "true")
	t.Setenv("ZEROID_ATTESTATION_ALLOW_PRIVATE_ISSUER_ENDPOINTS", "true")
	t.Setenv("ZEROID_HMAC_SECRET", "this-is-a-sufficiently-long-secret-key")
	t.Setenv("ZEROID_ALLOW_UNSAFE_DEV_STUB", "false")
	t.Setenv("ZEROID_ALLOW_UNAUTHENTICATED_TOKEN_INSPECTION", "false")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig with valid env vars failed: %v", err)
	}
	if cfg.Token.AllowUnauthenticatedTokenInspection {
		t.Error("ZEROID_ALLOW_UNAUTHENTICATED_TOKEN_INSPECTION=false did not reach token config")
	}
	if !cfg.Server.TrustForwardedHeaders {
		t.Error("ZEROID_TRUST_FORWARDED_HEADERS=true did not reach server.trust_forwarded_headers")
	}
	if !cfg.Backchannel.AllowPrivateNotificationEndpoints {
		t.Error("ZEROID_BACKCHANNEL_ALLOW_PRIVATE_ENDPOINTS=true did not reach backchannel")
	}
	if !cfg.Attestation.AllowPrivateIssuerEndpoints {
		t.Error("ZEROID_ATTESTATION_ALLOW_PRIVATE_ISSUER_ENDPOINTS=true did not reach attestation")
	}
	if cfg.Token.HMACSecret != "this-is-a-sufficiently-long-secret-key" {
		t.Errorf("ZEROID_HMAC_SECRET did not reach token.hmac_secret, got %q", cfg.Token.HMACSecret)
	}
	if cfg.Attestation.AllowUnsafeDevStub {
		t.Error("ZEROID_ALLOW_UNSAFE_DEV_STUB=false did not turn off the dev stub")
	}
}

// TestRejectRemovedTelemetryKeys pins finding #6: stale telemetry.endpoint /
// telemetry.insecure keys must fail loudly rather than be silently dropped.
func TestRejectRemovedTelemetryKeys(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"endpoint", "telemetry:\n  endpoint: \"localhost:4317\"\n", "telemetry.endpoint has been removed"},
		{"insecure", "telemetry:\n  insecure: true\n", "telemetry.insecure has been removed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "zeroid.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("writing test yaml: %v", err)
			}
			_, err := LoadConfig(path)
			if err == nil {
				t.Fatalf("expected LoadConfig to reject %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q must mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestValidateProductionGate pins findings #2 and #3: the production gate on
// server.env rejects the unsafe dev stub and the unchanged default
// issuer / wimse_domain, while dev leaves all three alone.
func TestValidateProductionGate(t *testing.T) {
	t.Run("dev_allows_stub", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Server.Env = "development"
		cfg.Attestation.AllowUnsafeDevStub = true
		if err := cfg.Validate(); err != nil {
			t.Fatalf("dev config must pass with stub on: %v", err)
		}
	})

	t.Run("production_rejects_unsafe_stub", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Server.Env = "production"
		cfg.Attestation.AllowUnsafeDevStub = true
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "allow_unsafe_dev_stub must be false in production") {
			t.Fatalf("production + unsafe stub must be rejected, got: %v", err)
		}
	})

	t.Run("production_case_insensitive", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Server.Env = "Production"
		cfg.Attestation.AllowUnsafeDevStub = true
		if err := cfg.Validate(); err == nil {
			t.Fatal("\"Production\" must still trip the production gate")
		}
	})

	t.Run("production_passes_with_valid_config", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Server.Env = "production"
		cfg.Attestation.AllowUnsafeDevStub = false
		if err := cfg.Validate(); err != nil {
			t.Fatalf("production with valid config must pass: %v", err)
		}
	})

	t.Run("production_rejects_unauthenticated_inspection", func(t *testing.T) {
		// RFC 7662 §2.1 / RFC 7009 §2.1: production must not serve an
		// unauthenticated introspection/revocation surface.
		cfg := baseValidConfig(t)
		cfg.Server.Env = "production"
		cfg.Attestation.AllowUnsafeDevStub = false
		cfg.Token.Issuer = "https://auth.acme.example"
		cfg.WIMSEDomain = "acme.example"
		cfg.Token.AllowUnauthenticatedTokenInspection = true
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "allow_unauthenticated_token_inspection must be false in production") {
			t.Fatalf("production + unauthenticated token inspection must be rejected, got: %v", err)
		}
	})

	t.Run("dev_allows_unauthenticated_inspection", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Server.Env = "development"
		cfg.Token.AllowUnauthenticatedTokenInspection = true
		if err := cfg.Validate(); err != nil {
			t.Fatalf("dev must allow unauthenticated token inspection: %v", err)
		}
	})
}

// TestValidateHMACSecret pins finding #4: hmac_secret is optional, but when
// set must be at least 32 bytes.
func TestValidateHMACSecret(t *testing.T) {
	t.Run("empty_ok", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Token.HMACSecret = ""
		if err := cfg.Validate(); err != nil {
			t.Fatalf("empty hmac_secret must be allowed: %v", err)
		}
	})
	t.Run("short_rejected", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Token.HMACSecret = "too-short"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "hmac_secret must be at least 32 bytes") {
			t.Fatalf("short hmac_secret must be rejected, got: %v", err)
		}
	})
	t.Run("long_enough_ok", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Token.HMACSecret = strings.Repeat("a", 32)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("32-byte hmac_secret must be allowed: %v", err)
		}
	})
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
