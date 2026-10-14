package zeroid

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
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

// The client_auth knobs must actually reach the config. They were documented in
// zeroid.yaml with `# Env:` lines before they existed in envMapping, so both
// resolved to their zero values however they were set — a security lever that
// failed silently in BOTH directions: an operator pinning it false in prod got
// no confirmation, and one setting it true in dev got a non-working localhost
// jwks_uri with no error.
//
// Note this needs the type-suffix entries as well as the envMapping rows.
// Without the bool suffix the value lands as the string "false", which is
// truthy-shaped and mis-unmarshals; asserting the resolved TYPED field is what
// makes that visible.
func TestLoadEnvVarsClientAuth(t *testing.T) {
	t.Setenv("ZEROID_CLIENT_AUTH_ALLOW_PRIVATE_JWKS_ENDPOINTS", "true")
	t.Setenv("ZEROID_CLIENT_AUTH_JWKS_CACHE_SIZE", "64")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if !cfg.ClientAuth.AllowPrivateJWKSEndpoints {
		t.Error("ZEROID_CLIENT_AUTH_ALLOW_PRIVATE_JWKS_ENDPOINTS=true did not reach client_auth")
	}
	if cfg.ClientAuth.JWKSCacheSize != 64 {
		t.Errorf("ZEROID_CLIENT_AUTH_JWKS_CACHE_SIZE=64 did not reach client_auth, got %d", cfg.ClientAuth.JWKSCacheSize)
	}
}

// Production-safe defaults: both zero values must survive a bare load.
func TestClientAuthDefaultsAreProductionSafe(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.ClientAuth.AllowPrivateJWKSEndpoints {
		t.Error("allow_private_jwks_endpoints must default to false — it governs an outbound fetch of attacker-supplied URLs")
	}
	if cfg.ClientAuth.JWKSCacheSize != 0 {
		t.Errorf("jwks_cache_size must default to 0 (meaning the built-in cap), got %d", cfg.ClientAuth.JWKSCacheSize)
	}
}

// CIBA approver settings: defaults keep standalone deployments unchanged, and
// both env vars reach the typed fields.
func TestBackchannelApproverConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := LoadConfig("")
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.Backchannel.RequireApproverIdentity {
			t.Error("backchannel.require_approver_identity must default to false")
		}
		if cfg.Backchannel.EnforceHints != "off" {
			t.Errorf("backchannel.enforce_hints must default to off, got %q", cfg.Backchannel.EnforceHints)
		}
		if cfg.Backchannel.ResolvedRetention != "720h" {
			t.Errorf("backchannel.resolved_retention must default to 720h, got %q", cfg.Backchannel.ResolvedRetention)
		}
	})

	t.Run("env", func(t *testing.T) {
		t.Setenv("ZEROID_BACKCHANNEL_REQUIRE_APPROVER_IDENTITY", "true")
		t.Setenv("ZEROID_BACKCHANNEL_ENFORCE_HINTS", "shadow")
		t.Setenv("ZEROID_BACKCHANNEL_RESOLVED_RETENTION", "48h")
		cfg, err := LoadConfig("")
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if !cfg.Backchannel.RequireApproverIdentity {
			t.Error("ZEROID_BACKCHANNEL_REQUIRE_APPROVER_IDENTITY=true did not reach backchannel")
		}
		if cfg.Backchannel.ResolvedRetention != "48h" {
			t.Errorf("ZEROID_BACKCHANNEL_RESOLVED_RETENTION=48h did not reach backchannel, got %q", cfg.Backchannel.ResolvedRetention)
		}
		if cfg.Backchannel.EnforceHints != "shadow" {
			t.Errorf("ZEROID_BACKCHANNEL_ENFORCE_HINTS=shadow did not reach backchannel, got %q", cfg.Backchannel.EnforceHints)
		}
	})

	t.Run("bad_bool", func(t *testing.T) {
		t.Setenv("ZEROID_BACKCHANNEL_REQUIRE_APPROVER_IDENTITY", "maybe")
		if _, err := LoadConfig(""); err == nil || !strings.Contains(err.Error(), "not a valid bool") {
			t.Fatalf("expected a bool parse error, got %v", err)
		}
	})

	t.Run("validate_resolved_retention", func(t *testing.T) {
		for _, v := range []string{"", "0s", "720h"} {
			cfg := baseValidConfig(t)
			cfg.Backchannel.ResolvedRetention = v
			if err := cfg.Validate(); err != nil {
				t.Errorf("resolved_retention=%q must validate, got %v", v, err)
			}
		}
		for _, v := range []string{"30d", "-1h"} {
			cfg := baseValidConfig(t)
			cfg.Backchannel.ResolvedRetention = v
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "backchannel.resolved_retention") {
				t.Errorf("resolved_retention=%q must be rejected naming the key, got %v", v, err)
			}
		}
	})

	t.Run("validate_enforce_hints", func(t *testing.T) {
		for _, mode := range []string{"", "off", "shadow", "on"} {
			cfg := baseValidConfig(t)
			cfg.Backchannel.EnforceHints = mode
			cfg.Backchannel.RequireApproverIdentity = true
			if err := cfg.Validate(); err != nil {
				t.Errorf("enforce_hints=%q must validate, got %v", mode, err)
			}
		}
		for _, mode := range []string{"", "off"} {
			cfg := baseValidConfig(t)
			cfg.Backchannel.EnforceHints = mode
			if err := cfg.Validate(); err != nil {
				t.Errorf("enforce_hints=%q without require_approver_identity must validate, got %v", mode, err)
			}
		}
		cfg := baseValidConfig(t)
		cfg.Backchannel.EnforceHints = "strict"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "backchannel.enforce_hints") {
			t.Fatalf("enforce_hints=strict must be rejected naming the key, got %v", err)
		}
	})

	t.Run("validate_enforce_hints_requires_approver_identity", func(t *testing.T) {
		for _, mode := range []string{"shadow", "on"} {
			cfg := baseValidConfig(t)
			cfg.Backchannel.EnforceHints = mode
			cfg.Backchannel.RequireApproverIdentity = false
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "backchannel.enforce_hints") ||
				!strings.Contains(err.Error(), "backchannel.require_approver_identity") {
				t.Errorf("enforce_hints=%q without require_approver_identity must be rejected naming both keys, got %v", mode, err)
			}
		}
	})
}

// Ratchet: every `# Env: ZEROID_*` line in the shipped sample config must name a
// variable the loader actually reads.
//
// zeroid.yaml is the discovery surface operators work from, and there is no
// generic ZEROID_ prefix loader behind it — envMapping is an explicit table, so
// documenting a variable and wiring it are separate acts that silently drift.
// That is exactly how the two client_auth knobs shipped documented-but-dead.
func TestSampleConfigEnvVarsAreAllWired(t *testing.T) {
	raw, err := os.ReadFile("zeroid.yaml")
	if err != nil {
		t.Skipf("zeroid.yaml not readable: %v", err)
	}
	envRef := regexp.MustCompile(`ZEROID_[A-Z0-9_]+`)
	documented := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "# Env:") {
			continue
		}
		for _, name := range envRef.FindAllString(line, -1) {
			documented[name] = true
		}
	}
	if len(documented) == 0 {
		t.Fatal("found no `# Env:` lines in zeroid.yaml — the ratchet is not actually checking anything")
	}

	for name := range documented {
		if _, ok := envMapping[name]; !ok {
			t.Errorf("zeroid.yaml documents %s but envMapping never reads it — it is dead config", name)
		}
	}
}

// TestValidateRegistrationEndpoint pins token.registration_endpoint's shape
// rules. The value is published verbatim as registration_endpoint in AS
// metadata, so anything a client could not safely register against is refused
// at load rather than advertised.
func TestValidateRegistrationEndpoint(t *testing.T) {
	const (
		httpsIssuer = "https://auth.example.com"
		httpIssuer  = "http://highflame-authn:8051"
	)
	cases := []struct {
		name    string
		input   string
		issuer  string // "" means httpsIssuer
		wantErr string // substring; "" means success
	}{
		{"empty_keeps_default", "", "", ""},
		{"https", "https://register.example.com/oauth/register", "", ""},
		{"https_with_port_and_query", "https://register.example.com:8443/r?tenant=a", "", ""},
		{"https_port_max", "https://register.example.com:65535/r", "", ""},
		{"https_idn_in_xn_form", "https://xn--bcher-kva.example/r", "", ""},
		{"http_localhost", "http://localhost:3000/register", "", ""},
		{"http_loopback_v4", "http://127.0.0.1:3000/register", "", ""},
		{"http_loopback_v6", "http://[::1]:3000/register", "", ""},
		{"http_beside_http_issuer", "http://highflame-studio:3000/oauth/register", httpIssuer, ""},
		{"https_beside_http_issuer", "https://register.example.com/r", httpIssuer, ""},

		{"http_non_loopback", "http://register.example.com/register", "", "http is accepted only for a loopback host or when token.issuer is itself http"},
		{"http_non_loopback_https_issuer_cluster_name", "http://highflame-studio:3000/oauth/register", "", "must use https"},
		{"http_name_resolving_loopback_is_not_trusted", "http://localhost.example.com/register", "", "http is accepted only for a loopback host"},
		{"relative", "/oauth2/register", "", "absolute URL with a host"},
		{"no_scheme", "register.example.com/register", "", "absolute URL with a host"},
		{"other_scheme", "ftp://register.example.com/register", "", "must use https"},
		{"other_scheme_http_issuer", "ftp://register.example.com/register", httpIssuer, "must use https"},
		{"javascript_scheme", "javascript://register.example.com/x", "", "must use https"},
		{"userinfo", "https://user:pass@register.example.com/register", "", "must not contain user-info"},
		{"fragment", "https://register.example.com/register#x", "", "must not contain a fragment"},
		{"empty_fragment", "https://register.example.com/register#", "", "must not contain a fragment"},
		{"unparseable", "https://register.example.com/%zz", "", "must be a valid URL"},

		{"leading_space", " https://register.example.com/r", "", "whitespace or control characters"},
		{"trailing_space", "https://register.example.com/r ", "", "whitespace or control characters"},
		{"trailing_newline", "https://register.example.com/r\n", "", "whitespace or control characters"},
		{"inner_space", "https://register.example.com/a b", "", "whitespace or control characters"},
		{"tab", "https://register.example.com/\tr", "", "whitespace or control characters"},
		{"nul", "https://register.example.com/r\x00", "", "whitespace or control characters"},
		{"unicode_space", "https://register.example.com/r\u00a0", "", "whitespace or control characters"},

		{"unicode_host", "https://bücher.example/r", "", "host must be ASCII"},
		{"percent_encoded_unicode_host", "https://b%C3%BCcher.example/r", "", "host must be ASCII"},

		{"port_zero", "https://register.example.com:0/r", "", "port must be a number from 1 to 65535"},
		{"port_too_large", "https://register.example.com:65536/r", "", "port must be a number from 1 to 65535"},
		{"port_empty", "https://register.example.com:/r", "", "port must be a number from 1 to 65535"},
		{"port_non_numeric", "https://register.example.com:abc/r", "", "must be a valid URL"},

		{"uppercase_scheme", "HTTPS://register.example.com/r", "", "canonical form"},
		{"uppercase_host", "https://Register.Example.com/r", "", "canonical form"},
		{"non_ascii_path", "https://register.example.com/régister", "", "canonical form"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := tc.issuer
			if issuer == "" {
				issuer = httpsIssuer
			}
			err := validateRegistrationEndpoint(tc.input, issuer)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRegistrationEndpoint(%q, %q) unexpected error: %v", tc.input, issuer, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateRegistrationEndpoint(%q, %q) = %v, want error containing %q", tc.input, issuer, err, tc.wantErr)
			}
		})
	}
}

// TestValidateRegistrationEndpoint_CanonicalFormInError pins that a
// non-canonical value is rejected (not rewritten) and the error names the form
// to use instead.
func TestValidateRegistrationEndpoint_CanonicalFormInError(t *testing.T) {
	err := validateRegistrationEndpoint("HTTPS://Register.Example.com/r", "https://auth.example.com")
	if err == nil || !strings.Contains(err.Error(), `want "https://register.example.com/r"`) {
		t.Fatalf("got %v, want the canonical form in the error", err)
	}
}

// TestURLValidatorsDoNotEchoCredentials pins that neither the issuer nor the
// registration_endpoint validator quotes user-info back in its error — on any
// rejection path, including values that fail to parse at all, where the
// standard library's own error would repeat the whole URL.
func TestURLValidatorsDoNotEchoCredentials(t *testing.T) {
	const secret = "hunter2-s3cret"
	inputs := []string{
		"https://admin:" + secret + "@register.example.com/r",      // user-info rejection
		"https://admin:" + secret + "@register.example.com:abc/r",  // parse failure (bad port)
		"https://admin:" + secret + "@register.example.com/%zz",    // parse failure (bad escape)
		"http://admin:" + secret + "@register.example.com/r",       // scheme rejection path
		"ftp://admin:" + secret + "@register.example.com/r",        // other scheme
		" https://admin:" + secret + "@register.example.com/r",     // whitespace
		"https://admin:" + secret + "@register.example.com/r#frag", // fragment
		"https://admin:" + secret + "@register.example.com:0/r",    // port
		"https://admin:" + secret + "@register.example.com/",       // issuer trailing slash
		"https://admin:" + secret + "@register.example.com/r?x=1",  // issuer query
		"https://admin:" + secret + "@register.example.com/r#f",    // issuer fragment
		"https://admin:" + secret + "@bücher.example/r",            // non-ASCII host
	}
	for _, in := range inputs {
		for name, err := range map[string]error{
			"registration_endpoint": validateRegistrationEndpoint(in, "https://auth.example.com"),
			"issuer":                validateIssuer(in),
		} {
			if err == nil {
				t.Errorf("%s: %q unexpectedly accepted", name, in)
				continue
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: error for %q leaks the password: %v", name, in, err)
			}
		}
	}
}

func TestRedactUserinfo(t *testing.T) {
	cases := map[string]string{
		"https://u:p@host/x":         "https://redacted@host/x",
		"https://u@host":             "https://redacted@host",
		"https://u:p@w@host:1/x?y#z": "https://redacted@host:1/x?y#z",
		"https://host/path@x":        "https://host/path@x",
		"https://host?q=a@b":         "https://host?q=a@b",
		"no-scheme@host":             "no-scheme@host",
		"":                           "",
	}
	for in, want := range cases {
		if got := redactUserinfo(in); got != want {
			t.Errorf("redactUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

// The env var reaches the typed field, and Validate() runs the check so an
// invalid value fails config load instead of being advertised.
func TestRegistrationEndpointConfig(t *testing.T) {
	t.Run("env_var_wired", func(t *testing.T) {
		t.Setenv("ZEROID_REGISTRATION_ENDPOINT", "https://register.example.com/register")
		cfg, err := LoadConfig("")
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.Token.RegistrationEndpoint != "https://register.example.com/register" {
			t.Errorf("ZEROID_REGISTRATION_ENDPOINT did not reach token.registration_endpoint, got %q", cfg.Token.RegistrationEndpoint)
		}
	})

	t.Run("default_empty", func(t *testing.T) {
		cfg, err := LoadConfig("")
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.Token.RegistrationEndpoint != "" {
			t.Errorf("token.registration_endpoint must default to empty (advertise ZeroID's own), got %q", cfg.Token.RegistrationEndpoint)
		}
	})

	t.Run("validate_rejects_invalid", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Token.RegistrationEndpoint = "http://register.example.com/register"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "token.registration_endpoint") {
			t.Fatalf("Validate must reject a non-loopback http registration endpoint, got: %v", err)
		}
	})

	t.Run("validate_accepts_valid", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Token.RegistrationEndpoint = "https://register.example.com/register"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate must accept an https registration endpoint: %v", err)
		}
	})

	// Validate threads token.issuer into the check: the same http value is
	// accepted beside an http issuer and refused beside an https one.
	t.Run("validate_uses_issuer_scheme", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Token.Issuer = "http://highflame-authn:8051"
		cfg.Token.RegistrationEndpoint = "http://highflame-studio:3000/oauth/register"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate must accept an http registration endpoint beside an http issuer: %v", err)
		}
		cfg.Token.Issuer = "https://highflame-authn:8051"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "token.registration_endpoint") {
			t.Fatalf("Validate must refuse an http registration endpoint beside an https issuer, got: %v", err)
		}
	})
}

// TestRefreshReuseGraceConfig pins token.refresh_reuse_grace_seconds: unset
// keeps the default (so a Config built in code, as embedders do, does not
// silently go strict), 0 disables the grace, and Validate refuses negative or
// over-long windows. The env var reaches the field.
func TestRefreshReuseGraceConfig(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	t.Run("unset is the default", func(t *testing.T) {
		cfg := baseValidConfig(t)
		cfg.Token.RefreshReuseGraceSeconds = nil
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unset grace must validate: %v", err)
		}
		if got := cfg.Token.RefreshReuseGrace(); got != domain.RefreshTokenReuseGraceWindow {
			t.Fatalf("unset grace = %v, want the default %v", got, domain.RefreshTokenReuseGraceWindow)
		}
	})
	for _, ok := range []int{0, 1, domain.MaxRefreshTokenReuseGraceSeconds} {
		t.Run(fmt.Sprintf("%d accepted", ok), func(t *testing.T) {
			cfg := baseValidConfig(t)
			cfg.Token.RefreshReuseGraceSeconds = intPtr(ok)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("grace %d must validate: %v", ok, err)
			}
			if got := cfg.Token.RefreshReuseGrace(); got != time.Duration(ok)*time.Second {
				t.Fatalf("grace %d resolved to %v", ok, got)
			}
		})
	}
	for _, bad := range []int{-1, domain.MaxRefreshTokenReuseGraceSeconds + 1} {
		t.Run(fmt.Sprintf("%d rejected", bad), func(t *testing.T) {
			cfg := baseValidConfig(t)
			cfg.Token.RefreshReuseGraceSeconds = intPtr(bad)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "token.refresh_reuse_grace_seconds must be between 0 and 300") {
				t.Fatalf("grace %d must be rejected, got: %v", bad, err)
			}
		})
	}
	t.Run("env var reaches the config", func(t *testing.T) {
		t.Setenv("ZEROID_REFRESH_REUSE_GRACE_SECONDS", "0")
		cfg, err := LoadConfig("")
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.Token.RefreshReuseGraceSeconds == nil || *cfg.Token.RefreshReuseGraceSeconds != 0 {
			t.Fatalf("ZEROID_REFRESH_REUSE_GRACE_SECONDS=0 did not reach token.refresh_reuse_grace_seconds: %v", cfg.Token.RefreshReuseGraceSeconds)
		}
		if cfg.Token.RefreshReuseGrace() != 0 {
			t.Fatal("0 must disable the grace")
		}
	})
	t.Run("loaded default is 10", func(t *testing.T) {
		cfg, err := LoadConfig("")
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.Token.RefreshReuseGrace() != 10*time.Second {
			t.Fatalf("default grace = %v, want 10s", cfg.Token.RefreshReuseGrace())
		}
	})
	t.Run("non-integer env var fails loud", func(t *testing.T) {
		t.Setenv("ZEROID_REFRESH_REUSE_GRACE_SECONDS", "ten")
		if _, err := LoadConfig(""); err == nil || !strings.Contains(err.Error(), "not a valid integer") {
			t.Fatalf("expected a not-a-valid-integer error, got %v", err)
		}
	})
}
