// Package zeroid provides the core server and configuration for ZeroID —
// the identity layer for autonomous agents and non-human workloads.
// Three-layer config loading: defaults -> YAML file -> environment variable overlays.
package zeroid

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// DefaultAdminPathPrefix is the default URL prefix for admin API routes.
// Standalone ZeroID serves admin routes at /api/v1/*. Deployers can override
// this via ServerConfig.AdminPathPrefix.
const DefaultAdminPathPrefix = "/api/v1"

// DefaultSigningJWKSName is the default suffix for the workload-attested
// signing-credential verification JWKS, served at
// /.well-known/<name>. It is intentionally generic: ZeroID is
// product-agnostic. Deployers brand it via
// SigningCredsConfig.WellKnownJWKSName (e.g. a product publishes its
// receipt-verification keys at /.well-known/<product>-receipt-keys).
const DefaultSigningJWKSName = "signing-keys"

// Config holds the complete ZeroID service configuration.
type Config struct {
	Server      ServerConfig      `koanf:"server"`
	Database    DatabaseConfig    `koanf:"database"`
	Keys        KeysConfig        `koanf:"keys"`
	Token       TokenConfig       `koanf:"token"`
	Telemetry   TelemetryConfig   `koanf:"telemetry"`
	Logging     LoggingConfig     `koanf:"logging"`
	Attestation AttestationConfig `koanf:"attestation"`
	Backchannel BackchannelConfig `koanf:"backchannel"`

	SigningCreds SigningCredsConfig `koanf:"signing_credentials"`

	// WIMSEDomain is the domain prefix for SPIFFE/WIMSE URIs (e.g. "zeroid.dev").
	WIMSEDomain string `koanf:"wimse_domain"`
}

// BackchannelConfig governs CIBA (OpenID CIBA Core 1.0) behavior. All fields
// are optional; defaults are applied in service.DefaultBackchannelConfig().
type BackchannelConfig struct {
	// AllowPrivateNotificationEndpoints relaxes the SSRF guard on CIBA
	// outbound notification destinations. Default false (production-safe).
	//
	// When false, registered client_notification_endpoint hosts are resolved
	// and rejected if they (or any of their resolved IPs) fall in private,
	// loopback, link-local, multicast, CGN, or unspecified ranges. Re-checked
	// at request time as DNS-rebinding defense.
	//
	// When true, the guard is disabled — only HTTPS scheme + non-empty host
	// are enforced. Use ONLY in single-tenant test/dev deployments that
	// register endpoints like https://localhost:9000/. Production deployments
	// MUST keep this false (see GHSA-599q-j34m-33vc).
	AllowPrivateNotificationEndpoints bool `koanf:"allow_private_notification_endpoints"`
}

// AttestationConfig governs the attestation verification subsystem. The
// real verifier path (OIDC) is always wired and fail-closed without a
// tenant-configured AttestationPolicy. AllowUnsafeDevStub controls
// whether a permissive stub covers the proof types whose real verifier
// hasn't shipped yet (image_hash, tpm).
type AttestationConfig struct {
	// AllowUnsafeDevStub, when true, registers a stub verifier that
	// accepts any submitted proof for image_hash and tpm. Prints a
	// loud startup warning whenever it's installed.
	//
	// Default is true today: until image_hash / tpm real verifiers
	// land, the stub is the only way demo flows that submit those
	// proof types keep working — flipping the default to false would
	// hard-reject them. Deployments that don't use image_hash or tpm
	// should set ZEROID_ALLOW_UNSAFE_DEV_STUB=false. The OIDC verifier
	// (the only real verifier shipped) is unaffected by this flag.
	AllowUnsafeDevStub bool `koanf:"allow_unsafe_dev_stub"`
}

// SigningCredsConfig governs workload-attested ephemeral signing
// credentials. The two clocks are deliberately decoupled: MaxTTLSeconds
// bounds how long an attested key may SIGN; AuditRetentionDays bounds how
// long its public key stays resolvable for VERIFYING historical
// attestations (>> MaxTTLSeconds). See domain/signing_credential.go.
type SigningCredsConfig struct {
	// MaxTTLSeconds caps the operational signing window an attestation
	// may request (default 1h — keys are ephemeral, rotated often).
	MaxTTLSeconds int `koanf:"max_ttl_seconds"`
	// AuditRetentionDays is how long a non-revoked public key remains
	// verifiable after attestation (default 400 — covers a >1y audit
	// window so historical receipts verify long after key rotation).
	AuditRetentionDays int `koanf:"audit_retention_days"`
	// AllowedPurposes is the deployer-supplied allowlist of purpose
	// strings a workload may attest a key for. ZeroID is
	// product-agnostic: it ships EMPTY (no purpose accepted) so a
	// deployment must explicitly opt in and name its own purposes
	// (e.g. a product allows "receipt", "authz_audit"). An attest
	// request whose purpose is not in this list is rejected.
	AllowedPurposes []string `koanf:"allowed_purposes"`
	// JWKSPurpose selects which purpose's keys the well-known
	// verification JWKS publishes. The well-known path is inherently
	// purpose-specific (it is the verification endpoint for one class
	// of receipts), so a deployer that publishes more than one purpose
	// runs more than one ZeroID-fronting alias. Empty ⇒ the JWKS route
	// is not registered (feature dormant).
	JWKSPurpose string `koanf:"jwks_purpose"`
	// WellKnownJWKSName is the /.well-known/<name> suffix the
	// verification JWKS is served at. Defaults to DefaultSigningJWKSName
	// ("signing-keys"); deployers brand it (e.g. "<product>-receipt-keys").
	WellKnownJWKSName string `koanf:"well_known_jwks_name"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Port                   string `koanf:"port"`
	Env                    string `koanf:"env"`
	ReadTimeout            string `koanf:"read_timeout"`
	WriteTimeout           string `koanf:"write_timeout"`
	IdleTimeout            string `koanf:"idle_timeout"`
	ShutdownTimeoutSeconds int    `koanf:"shutdown_timeout_seconds"`

	// AdminPathPrefix is the URL prefix for admin API routes (identities, agents,
	// credentials, etc.). Defaults to "/api/v1" for standalone deployments.
	//
	// Deployers that mount ZeroID under their own path structure can override this.
	// For example, highflame-authn sets this to "" and mounts the router at "/v1/auth"
	// so admin routes become /v1/auth/identities/schema instead of /api/v1/identities/schema.
	//
	// Set to empty string ("") to register admin routes at the router root.
	AdminPathPrefix *string `koanf:"admin_path_prefix"`

	// TrustForwardedHeaders tells the server to read X-Forwarded-Proto and
	// X-Forwarded-Host when reconstructing the effective request URL for
	// DPoP htu validation (RFC 9449 §4.3). Production deployers behind a
	// trusted edge proxy (nginx, AWS ALB, GCP LB) flip this on; deployers
	// that terminate TLS at the service itself leave it false so spoofed
	// proxy headers cannot move the htu goalposts.
	TrustForwardedHeaders bool `koanf:"trust_forwarded_headers"`
}

// GetAdminPathPrefix returns the admin route prefix. Defaults to "/api/v1"
// when not explicitly set.
func (s *ServerConfig) GetAdminPathPrefix() string {
	if s.AdminPathPrefix != nil {
		return *s.AdminPathPrefix
	}
	return DefaultAdminPathPrefix
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	URL          string `koanf:"url"`
	Host         string `koanf:"host"`
	Port         string `koanf:"port"`
	User         string `koanf:"user"`
	Password     string `koanf:"password"`
	Name         string `koanf:"name"`
	SSLMode      string `koanf:"ssl_mode"`
	MaxOpenConns int    `koanf:"max_open_conns"`
	MaxIdleConns int    `koanf:"max_idle_conns"`
	// AutoMigrate controls whether NewServer runs embedded migrations on startup.
	// Default: true (convenient for standalone/dev). Set to false when the deployer
	// manages schema migrations via their own pipeline (production recommended).
	AutoMigrate *bool `koanf:"auto_migrate"`
}

// KeysConfig holds key paths for JWT signing.
// ECDSA P-256 keys are used for NHI/agent flows (ES256).
// RSA keys are used for human/SDK flows (RS256).
type KeysConfig struct {
	PrivateKeyPath string `koanf:"private_key_path"`
	PublicKeyPath  string `koanf:"public_key_path"`
	KeyID          string `koanf:"key_id"`
	// RSA key paths for RS256 signing (human/SDK tokens).
	RSAPrivateKeyPath string `koanf:"rsa_private_key_path"`
	RSAPublicKeyPath  string `koanf:"rsa_public_key_path"`
	RSAKeyID          string `koanf:"rsa_key_id"`
}

// TokenConfig holds JWT issuance settings.
type TokenConfig struct {
	Issuer string `koanf:"issuer"`
	// BaseURL is the publicly-visible URL clients use to reach this server.
	// It seeds every URI returned in responses (`registration_endpoint` and
	// `registration_client_uri` in DCR responses, the JWT `iss` claim's
	// authority for verification, and the well-known discovery doc).
	//
	// MUST be the URL clients actually hit — including any reverse-proxy
	// rewrites or path prefixes the deployment adds. If a proxy fronts
	// zeroid at https://auth.example.com/v1 and forwards to a backend on
	// http://10.0.0.5:8080, set BaseURL = "https://auth.example.com/v1"
	// (the public form), NOT the backend URL. A wrong value here doesn't
	// break token signing — JWTs continue to verify against jwks_uri — but
	// every URI the server PUBLISHES (DCR responses, discovery) becomes
	// unreachable from outside. Validate() will reject empty values; format
	// validity is the deployer's responsibility.
	//
	// Note: DPoP `htu` validation does NOT depend on BaseURL — it compares
	// against the request's effective URL (via RequestURLMiddleware) so
	// reverse-proxied deployments don't need to keep BaseURL and the proxy
	// in lock-step for token issuance to work. BaseURL is purely about the
	// shape of URIs the server hands BACK to clients.
	BaseURL    string `koanf:"base_url"`
	DefaultTTL int    `koanf:"default_ttl"`
	MaxTTL     int    `koanf:"max_ttl"`

	// authorization_code grant configuration.
	// HMACSecret is the shared secret used to sign and verify auth code JWTs (HS256).
	HMACSecret string `koanf:"hmac_secret"`
	// AuthCodeIssuer is the expected issuer claim in auth code JWTs.
	// Defaults to Token.Issuer when empty.
	AuthCodeIssuer string `koanf:"auth_code_issuer"`
}

// TelemetryConfig holds OpenTelemetry settings.
// Endpoint and TLS are delegated to the OTel SDK via standard env vars
type TelemetryConfig struct {
	Enabled      bool    `koanf:"enabled"`
	ServiceName  string  `koanf:"service_name"`
	SamplingRate float64 `koanf:"sampling_rate"`
}

// LoggingConfig holds structured logging settings.
type LoggingConfig struct {
	Level string `koanf:"level"`
}

// LoadConfig reads configuration using Koanf: defaults -> YAML file -> environment overlays.
func LoadConfig(configPath string) (Config, error) {
	k := koanf.New(".")

	if err := loadDefaults(k); err != nil {
		return Config{}, fmt.Errorf("loading defaults: %w", err)
	}

	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			return Config{}, fmt.Errorf("loading config file %s: %w", configPath, err)
		}
	}

	if err := loadEnvVars(k); err != nil {
		return Config{}, fmt.Errorf("loading env vars: %w", err)
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshaling config: %w", err)
	}

	// Build database URL from individual vars if not provided directly.
	if cfg.Database.URL == "" && cfg.Database.Host != "" {
		cfg.Database.URL = buildDatabaseURL(&cfg.Database)
	}

	return cfg, nil
}

// Validate checks required fields and value ranges.
func (c *Config) Validate() error {
	if c.Server.Port == "" {
		return fmt.Errorf("server.port is required")
	}
	if c.Database.URL == "" {
		return fmt.Errorf("database URL is required: provide ZEROID_DATABASE_URL or individual DB_ vars")
	}
	if c.Keys.PrivateKeyPath == "" {
		return fmt.Errorf("keys.private_key_path is required")
	}
	if _, err := os.Stat(c.Keys.PrivateKeyPath); err != nil {
		return fmt.Errorf("private key not found at %s (run 'make setup-keys'): %w", c.Keys.PrivateKeyPath, err)
	}
	if c.Keys.PublicKeyPath == "" {
		return fmt.Errorf("keys.public_key_path is required")
	}
	if _, err := os.Stat(c.Keys.PublicKeyPath); err != nil {
		return fmt.Errorf("public key not found at %s (run 'make setup-keys'): %w", c.Keys.PublicKeyPath, err)
	}
	if c.Database.MaxOpenConns <= 0 {
		return fmt.Errorf("database.max_open_conns must be > 0, got %d", c.Database.MaxOpenConns)
	}
	if c.Database.MaxIdleConns < 0 || c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("database.max_idle_conns must be between 0 and max_open_conns, got %d", c.Database.MaxIdleConns)
	}
	if err := validateWIMSEDomain(c.WIMSEDomain); err != nil {
		return fmt.Errorf("wimse_domain: %w", err)
	}
	if c.Token.BaseURL == "" {
		return fmt.Errorf("token.base_url is required: every URI the server hands back (DCR registration_client_uri, well-known discovery) derives from it; see TokenConfig.BaseURL")
	}
	return nil
}

// validateWIMSEDomain enforces the SPIFFE §2.2 trust-domain shape — lowercase
// RFC 1123 hostname, no scheme. Catching it at startup is the difference
// between a clean error and minting unparseable SPIFFE IDs forever.
func validateWIMSEDomain(s string) error {
	if s == "" {
		return fmt.Errorf("trust domain is required")
	}
	// Common misconfig: someone copies a full SPIFFE ID into the env var.
	if strings.HasPrefix(s, "spiffe://") {
		return fmt.Errorf("must be a bare DNS name, not a SPIFFE URI (drop the spiffe:// prefix)")
	}
	if len(s) > 253 {
		return fmt.Errorf("must be at most 253 characters, got %d", len(s))
	}
	// Manual walk over a regex — error messages can name the offending label.
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return fmt.Errorf("must not contain empty label (consecutive dots or leading/trailing dot in %q)", s)
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q exceeds 63 characters", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q must not start or end with a hyphen", label)
		}
		// Range over runes so a multi-byte UTF-8 char gets reported as itself
		// rather than as the leading byte.
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return fmt.Errorf("label %q contains character %q (allowed: a-z 0-9 -, lowercase only)", label, r)
			}
		}
	}
	return nil
}

func loadDefaults(k *koanf.Koanf) error {
	defaults := map[string]any{
		// Server
		"server.port":                     "8899",
		"server.env":                      "development",
		"server.read_timeout":             "15s",
		"server.write_timeout":            "15s",
		"server.idle_timeout":             "60s",
		"server.shutdown_timeout_seconds": 30,

		// Database
		"database.port":           "5432",
		"database.ssl_mode":       "disable",
		"database.max_open_conns": 25,
		"database.max_idle_conns": 5,

		// Keys
		"keys.private_key_path":     "./keys/private.pem",
		"keys.public_key_path":      "./keys/public.pem",
		"keys.key_id":               "zeroid-key-1",
		"keys.rsa_private_key_path": "",
		"keys.rsa_public_key_path":  "",
		"keys.rsa_key_id":           "v1",

		// Token
		"token.issuer":      "https://highflame.ai",
		"token.base_url":    "https://highflame.ai",
		"token.default_ttl": 3600,
		"token.max_ttl":     7776000, // 90 days

		// WIMSE
		"wimse_domain": "highflame.ai",

		// Telemetry
		"telemetry.enabled":       false,
		"telemetry.service_name":  "zeroid",
		"telemetry.sampling_rate": 1.0,

		// Admin path prefix
		"server.admin_path_prefix": DefaultAdminPathPrefix,

		// Attestation — dev stub on by default until image_hash / tpm
		// real verifiers ship. Override with
		// ZEROID_ALLOW_UNSAFE_DEV_STUB=false for deployments that don't
		// submit those proof types (or once real verifiers land).
		"attestation.allow_unsafe_dev_stub": true,

		// Workload-attested signing credentials. Operational signing
		// window is short (1h, keys are ephemeral + rotated); the public
		// key stays verifiable for a long audit window (400d) so
		// historical attestations verify long after rotation.
		"signing_credentials.max_ttl_seconds":      3600,
		"signing_credentials.audit_retention_days": 400,
		// Product-agnostic by default: no purpose accepted and the
		// generic well-known name. A deployment opts in by configuring
		// allowed_purposes + jwks_purpose (+ optionally branding the name).
		"signing_credentials.well_known_jwks_name": DefaultSigningJWKSName,

		// Logging
		"logging.level": "info",
	}

	for key, val := range defaults {
		if err := k.Set(key, val); err != nil {
			return fmt.Errorf("setting default %s: %w", key, err)
		}
	}
	return nil
}

func loadEnvVars(k *koanf.Koanf) error {
	envMapping := map[string]string{
		// Server
		"ZEROID_PORT":              "server.port",
		"ZEROID_ENV":               "server.env",
		"ZEROID_ADMIN_PATH_PREFIX": "server.admin_path_prefix",

		// Database
		"ZEROID_DATABASE_URL": "database.url",
		"DB_HOST":             "database.host",
		"DB_PORT":             "database.port",
		"DB_USERNAME":         "database.user",
		"DB_PASSWORD":         "database.password",
		"ZEROID_DB_NAME":      "database.name",
		"DB_SSL_MODE":         "database.ssl_mode",
		"ZEROID_AUTO_MIGRATE": "database.auto_migrate",

		// Keys
		"ZEROID_PRIVATE_KEY_PATH":     "keys.private_key_path",
		"ZEROID_PUBLIC_KEY_PATH":      "keys.public_key_path",
		"ZEROID_KEY_ID":               "keys.key_id",
		"ZEROID_RSA_PRIVATE_KEY_PATH": "keys.rsa_private_key_path",
		"ZEROID_RSA_PUBLIC_KEY_PATH":  "keys.rsa_public_key_path",
		"ZEROID_RSA_KEY_ID":           "keys.rsa_key_id",

		"ZEROID_SIGNING_CREDS_MAX_TTL_SECONDS":      "signing_credentials.max_ttl_seconds",
		"ZEROID_SIGNING_CREDS_AUDIT_RETENTION_DAYS": "signing_credentials.audit_retention_days",
		"ZEROID_SIGNING_CREDS_JWKS_PURPOSE":         "signing_credentials.jwks_purpose",
		"ZEROID_SIGNING_CREDS_WELL_KNOWN_JWKS_NAME": "signing_credentials.well_known_jwks_name",

		// Token
		"ZEROID_ISSUER":                "token.issuer",
		"ZEROID_BASE_URL":              "token.base_url",
		"ZEROID_TOKEN_TTL_SECONDS":     "token.default_ttl",
		"ZEROID_MAX_TOKEN_TTL_SECONDS": "token.max_ttl",

		// WIMSE
		"ZEROID_WIMSE_DOMAIN": "wimse_domain",

		// Attestation
		"ZEROID_ALLOW_UNSAFE_DEV_STUB": "attestation.allow_unsafe_dev_stub",

		// Telemetry — OTEL_EXPORTER_OTLP_ENDPOINT and TLS settings are read
		// directly by the OTel SDK (spec-compliant).
		"OTEL_ENABLED":            "telemetry.enabled",
		"OTEL_TRACES_SAMPLER_ARG": "telemetry.sampling_rate",

		// Logging
		"ZEROID_LOG_LEVEL": "logging.level",
	}

	for envVar, configPath := range envMapping {
		value, ok := os.LookupEnv(envVar)
		if !ok {
			continue
		}

		switch {
		case strings.HasSuffix(configPath, ".enabled") ||
			strings.HasSuffix(configPath, ".allow_unsafe_dev_stub"):
			if boolVal, err := strconv.ParseBool(value); err == nil {
				_ = k.Set(configPath, boolVal)
			}
		case strings.HasSuffix(configPath, ".max_open_conns") ||
			strings.HasSuffix(configPath, ".max_idle_conns") ||
			strings.HasSuffix(configPath, ".default_ttl") ||
			strings.HasSuffix(configPath, ".max_ttl") ||
			strings.HasSuffix(configPath, ".shutdown_timeout_seconds"):
			if intVal, err := strconv.Atoi(value); err == nil {
				_ = k.Set(configPath, intVal)
			}
		case strings.HasSuffix(configPath, ".sampling_rate"):
			if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
				_ = k.Set(configPath, floatVal)
			}
		default:
			_ = k.Set(configPath, value)
		}
	}

	return nil
}

func buildDatabaseURL(db *DatabaseConfig) string {
	userInfo := db.User
	if db.Password != "" {
		userInfo += ":" + db.Password
	}
	url := fmt.Sprintf("postgres://%s@%s:%s/%s", userInfo, db.Host, db.Port, db.Name)
	if db.SSLMode != "" {
		url += "?sslmode=" + db.SSLMode
	}
	return url
}
