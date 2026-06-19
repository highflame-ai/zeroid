// Package zeroid provides the core server and configuration for ZeroID —
// the identity layer for autonomous agents and non-human workloads.
// Three-layer config loading: defaults -> YAML file -> environment variable overlays.
package zeroid

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/highflame-ai/zeroid/domain"
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

	// ExternalIssuers configures direct OIDC IdP federation (issue #88).
	// When grant_type=token-exchange and subject_token_type=id_token, ZeroID
	// looks up the upstream iss in this list, fetches the issuer's JWKS, and
	// verifies the ID token before minting a ZeroID token. Empty list (default)
	// disables direct federation — only the broker path remains available.
	ExternalIssuers []domain.ExternalIssuerConfig `koanf:"external_issuers"`
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

	// AllowPrivateIssuerEndpoints relaxes the SSRF guard the OIDC
	// attestation verifier applies to a proof's issuer endpoint (the URL
	// it fetches OIDC discovery + JWKS from). Default false
	// (production-safe).
	//
	// When false, the verifier rejects issuer endpoints that resolve to
	// private, loopback, link-local, multicast, CGN, or unspecified IP
	// ranges so an attacker-controlled proof can't make the server fetch
	// internal URLs (SSRF).
	//
	// When true, that guard is disabled. Use ONLY in single-tenant
	// test/dev deployments whose attestation issuer is itself on
	// localhost / a private network. Production MUST keep this false.
	//
	// Wired at startup into both the OIDC verifier (fetch-time guard) and
	// the attestation policy service (write-time URL validation).
	AllowPrivateIssuerEndpoints bool `koanf:"allow_private_issuer_endpoints"`
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
	// Issuer is the canonical URL of this ZeroID instance. It serves three
	// roles, all REQUIRED to be the same URL by RFC 8414 §3:
	//
	//  1. The JWT `iss` claim on every issued token.
	//  2. The discovery anchor — RFC 8414 §3 says clients construct
	//     `{Issuer}/.well-known/oauth-authorization-server` (with the
	//     well-known segment inserted between host and path) to find AS
	//     metadata. Issuer MUST be reachable at that URL.
	//  3. The URL prefix for every endpoint advertised in the AS metadata,
	//     PRM document, and RFC 7592 `registration_client_uri` — i.e. the
	//     URL clients actually hit.
	//
	// MUST be the publicly-routable URL of this AS, scheme://host[:port][/path],
	// no fragment. Reverse-proxied deployments: use the public form, not the
	// backend's listener URL. Path-mounted deployments (rare; antipattern for
	// new deployments): include the path in Issuer so RFC 8414's insertion
	// rule lands on a route the AS actually serves.
	//
	// DPoP `htu` validation does NOT depend on Issuer — it compares against
	// the request's effective URL (via RequestURLMiddleware), so reverse-proxy
	// header trust governs DPoP independently.
	Issuer     string `koanf:"issuer"`
	DefaultTTL int    `koanf:"default_ttl"`
	MaxTTL     int    `koanf:"max_ttl"`

	// authorization_code grant configuration.
	// HMACSecret is the shared secret used to sign and verify auth code JWTs (HS256).
	HMACSecret string `koanf:"hmac_secret"`
	// AuthCodeIssuer is the expected issuer claim in auth code JWTs.
	// Defaults to Token.Issuer when empty.
	AuthCodeIssuer string `koanf:"auth_code_issuer"`

	// AllowUnauthenticatedTokenInspection controls whether the introspection
	// (RFC 7662) and revocation (RFC 7009) endpoints accept anonymous callers.
	//
	// RFC 7662 §2.1 says the introspection endpoint MUST require some form of
	// authorization (token-scanning defense); RFC 7009 §2.1 requires client
	// authentication on revocation. When this is false, ZeroID enforces that:
	// a caller MUST present client credentials, and an anonymous call is
	// rejected with invalid_client.
	//
	// Default true preserves the accept-and-verify posture (anonymous allowed,
	// presented credentials still verified) for the standalone, network-
	// isolated deployment model and local development. Validate() REJECTS true
	// when server.env is production, so production deployments are strict
	// (spec-compliant) by default and must consciously keep this false — the
	// same production-gate pattern as AllowUnsafeDevStub and the default
	// issuer. A production deployment that genuinely relies on network
	// isolation should authenticate these endpoints at its own edge
	// (Server.Use) rather than serving them unauthenticated from ZeroID.
	AllowUnauthenticatedTokenInspection bool `koanf:"allow_unauthenticated_token_inspection"`
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

	// Detect removed/renamed config keys so deployers see a loud failure on
	// upgrade instead of silently losing settings. Koanf's Unmarshal would
	// otherwise drop keys that no longer map to struct fields.
	if err := rejectRemovedKeys(k); err != nil {
		return Config{}, err
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
	if err := validateIssuer(c.Token.Issuer); err != nil {
		return err
	}

	// Production-gated hardening. server.env had ZERO readers before this —
	// it now governs the footgun defaults that are safe in dev but dangerous
	// in production. The dev defaults stay intact so local/test workflows are
	// unaffected; these checks only fire when the deployer declares production.
	if isProductionEnv(c.Server.Env) {
		// The dev stub accepts ANY submitted proof for image_hash/tpm. Its
		// default is true (so dev demos work); leaving it on in production
		// means accept-any attestation. Force an explicit opt-out.
		if c.Attestation.AllowUnsafeDevStub {
			return fmt.Errorf("attestation.allow_unsafe_dev_stub must be false in production (server.env=%q): the stub accepts ANY submitted proof for image_hash/tpm — set ZEROID_ALLOW_UNSAFE_DEV_STUB=false", c.Server.Env)
		}
		// token.issuer and wimse_domain ship with Highflame's hosted defaults.
		// A production deploy that forgets to override them silently runs on
		// Highflame's identity — require an explicit value.
		if c.Token.Issuer == defaultIssuer {
			return fmt.Errorf("token.issuer must be set explicitly in production (server.env=%q): it still has the built-in default %q — set ZEROID_ISSUER to this deployment's public URL", c.Server.Env, defaultIssuer)
		}
		if c.WIMSEDomain == defaultWIMSEDomain {
			return fmt.Errorf("wimse_domain must be set explicitly in production (server.env=%q): it still has the built-in default %q — set ZEROID_WIMSE_DOMAIN to this deployment's trust domain", c.Server.Env, defaultWIMSEDomain)
		}
		// Introspection (RFC 7662 §2.1) and revocation (RFC 7009 §2.1) MUST
		// require caller authorization. The default leaves them accept-and-
		// verify (anonymous allowed) for the standalone/dev model; production
		// must not serve an unauthenticated token-scanning / force-revoke
		// surface. Force the explicit opt-out.
		if c.Token.AllowUnauthenticatedTokenInspection {
			return fmt.Errorf("token.allow_unauthenticated_token_inspection must be false in production (server.env=%q): RFC 7662 §2.1 / RFC 7009 §2.1 require caller authentication on introspection/revocation — set ZEROID_ALLOW_UNAUTHENTICATED_TOKEN_INSPECTION=false (authenticate these endpoints at your edge if you rely on network isolation)", c.Server.Env)
		}
	}

	// token.hmac_secret signs/verifies stateless authorization_code JWTs
	// (HS256). The authorization_code grant is optional, so the secret is not
	// globally required — but a weak secret is forgeable, so when one IS set
	// we enforce a floor. 32 bytes matches the HS256 output size.
	if c.Token.HMACSecret != "" && len(c.Token.HMACSecret) < 32 {
		return fmt.Errorf("token.hmac_secret must be at least 32 bytes when set, got %d: it signs stateless auth-code JWTs (HS256) and a short secret is forgeable", len(c.Token.HMACSecret))
	}

	seen := make(map[string]struct{}, len(c.ExternalIssuers))
	for i := range c.ExternalIssuers {
		c.ExternalIssuers[i].Defaults()
		if err := c.ExternalIssuers[i].Validate(); err != nil {
			return fmt.Errorf("external_issuers[%d]: %w", i, err)
		}
		iss := c.ExternalIssuers[i].Issuer
		if _, dup := seen[iss]; dup {
			return fmt.Errorf("external_issuers[%d]: duplicate issuer %q", i, iss)
		}
		seen[iss] = struct{}{}
	}
	return nil
}

// defaultIssuer and defaultWIMSEDomain are the built-in dev defaults that the
// production gate in Validate() rejects when left unchanged. They MUST match
// the values set in loadDefaults() — kept as named constants so the gate and
// the default can never drift.
const (
	defaultIssuer      = "https://auth.highflame.ai"
	defaultWIMSEDomain = "highflame.ai"
)

// isProductionEnv reports whether server.env names a production deployment.
// Accepts the common spellings ("production", "prod") case-insensitively so a
// deployer can't accidentally dodge the production gate with "Production".
func isProductionEnv(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "production", "prod":
		return true
	default:
		return false
	}
}

// validateIssuer enforces RFC 8414 §2's shape constraints on Token.Issuer.
// The issuer URL is load-bearing — it is the JWT iss claim, the RFC 8414 §3
// discovery anchor, and the URL prefix for every endpoint advertised in AS
// metadata, PRM, and RFC 7592 registration_client_uri. A malformed issuer
// causes silent client failures everywhere, so we reject anything that won't
// parse as a clean absolute URL up front.
func validateIssuer(s string) error {
	if s == "" {
		return fmt.Errorf("token.issuer is required: it is the JWT iss claim, the RFC 8414 §3 discovery anchor, and the URL prefix for every endpoint the server advertises; see TokenConfig.Issuer")
	}
	if strings.HasSuffix(s, "/") {
		return fmt.Errorf("token.issuer must not have a trailing slash (got %q): per RFC 8414 §3 a trailing slash MUST be removed before constructing the metadata URL", s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("token.issuer must be a valid URL (got %q): %w", s, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("token.issuer must use http or https scheme (got %q in %q)", u.Scheme, s)
	}
	if u.Host == "" {
		return fmt.Errorf("token.issuer must have a host (got %q)", s)
	}
	if u.User != nil {
		// Issuer URLs with embedded user-info (https://user:pass@host) are
		// not a real OAuth deployment shape — they would leak credentials
		// into JWT `iss` claims, metadata documents, and every URI the
		// server publishes. RFC 8414 §2's "URL using the https scheme"
		// language excludes user-info by reference to RFC 3986's URI
		// composition rules for OAuth identifiers. Error message kept
		// short so it fits one terminal line; rationale lives in this
		// comment for code readers.
		return fmt.Errorf("token.issuer must not contain user-info (got %q)", s)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("token.issuer must not contain query parameters (got %q): RFC 8414 §2 requires the issuer URL to have no query component", s)
	}
	if u.Fragment != "" {
		return fmt.Errorf("token.issuer must not contain a fragment (got %q): RFC 8414 §2 requires the issuer URL to have no fragment component", s)
	}
	return nil
}

// rejectRemovedKeys fails fast if a deployer's config (YAML or env) still sets
// keys that this version of ZeroID has removed. Silent drop on upgrade is
// indistinguishable from "the setting works but does nothing"; loud rejection
// forces migration.
//
// Add an entry here whenever a config key is removed. Keep entries until you
// believe no live deployment carries the old key.
func rejectRemovedKeys(k *koanf.Koanf) error {
	// Removed in the Token.BaseURL elimination (see CHANGELOG). Issuer now
	// serves the role BaseURL used to. Migration: set token.issuer (or
	// ZEROID_ISSUER) to whatever you previously had in token.base_url
	// (or ZEROID_BASE_URL).
	if k.Exists("token.base_url") {
		return fmt.Errorf("token.base_url has been removed: set token.issuer to the full URL ZeroID is reached at (RFC 8414 §3 anchors discovery on the issuer URL). See CHANGELOG for migration notes")
	}
	if os.Getenv("ZEROID_BASE_URL") != "" {
		return fmt.Errorf("ZEROID_BASE_URL has been removed: set ZEROID_ISSUER to the full URL ZeroID is reached at (RFC 8414 §3 anchors discovery on the issuer URL). See CHANGELOG for migration notes")
	}
	// telemetry.endpoint / telemetry.insecure were removed when exporter
	// configuration moved to the standard OTel SDK env vars
	// (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_INSECURE). They are no
	// longer fields on TelemetryConfig, so koanf would silently drop them —
	// reject loudly so a stale YAML doesn't quietly point telemetry at the
	// wrong collector.
	if k.Exists("telemetry.endpoint") {
		return fmt.Errorf("telemetry.endpoint has been removed: exporter config moved to the OTel SDK env var OTEL_EXPORTER_OTLP_ENDPOINT. Remove it from config and set the env var instead")
	}
	if k.Exists("telemetry.insecure") {
		return fmt.Errorf("telemetry.insecure has been removed: exporter config moved to the OTel SDK env var OTEL_EXPORTER_OTLP_INSECURE. Remove it from config and set the env var instead")
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
		// Default points at Highflame's hosted ZeroID URL (the actual
		// service, not the marketing site). Self-hosted deployments
		// override via ZEROID_ISSUER or token.issuer in YAML. Local dev
		// on localhost:8899 should set ZEROID_ISSUER=http://localhost:8899.
		"token.issuer":      defaultIssuer,
		"token.default_ttl": 3600,
		"token.max_ttl":     7776000, // 90 days
		// Accept-and-verify on introspect/revoke by default (dev/standalone).
		// Validate() forces this false in production (RFC 7662/7009).
		"token.allow_unauthenticated_token_inspection": true,

		// WIMSE
		"wimse_domain": defaultWIMSEDomain,

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
		// SSRF guard on the OIDC verifier's issuer-endpoint fetch. Default
		// false (production-safe); dev/test deployments whose attestation
		// issuer is on localhost/a private network opt in.
		"attestation.allow_private_issuer_endpoints": false,

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
		"ZEROID_PORT":                    "server.port",
		"ZEROID_ENV":                     "server.env",
		"ZEROID_ADMIN_PATH_PREFIX":       "server.admin_path_prefix",
		"ZEROID_TRUST_FORWARDED_HEADERS": "server.trust_forwarded_headers",

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
		"ZEROID_TOKEN_TTL_SECONDS":     "token.default_ttl",
		"ZEROID_MAX_TOKEN_TTL_SECONDS": "token.max_ttl",
		// HMAC secret signs/verifies stateless authorization_code JWTs (HS256).
		// A leak forges auth codes; Validate() enforces >= 32 bytes when set.
		"ZEROID_HMAC_SECRET": "token.hmac_secret",
		// Strict client auth on introspection/revocation (RFC 7662/7009).
		// Default true (accept-and-verify); Validate() forces false in production.
		"ZEROID_ALLOW_UNAUTHENTICATED_TOKEN_INSPECTION": "token.allow_unauthenticated_token_inspection",

		// WIMSE
		"ZEROID_WIMSE_DOMAIN": "wimse_domain",

		// Attestation
		"ZEROID_ALLOW_UNSAFE_DEV_STUB":                      "attestation.allow_unsafe_dev_stub",
		"ZEROID_ATTESTATION_ALLOW_PRIVATE_ISSUER_ENDPOINTS": "attestation.allow_private_issuer_endpoints",

		// Backchannel (CIBA) — SSRF guard relaxation for single-tenant
		// test/dev deployments only. Production MUST leave this false.
		"ZEROID_BACKCHANNEL_ALLOW_PRIVATE_ENDPOINTS": "backchannel.allow_private_notification_endpoints",

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

		// Parse errors are returned, not swallowed: a typo'd typed env var
		// (e.g. ZEROID_ALLOW_UNSAFE_DEV_STUB=flase) must NOT silently retain
		// the default — for a security flag that means the accept-any
		// attestation stub stays on. Fail loud at startup instead.
		switch {
		case strings.HasSuffix(configPath, ".enabled") ||
			strings.HasSuffix(configPath, ".allow_unsafe_dev_stub") ||
			strings.HasSuffix(configPath, ".trust_forwarded_headers") ||
			strings.HasSuffix(configPath, ".allow_private_notification_endpoints") ||
			strings.HasSuffix(configPath, ".allow_private_issuer_endpoints") ||
			strings.HasSuffix(configPath, ".allow_unauthenticated_token_inspection"):
			boolVal, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("%s=%q: not a valid bool (use true/false)", envVar, value)
			}
			if err := k.Set(configPath, boolVal); err != nil {
				return fmt.Errorf("setting %s from %s: %w", configPath, envVar, err)
			}
		case strings.HasSuffix(configPath, ".max_open_conns") ||
			strings.HasSuffix(configPath, ".max_idle_conns") ||
			strings.HasSuffix(configPath, ".default_ttl") ||
			strings.HasSuffix(configPath, ".max_ttl") ||
			strings.HasSuffix(configPath, ".shutdown_timeout_seconds"):
			intVal, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("%s=%q: not a valid integer", envVar, value)
			}
			if err := k.Set(configPath, intVal); err != nil {
				return fmt.Errorf("setting %s from %s: %w", configPath, envVar, err)
			}
		case strings.HasSuffix(configPath, ".sampling_rate"):
			floatVal, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return fmt.Errorf("%s=%q: not a valid float", envVar, value)
			}
			if err := k.Set(configPath, floatVal); err != nil {
				return fmt.Errorf("setting %s from %s: %w", configPath, envVar, err)
			}
		default:
			if err := k.Set(configPath, value); err != nil {
				return fmt.Errorf("setting %s from %s: %w", configPath, envVar, err)
			}
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
