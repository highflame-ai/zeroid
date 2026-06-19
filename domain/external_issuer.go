package domain

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

// ExternalIssuerConfig describes a single trusted upstream OIDC IdP that the
// /oauth2/token endpoint will accept ID tokens from when grant_type is
// urn:ietf:params:oauth:grant-type:token-exchange and subject_token_type is
// urn:ietf:params:oauth:token-type:id_token.
//
// The deployer is the trust anchor. Only issuers listed here are accepted —
// there is no auto-discovery, no OIDF, no implicit trust. ZeroID fetches the
// issuer's JWKS from JWKSURI, verifies the ID token's signature against it,
// and propagates the upstream iss into the issued token as user_id_iss so
// downstream consumers can answer "which IdP authenticated this user?" from
// the token alone (NIST SP 800-63C §4.1).
type ExternalIssuerConfig struct {
	// Issuer is the upstream IdP's iss value, matched verbatim against the
	// ID token's iss claim. Must be an absolute https:// URL.
	Issuer string `koanf:"issuer"`

	// JWKSURI is fetched on startup and re-fetched every JWKSCacheTTL. The
	// HTTP client used for fetching is the one configured on the JWKS client
	// (defaults to http.DefaultClient). Must be an absolute https:// URL.
	JWKSURI string `koanf:"jwks_uri"`

	// Audience is the value the upstream IdP is expected to set as aud on
	// tokens it issues for ZeroID. Required — token exchange without an
	// audience binding lets a token issued for some other RP be replayed
	// against ZeroID.
	Audience string `koanf:"audience"`

	// Algorithms is the allow-list of JWS algorithms accepted on incoming ID
	// tokens. Defaults to {"RS256", "ES256"} when empty. Only RS256/ES256/PS256
	// are supported by the underlying verifier; entries outside that set are
	// rejected at validation time.
	Algorithms []string `koanf:"algorithms"`

	// MaxTokenAge caps the time between the upstream iat and "now". An ID
	// token whose iat is older than MaxTokenAge is rejected even if it has
	// not yet expired. Defaults to 10m. Must be > 0.
	MaxTokenAge time.Duration `koanf:"max_token_age"`

	// JWKSCacheTTL controls how often the JWKS is refreshed in the
	// background. Minimum 30s (matches pkg/authjwt). Defaults to 5m.
	JWKSCacheTTL time.Duration `koanf:"jwks_cache_ttl"`

	// ClaimMapping maps ZeroID claim names to upstream claim paths. v1
	// supports single-level keys only — no JSONPath, no expressions. The
	// only required mapping is "user_id"; everything else is optional.
	//
	//	claim_mapping:
	//	  user_id: sub          # or "preferred_username", "oid", etc.
	//	  email:   email
	ClaimMapping map[string]string `koanf:"claim_mapping"`

	// AllowedAccounts limits the tenants that may use this issuer. When
	// non-empty, the request's account_id must appear in this list. Empty
	// means any tenant may use it.
	AllowedAccounts []string `koanf:"allowed_accounts"`

	// PropagateClaims is the explicit allow-list of upstream claims to
	// copy onto the issued ZeroID token. Only auth_time, acr, and amr are
	// recognized in v1 — these are RFC 9068 authentication-context claims
	// and only meaningful when copied through directly from the IdP.
	// Anything else is ignored. We never default-fill these claims; if the
	// upstream omitted them, ZeroID does not synthesize them.
	PropagateClaims []string `koanf:"propagate_claims"`

	// AllowPrivateEndpoints relaxes the SSRF guard applied to this issuer's
	// JWKSURI fetch. Default false rejects a jwks_uri host that resolves to a
	// private/loopback/link-local/metadata/reserved address (re-checked at
	// dial time as a DNS-rebinding defense), mirroring the attestation OIDC
	// verifier's guard (issue #198). Set true ONLY when the upstream IdP is
	// deliberately on a private network (corporate IdP behind a VPN) or in
	// single-tenant dev/test pointing at localhost. Production with a public
	// IdP MUST keep this false.
	AllowPrivateEndpoints bool `koanf:"allow_private_endpoints"`
}

// Validate checks the config for the bare minimum needed to verify a token:
// an issuer URL, a JWKS URL, an audience, and at least a user_id claim
// mapping. Defaults are applied for the optional knobs.
func (e *ExternalIssuerConfig) Validate() error {
	if e.Issuer == "" {
		return errors.New("external_issuer: issuer is required")
	}
	if u, err := url.Parse(e.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("external_issuer: issuer must be an absolute https URL, got %q", e.Issuer)
	}
	if e.JWKSURI == "" {
		return fmt.Errorf("external_issuer %s: jwks_uri is required", e.Issuer)
	}
	if u, err := url.Parse(e.JWKSURI); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("external_issuer %s: jwks_uri must be an absolute https URL, got %q", e.Issuer, e.JWKSURI)
	}
	if e.Audience == "" {
		return fmt.Errorf("external_issuer %s: audience is required (token-exchange without aud binding allows token replay)", e.Issuer)
	}
	if e.MaxTokenAge < 0 {
		return fmt.Errorf("external_issuer %s: max_token_age must be > 0", e.Issuer)
	}
	if e.JWKSCacheTTL < 0 {
		return fmt.Errorf("external_issuer %s: jwks_cache_ttl must be > 0", e.Issuer)
	}
	if _, ok := e.ClaimMapping["user_id"]; !ok {
		return fmt.Errorf("external_issuer %s: claim_mapping.user_id is required (need a stable subject identifier)", e.Issuer)
	}
	for _, claim := range e.PropagateClaims {
		switch claim {
		case "auth_time", "acr", "amr":
		default:
			return fmt.Errorf("external_issuer %s: propagate_claims entry %q not supported (allowed: auth_time, acr, amr)", e.Issuer, claim)
		}
	}
	return nil
}

// Defaults applies runtime defaults to the optional knobs. Idempotent — only
// fills zero-valued fields.
func (e *ExternalIssuerConfig) Defaults() {
	if len(e.Algorithms) == 0 {
		e.Algorithms = []string{"RS256", "ES256"}
	}
	if e.MaxTokenAge == 0 {
		e.MaxTokenAge = 10 * time.Minute
	}
	if e.JWKSCacheTTL == 0 {
		e.JWKSCacheTTL = 5 * time.Minute
	}
}

// AccountAllowed reports whether the given tenant is permitted to exchange
// tokens issued by this IdP. Empty AllowedAccounts means any tenant.
func (e *ExternalIssuerConfig) AccountAllowed(accountID string) bool {
	if len(e.AllowedAccounts) == 0 {
		return true
	}
	for _, a := range e.AllowedAccounts {
		if a == accountID {
			return true
		}
	}
	return false
}
