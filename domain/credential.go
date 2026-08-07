package domain

import (
	"time"

	"github.com/uptrace/bun"
)

// Audit-retention window bounds for issued_credentials. One source of truth
// for the "evidence clock" default and ceiling, referenced by the koanf
// default, Config.Validate, and CredentialService's clamp so the three can't
// silently diverge.
const (
	// DefaultAuditRetentionDays is the retention applied when
	// token.audit_retention_days is absent or 0. ~400 days mirrors the
	// signing-credentials retention default. NOTE: migration 037's backfill
	// hardcodes 400 (a migration can't read config); a deployment running a
	// non-default window must re-stamp historical rows out-of-band.
	DefaultAuditRetentionDays = 400
	// MaxAuditRetentionDays caps the window. Past ~106751 days the
	// days→time.Duration conversion overflows int64 into a negative
	// duration, which would stamp retention BEFORE expiry and erase the
	// evidence window the knob exists to protect. 36500 (~100y) is a
	// generous practical ceiling well below the overflow point.
	MaxAuditRetentionDays = 36500
)

// GrantType represents the OAuth2 grant type used to issue a credential.
type GrantType string

const (
	// GrantTypeClientCredentials is the standard machine-to-machine OAuth2 grant (RFC 6749 §4.4).
	GrantTypeClientCredentials GrantType = "client_credentials"
	// GrantTypeJWTBearer is the JWT assertion grant for bootstrapping without a shared secret (RFC 7523).
	GrantTypeJWTBearer GrantType = "jwt_bearer"
	// GrantTypeTokenExchange is used for workload token delegation (RFC 8693).
	GrantTypeTokenExchange GrantType = "token_exchange"
	// GrantTypeAPIKey is used for SDK/CLI authentication via zid_sk_* API keys.
	// Issues RS256 tokens when RSA keys are configured.
	GrantTypeAPIKey GrantType = "api_key"
	// GrantTypeAuthorizationCode is the standard PKCE authorization code grant (RFC 6749 §4.1).
	// Used by CLI and MCP clients. MCP clients also receive a refresh token.
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	// GrantTypeRefreshToken is used to rotate refresh tokens for long-lived sessions (RFC 6749 §6).
	// Implements family-based rotation with reuse detection.
	GrantTypeRefreshToken GrantType = "refresh_token"
)

// urnToShortGrantType maps OAuth2 URN grant type identifiers to their canonical short forms.
var urnToShortGrantType = map[string]GrantType{
	"urn:ietf:params:oauth:grant-type:jwt-bearer":     GrantTypeJWTBearer,
	"urn:ietf:params:oauth:grant-type:token-exchange": GrantTypeTokenExchange,
}

// allValidGrantTypes is the set of all recognised canonical short forms.
var allValidGrantTypes = map[GrantType]bool{
	GrantTypeClientCredentials: true,
	GrantTypeJWTBearer:         true,
	GrantTypeTokenExchange:     true,
	GrantTypeAPIKey:            true,
	GrantTypeAuthorizationCode: true,
	GrantTypeRefreshToken:      true,
	GrantTypeCIBA:              true,
}

// NormalizeGrantType converts a grant type string to its canonical short form.
// Accepts both URN forms (e.g. "urn:ietf:params:oauth:grant-type:jwt-bearer")
// and short forms (e.g. "jwt_bearer"). Returns the input unchanged if not recognised.
func NormalizeGrantType(gt string) GrantType {
	if short, ok := urnToShortGrantType[gt]; ok {
		return short
	}
	return GrantType(gt)
}

// IsValidGrantType reports whether gt is a recognised grant type.
// Accepts both URN and short forms.
func IsValidGrantType(gt string) bool {
	return allValidGrantTypes[NormalizeGrantType(gt)]
}

// IssuedCredential represents a JWT credential issued to an identity.
// It is persisted for introspection, revocation, and audit purposes.
type IssuedCredential struct {
	bun.BaseModel `bun:"table:issued_credentials,alias:ic"`

	ID              string     `bun:"id,pk,type:uuid"              json:"id"`
	IdentityID      *string    `bun:"identity_id,type:uuid"        json:"identity_id,omitempty"`
	AccountID       string     `bun:"account_id,type:varchar(255)" json:"account_id"`
	ProjectID       string     `bun:"project_id,type:varchar(255)" json:"project_id"`
	JTI             string     `bun:"jti,type:varchar(255),unique"  json:"jti"`
	Subject         string     `bun:"subject,type:text"             json:"subject"`
	IssuedAt        time.Time  `bun:"issued_at,nullzero,notnull,default:current_timestamp" json:"issued_at"`
	ExpiresAt       time.Time  `bun:"expires_at,nullzero,notnull"   json:"expires_at"`
	TTLSeconds      int        `bun:"ttl_seconds"                   json:"ttl_seconds"`
	Scopes          []string   `bun:"scopes,array"                  json:"scopes"`
	IsRevoked       bool       `bun:"is_revoked"                    json:"is_revoked"`
	RevokedAt       *time.Time `bun:"revoked_at"                    json:"revoked_at,omitempty"`
	RevokeReason    string     `bun:"revoke_reason,type:text"       json:"revoke_reason,omitempty"`
	GrantType       GrantType  `bun:"grant_type,type:varchar(50)"   json:"grant_type"`
	DelegationDepth int        `bun:"delegation_depth"              json:"delegation_depth"`
	ParentJTI       string     `bun:"parent_jti,type:varchar(255)"  json:"parent_jti,omitempty"`
	// DelegatedByWIMSEURI records the orchestrator that delegated authority (RFC 8693 token_exchange).
	DelegatedByWIMSEURI string `bun:"delegated_by_wimse_uri,type:text" json:"delegated_by_wimse_uri,omitempty"`
	// DRMHash binds the credential to the SHA-256 of the DRM document
	// active at issuance (issue #59). Empty when no DRM is configured for
	// the tenant. Indexed for policy_drift detection.
	DRMHash string `bun:"drm_hash,type:varchar(80)" json:"drm_hash,omitempty"`
	// ConstraintCatalogHash binds the credential to the SHA-256 of the
	// Constraint Catalog document active at issuance (issue #59). Empty
	// when no catalog is configured for the tenant.
	ConstraintCatalogHash string `bun:"constraint_catalog_hash,type:varchar(80)" json:"constraint_catalog_hash,omitempty"`
	// MissionID is a stable, opaque identifier for a delegation tree —
	// equal to the root credential's JTI today; consumers MUST treat it
	// as opaque so the population scheme can evolve. Denormalised onto
	// every credential in the tree so workflow-scoped audit queries are
	// O(1) instead of walking the parent_jti chain. Issue #81.
	MissionID string `bun:"mission_id,type:varchar(255),nullzero" json:"mission_id,omitempty"`
	// DPoPKeyThumbprint is the base64url JWK thumbprint (RFC 7638 SHA-256) of
	// the DPoP key bound to this credential (RFC 9449 §6.1). Empty for plain
	// Bearer tokens. When non-empty, the access token carries a cnf.jkt claim
	// and must be presented with a valid DPoP proof at the protected resource.
	DPoPKeyThumbprint string `bun:"dpop_key_thumbprint,type:text" json:"dpop_key_thumbprint,omitempty"`
	// AuditRetentionUntil is the evidence clock, decoupled from ExpiresAt
	// (the operational clock): how long the row remains queryable so the
	// delegation graph (parent_jti walks, mission_id aggregates) survives
	// token expiry. The cleanup worker prunes on this, not ExpiresAt. Nil on
	// rows written before migration 037; those fall back to the legacy
	// expires_at prune rule.
	AuditRetentionUntil *time.Time `bun:"audit_retention_until" json:"audit_retention_until,omitempty"`
}
