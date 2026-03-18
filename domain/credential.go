package domain

import (
	"time"

	"github.com/uptrace/bun"
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
	"urn:ietf:params:oauth:grant-type:token-exchange":  GrantTypeTokenExchange,
}

// allValidGrantTypes is the set of all recognised canonical short forms.
var allValidGrantTypes = map[GrantType]bool{
	GrantTypeClientCredentials: true,
	GrantTypeJWTBearer:         true,
	GrantTypeTokenExchange:     true,
	GrantTypeAPIKey:            true,
	GrantTypeAuthorizationCode: true,
	GrantTypeRefreshToken:      true,
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
}
