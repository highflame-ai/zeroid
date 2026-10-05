package domain

import (
	"time"

	"github.com/uptrace/bun"
)

const (
	// DefaultPolicyName is the well-known name for the auto-created tenant default policy.
	DefaultPolicyName = "default"

	// DefaultPolicyDescription describes the system-created default policy.
	DefaultPolicyDescription = "System default credential policy — applied to agents when no explicit policy is specified"

	// DefaultMaxTTLSeconds is the default token TTL (1 hour).
	DefaultMaxTTLSeconds = 3600

	// DefaultMaxDelegationDepth is the default maximum delegation chain depth.
	// Set generously so out-of-the-box multi-hop agent chains
	// (orchestrator → sub-agent → tool-agent → …) succeed without custom
	// policies. Tenants that require stricter delegation limits attach a
	// narrower policy explicitly. The revocation cascade caps traversal
	// at 50 independently (migration 007).
	DefaultMaxDelegationDepth = 5
)

// DefaultAllowedGrantTypes returns the grant types permitted by the default
// policy. It covers every NHI-facing grant so that out-of-the-box tenants can
// exercise the full OAuth surface without authoring a policy first. Tenants
// who want to restrict grants (e.g. block delegation, disallow API keys)
// must author a custom policy and attach it at identity registration.
//
// authorization_code and refresh_token are omitted because they flow through
// oauth_clients (not identities) and are gated by the client's grant_types.
func DefaultAllowedGrantTypes() []string {
	return []string{
		string(GrantTypeClientCredentials),
		string(GrantTypeAPIKey),
		string(GrantTypeJWTBearer),
		string(GrantTypeTokenExchange),
		// CIBA joined when bound-client redemption started enforcing the
		// identity's credential policy (the anchoring change): without it,
		// every bound client under a tenant-default policy would be refused.
		// NOTE for upgrades: default-policy rows are created once and do not
		// self-heal — tenants whose stored default predates this entry must
		// add the CIBA grant to that policy to use bound-client CIBA.
		string(GrantTypeCIBA),
	}
}

// CredentialPolicy defines governance constraints enforced at token issuance time.
// Policies are reusable templates assigned to API keys via credential_policy_id.
// When an API key is used for token exchange, ZeroID checks all six constraints
// before signing the JWT.
type CredentialPolicy struct {
	bun.BaseModel `bun:"table:credential_policies,alias:cp"`

	ID                  string   `bun:"id,pk,type:uuid"                  json:"id"`
	AccountID           string   `bun:"account_id,type:varchar(255)"     json:"account_id"`
	ProjectID           string   `bun:"project_id,type:varchar(255)"     json:"project_id"`
	Name                string   `bun:"name,type:varchar(255)"           json:"name"`
	Description         string   `bun:"description,type:text"            json:"description,omitempty"`
	MaxTTLSeconds       int      `bun:"max_ttl_seconds"                  json:"max_ttl_seconds"`
	AllowedGrantTypes   []string `bun:"allowed_grant_types,array"        json:"allowed_grant_types"`
	AllowedScopes       []string `bun:"allowed_scopes,array"             json:"allowed_scopes,omitempty"`
	RequiredTrustLevel  string   `bun:"required_trust_level,type:varchar(50)"  json:"required_trust_level,omitempty"`
	RequiredAttestation string   `bun:"required_attestation,type:varchar(50)"  json:"required_attestation,omitempty"`
	MaxDelegationDepth  int      `bun:"max_delegation_depth"             json:"max_delegation_depth"`
	// Source names what created this policy — e.g. "discovery" for one auto-derived
	// at adoption. Empty/NULL for user-authored policies.
	// nullzero: an empty Source must persist as SQL NULL, not '' — the partial
	// indexes key on `source IS NULL` (user policies) vs `IS NOT NULL` (derived).
	Source string `bun:"source,type:varchar(50),nullzero"      json:"source,omitempty"`
	// SourceKey is a derived policy's stable dedup identity WITHIN its source (a
	// posture hash), so re-derivation reuses the same row while the display name
	// stays human-readable. Unique per (account, project, source) when set.
	SourceKey string `bun:"source_key,type:varchar(255),nullzero" json:"source_key,omitempty"`
	IsActive  bool   `bun:"is_active"                    json:"is_active"`
	// ExpiresAt time-bounds the policy. EnforcePolicy treats an expired
	// policy the same as an inactive one — identity policy, per-key policy,
	// or both. NULL means "no expiry".
	ExpiresAt *time.Time `bun:"expires_at"                       json:"expires_at,omitempty"`
	// JWTTyp chooses the access token's JOSE `typ` header under the rfc8693
	// token profile: JWTTypAccessToken (the default when empty, RFC 9068
	// §2.1) or JWTTypJWT for agents whose tokens must stay valid JWT-SVIDs
	// (JWT-SVID §2.3 allows only JWT or JOSE). The two specs disagree and a
	// token can satisfy only one. Ignored under the legacy profile, which
	// always issues JWT.
	JWTTyp string `bun:"jwt_typ,type:varchar(10),nullzero" json:"jwt_typ,omitempty"`
	// RequiredPrincipalType requires that the chain a token belongs to is
	// rooted in a person: "" (any, the default) or "user". Checked for every
	// grant the identity uses, so an agent that requires a user subject can
	// neither mint its own workload token nor accept one in an exchange — the
	// authority-laundering path (P3). "owner" arrives with personal agents.
	RequiredPrincipalType string `bun:"required_principal_type,type:varchar(20),nullzero" json:"required_principal_type,omitempty"`
	// UserGrantScopes caps what this identity may hold for a person — tokens
	// whose principal is a user, held as client or current actor — while
	// AllowedScopes keeps capping its own authority (D10). Empty means no
	// extra cap: the person's own grant bounds the chain. Applied only where
	// that grant is itself bounded (a delegated user chain, ID-JAG,
	// authorization_code and refresh); see IssueRequest.UserGrantBounded.
	UserGrantScopes []string  `bun:"user_grant_scopes,array" json:"user_grant_scopes,omitempty"`
	CreatedAt       time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt       time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}

// Access token `typ` header values a credential policy may choose.
const (
	// JWTTypAccessToken is the RFC 9068 §2.1 type of a JWT access token, and
	// the rfc8693 profile's default.
	JWTTypAccessToken = "at+jwt"
	// JWTTypJWT keeps the token a conformant JWT-SVID (JWT-SVID §2.3), and is
	// what the legacy profile always issues.
	JWTTypJWT = "JWT"
)

// ValidJWTTyp reports whether v is a typ a policy may choose; empty means the
// profile default.
func ValidJWTTyp(v string) bool {
	return v == "" || v == JWTTypAccessToken || v == JWTTypJWT
}

// IsExpired reports whether the policy has aged out. A nil ExpiresAt
// means "no expiry" and is never expired.
func (p *CredentialPolicy) IsExpired() bool {
	if p == nil || p.ExpiresAt == nil {
		return false
	}
	return !time.Now().Before(*p.ExpiresAt)
}
