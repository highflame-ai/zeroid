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
	}
}

// CredentialPolicy defines governance constraints enforced at token issuance time.
// Policies are reusable templates assigned to API keys via credential_policy_id.
// When an API key is used for token exchange, ZeroID checks all six constraints
// before signing the JWT.
type CredentialPolicy struct {
	bun.BaseModel `bun:"table:credential_policies,alias:cp"`

	ID                  string    `bun:"id,pk,type:uuid"                  json:"id"`
	AccountID           string    `bun:"account_id,type:varchar(255)"     json:"account_id"`
	ProjectID           string    `bun:"project_id,type:varchar(255)"     json:"project_id"`
	Name                string    `bun:"name,type:varchar(255)"           json:"name"`
	Description         string    `bun:"description,type:text"            json:"description,omitempty"`
	MaxTTLSeconds       int       `bun:"max_ttl_seconds"                  json:"max_ttl_seconds"`
	AllowedGrantTypes   []string  `bun:"allowed_grant_types,array"        json:"allowed_grant_types"`
	AllowedScopes       []string  `bun:"allowed_scopes,array"             json:"allowed_scopes,omitempty"`
	RequiredTrustLevel  string    `bun:"required_trust_level,type:varchar(50)"  json:"required_trust_level,omitempty"`
	RequiredAttestation string    `bun:"required_attestation,type:varchar(50)"  json:"required_attestation,omitempty"`
	MaxDelegationDepth  int       `bun:"max_delegation_depth"             json:"max_delegation_depth"`
	IsActive            bool      `bun:"is_active"                        json:"is_active"`
	CreatedAt           time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt           time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}
