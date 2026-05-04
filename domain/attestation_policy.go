package domain

import (
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

// AttestationPolicy is per-tenant per-proof-type trust configuration.
// A policy row says: "for proof_type X in this tenant, here are the
// accepted issuers/roots/hashes and the rules that must match". No policy
// row means the verifier for that proof type is unconfigured and all
// verification attempts fail closed.
//
// Config is a JSONB blob whose shape depends on ProofType:
//   - oidc_token: OIDCPolicyConfig
//   - image_hash: (not yet implemented) ImageHashPolicyConfig
//   - tpm:        (not yet implemented) TPMPolicyConfig
//
// Storing the proof-type-specific shape inline avoids a separate table per
// verifier and lets new verifiers land without schema changes.
type AttestationPolicy struct {
	bun.BaseModel `bun:"table:attestation_policies,alias:ap"`

	ID        string          `bun:"id,pk,type:uuid"              json:"id"`
	AccountID string          `bun:"account_id,type:varchar(255)" json:"account_id"`
	ProjectID string          `bun:"project_id,type:varchar(255)" json:"project_id"`
	ProofType ProofType       `bun:"proof_type,type:varchar(50)"  json:"proof_type"`
	Config    json.RawMessage `bun:"config,type:jsonb"            json:"config"`
	IsActive  bool            `bun:"is_active"                    json:"is_active"`
	CreatedAt time.Time       `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time       `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}

// OIDCPolicyConfig is the Config payload for proof_type=oidc_token. Defines
// which upstream IdP JWTs are accepted and what claim constraints they must
// satisfy before trust is promoted.
type OIDCPolicyConfig struct {
	// Issuers is the allowlist of trusted OIDC issuers. At least one must
	// match the incoming JWT's iss claim for verification to proceed.
	Issuers []OIDCIssuerConfig `json:"issuers"`
}

// OIDCIssuerConfig describes one trusted OIDC issuer and its constraints.
type OIDCIssuerConfig struct {
	// URL is the issuer URL (matched against the JWT iss claim and used to
	// discover the JWKS endpoint via .well-known/openid-configuration).
	URL string `json:"url"`

	// Audiences, if non-empty, requires the JWT aud claim to contain at
	// least one of these values. Empty disables audience checking.
	Audiences []string `json:"audiences,omitempty"`

	// RequiredClaims are exact-string-match requirements on additional JWT
	// claims. Every key listed must be present on the token and equal the
	// configured value. Use this to bind tokens to a specific workload,
	// e.g. {"repository": "myorg/myrepo", "ref": "refs/heads/main"} for
	// GitHub Actions OIDC.
	RequiredClaims map[string]string `json:"required_claims,omitempty"`
}
