package domain

import (
	"time"

	"github.com/uptrace/bun"
)

// SigningCredential is a workload-attested ephemeral signing key. A
// workload generates an Ed25519 keypair in memory and attests the PUBLIC
// half here; ZeroID never sees or stores the private key. See
// migrations/023_signing_credentials.up.sql for the two-clock model.
type SigningCredential struct {
	bun.BaseModel `bun:"table:signing_credentials,alias:sc"`

	ID                  string     `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	AccountID           string     `bun:"account_id"                                json:"account_id,omitempty"`
	ProjectID           string     `bun:"project_id"                                json:"project_id,omitempty"`
	KID                 string     `bun:"kid"                                       json:"kid"`
	Workload            string     `bun:"workload"                                  json:"workload"`
	Purpose             string     `bun:"purpose"                                   json:"purpose"`
	Algorithm           string     `bun:"algorithm"                                 json:"algorithm"`
	PublicKey           string     `bun:"public_key"                                json:"-"` // never logged/returned
	NotAfter            time.Time  `bun:"not_after"                                 json:"not_after"`
	AuditRetentionUntil time.Time  `bun:"audit_retention_until"                     json:"audit_retention_until"`
	Revoked             bool       `bun:"revoked"                                   json:"revoked"`
	RevokedReason       string     `bun:"revoked_reason"                            json:"revoked_reason,omitempty"`
	RevokedAt           *time.Time `bun:"revoked_at"                                json:"revoked_at,omitempty"`
	CreatedAt           time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
}

// Purpose is an opaque, deployer-defined string (e.g. what the attested
// key signs). ZeroID does not enumerate purposes — it is product-
// agnostic; the accepted set comes from SigningCredsConfig.AllowedPurposes
// supplied by the deployment, not from constants here.

// SigningAlgorithmEdDSA is the only supported signing algorithm at launch.
const SigningAlgorithmEdDSA = "EdDSA"

// VerifiableNow reports whether this credential's public key may still be
// used to VERIFY an attestation right now. The rule is the correctness
// crux: a merely-expired key (past NotAfter) still verifies historical
// attestations while inside the audit-retention window; only a *revoked*
// key is rejected outright.
func (c *SigningCredential) VerifiableNow(now time.Time) bool {
	if c.Revoked {
		return false
	}
	return now.Before(c.AuditRetentionUntil)
}

// SignableNow reports whether this key is still within its OPERATIONAL
// window (may be used to produce new signatures). Distinct from
// VerifiableNow — a key stops being signable long before it stops being
// verifiable.
func (c *SigningCredential) SignableNow(now time.Time) bool {
	return !c.Revoked && now.Before(c.NotAfter)
}
