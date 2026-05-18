package domain

import (
	"errors"
	"time"

	"github.com/uptrace/bun"
)

// ErrDRMUnauthorized signals that the requested delegation (from→to pair,
// scopes, or resource set) is not permitted by the active DRM. Wrapped so
// callers can use errors.Is at the OAuth boundary to translate into an
// invalid_grant response (RFC 8693 §2.2.2).
var ErrDRMUnauthorized = errors.New("delegation not authorized by active decision-rights matrix")

// ErrDRMInvalid indicates the DRM document failed schema validation at
// admission time (missing version, empty allowed_delegations, malformed
// SPIFFE pattern). Surfaces as 400 from the admin handler.
var ErrDRMInvalid = errors.New("invalid decision-rights matrix document")

// DRMAllowedDelegation is one row of the DRM authorization table.
//
// `From` and `To` are SPIFFE URI patterns (`spiffe://domain/.../*` style).
// `Resources` and `Conditions` are kept as opaque maps/strings — the DRM
// is an authorization fence for *which delegations exist*, not a full
// policy engine; Cedar/OPA live downstream in Shield for per-request
// authorization.
type DRMAllowedDelegation struct {
	From       string         `json:"from"`
	To         string         `json:"to"`
	Resources  []string       `json:"resources,omitempty"`
	Conditions map[string]any `json:"conditions,omitempty"`
}

// DRMDocument is the canonical wire/storage shape of a DRM. The Hash
// stored alongside DecisionRightsMatrix is computed over the canonical
// JSON encoding (sorted keys) of this struct.
type DRMDocument struct {
	Version            string                 `json:"version"`
	EffectiveAt        time.Time              `json:"effective_at"`
	ExpiresAt          *time.Time             `json:"expires_at,omitempty"`
	AllowedDelegations []DRMAllowedDelegation `json:"allowed_delegations"`
}

// Validate enforces the minimum schema requirements: version present,
// effective_at set, at least one allowed_delegation, and every delegation
// has a non-empty from/to. We deliberately do not validate the SPIFFE
// pattern syntax here — the governance service does that during the
// authorization check so the failure mode is consistent across writes
// and reads.
func (d DRMDocument) Validate() error {
	if d.Version == "" {
		return errors.New("drm: version is required")
	}
	if d.EffectiveAt.IsZero() {
		return errors.New("drm: effective_at is required")
	}
	if len(d.AllowedDelegations) == 0 {
		return errors.New("drm: allowed_delegations must not be empty")
	}
	for i, rule := range d.AllowedDelegations {
		if rule.From == "" || rule.To == "" {
			return errors.New("drm: allowed_delegations: from and to are required")
		}
		_ = i
	}
	return nil
}

// DecisionRightsMatrix is the persisted DRM row. Rows are immutable —
// the database trigger drm_block_mutation refuses UPDATE/DELETE. A new
// version is published by inserting a new row.
type DecisionRightsMatrix struct {
	bun.BaseModel `bun:"table:decision_rights_matrix,alias:drm"`

	ID          string      `bun:"id,pk,type:uuid"                                       json:"id"`
	AccountID   string      `bun:"account_id,type:varchar(255)"                          json:"account_id"`
	ProjectID   string      `bun:"project_id,type:varchar(255)"                          json:"project_id"`
	Version     string      `bun:"version,type:varchar(64)"                              json:"version"`
	EffectiveAt time.Time   `bun:"effective_at"                                          json:"effective_at"`
	ExpiresAt   *time.Time  `bun:"expires_at"                                            json:"expires_at,omitempty"`
	Document    DRMDocument `bun:"document,type:jsonb"                                   json:"document"`
	Hash        string      `bun:"hash,type:varchar(80)"                                 json:"hash"`
	CreatedAt   time.Time   `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
}
