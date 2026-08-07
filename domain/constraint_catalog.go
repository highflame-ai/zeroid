package domain

import (
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

// ConstraintCatalogVersion is the persisted, ES256-signed snapshot of the
// active downstream policy set (e.g. Cedar policies enforced in Shield).
// ZeroID does not parse the document — it hashes the canonical bytes,
// signs them, and rewrites the SignedAt every 24h so consumers of the
// hash claim can detect a stale/replayed catalog.
//
// Multiple rows can share the same Hash (re-sign of unchanged content),
// distinguished by SignedAt. Only Hash is embedded in tokens, so a
// re-sign with identical Hash leaves outstanding tokens valid.
type ConstraintCatalogVersion struct {
	bun.BaseModel `bun:"table:constraint_catalog_versions,alias:ccv"`

	ID           string          `bun:"id,pk,type:uuid"                                       json:"id"`
	AccountID    string          `bun:"account_id,type:varchar(255)"                          json:"account_id"`
	ProjectID    string          `bun:"project_id,type:varchar(255)"                          json:"project_id"`
	Version      string          `bun:"version,type:varchar(64)"                              json:"version"`
	EffectiveAt  time.Time       `bun:"effective_at"                                          json:"effective_at"`
	Document     json.RawMessage `bun:"document,type:jsonb"                                   json:"document"`
	Hash         string          `bun:"hash,type:varchar(80)"                                 json:"hash"`
	SignedAt     time.Time       `bun:"signed_at,nullzero,notnull,default:current_timestamp"  json:"signed_at"`
	Signature    string          `bun:"signature,type:text"                                   json:"signature"`
	SigningKeyID string          `bun:"signing_key_id,type:varchar(255)"                      json:"signing_key_id"`
	CreatedAt    time.Time       `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
}
