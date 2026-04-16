package domain

import (
	"time"

	"github.com/uptrace/bun"
)

// AuthCode tracks a consumed authorization code for single-use enforcement
// per RFC 6749 §4.1.2. Auth codes are stateless HS256 JWTs; this record is
// created on first exchange and used to detect replays.
type AuthCode struct {
	bun.BaseModel `bun:"table:auth_codes,alias:ac"`

	JTI             string    `bun:"jti,pk,type:varchar(255)"         json:"jti"`
	ClientID        string    `bun:"client_id,type:varchar(255)"      json:"client_id"`
	AccountID       string    `bun:"account_id,type:varchar(255)"     json:"account_id"`
	ProjectID       string    `bun:"project_id,type:varchar(255)"     json:"project_id"`
	CredentialJTI   *string   `bun:"credential_jti,type:varchar(255)" json:"credential_jti,omitempty"`
	RefreshFamilyID *string   `bun:"refresh_family_id,type:uuid"      json:"refresh_family_id,omitempty"`
	ConsumedAt      time.Time `bun:"consumed_at,nullzero,notnull,default:current_timestamp" json:"consumed_at"`
	ExpiresAt       time.Time `bun:"expires_at,notnull"               json:"expires_at"`
}
