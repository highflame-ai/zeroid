package domain

import (
	"time"

	"github.com/uptrace/bun"
)

// Refresh token constants.
const (
	RefreshTokenPrefix       = "zid_rt"
	RefreshTokenByteLength   = 32
	RefreshTokenTTLDays      = 90
	RefreshTokenStateActive  = "active"
	RefreshTokenStateRevoked = "revoked"

	// RefreshTokenReuseGraceWindow is how long after a token is revoked that a
	// subsequent presentation is treated as a concurrent retry rather than a
	// replay attack. Within this window, family revocation is suppressed so
	// legitimate multi-tab or network-retry scenarios don't kill the session.
	// Outside the window, reuse detection fires as normal (RFC 6749 §10.4).
	RefreshTokenReuseGraceWindow = 10 * time.Second
)

// RefreshToken is the Bun model for the refresh_tokens table.
type RefreshToken struct {
	bun.BaseModel `bun:"table:refresh_tokens,alias:rt"`

	ID         string     `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	TokenHash  string     `bun:"token_hash,notnull,unique"                 json:"-"`
	ClientID   string     `bun:"client_id,notnull"                         json:"client_id"`
	AccountID  string     `bun:"account_id,notnull"                        json:"account_id"`
	ProjectID  string     `bun:"project_id"                                json:"project_id"`
	UserID     string     `bun:"user_id,notnull"                           json:"user_id"`
	IdentityID *string    `bun:"identity_id,type:uuid"                     json:"identity_id,omitempty"`
	Scopes     string     `bun:"scopes"                                    json:"scopes"`
	FamilyID   string     `bun:"family_id,type:uuid,notnull"               json:"family_id"`
	State      string     `bun:"state,notnull,default:'active'"            json:"state"`
	ExpiresAt  time.Time  `bun:"type:timestamptz,notnull"                  json:"expires_at"`
	RevokedAt  *time.Time `bun:"revoked_at"                                json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `bun:"type:timestamptz,notnull,default:current_timestamp" json:"created_at"`
}
