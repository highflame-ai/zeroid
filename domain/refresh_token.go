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
	// DPoPKeyThumbprint is the base64url JWK thumbprint (RFC 7638) of the
	// DPoP key the refresh token is bound to. NULL/empty ⇒ unbound (Bearer).
	// Copied verbatim onto every successor row on rotation; checked against
	// the presented proof inside the rotation transaction (RFC 9449 §5).
	DPoPKeyThumbprint string `bun:"dpop_key_thumbprint,nullzero" json:"-"`
	// MissionID is the delegation-tree identifier (issue #81) of the access
	// token this refresh family was minted alongside. Copied verbatim onto
	// every successor row on rotation and read back when the refresh grant
	// issues a new access token, so a refreshed token inherits the original
	// mission instead of re-rooting it. nullzero ⇒ empty Go string round-trips
	// as SQL NULL (pre-migration families, or flows that carried no mission_id);
	// the refresh path falls back to re-rooting for those. Opaque to consumers.
	MissionID string `bun:"mission_id,nullzero" json:"mission_id,omitempty"`
	// Audience is the server-recognized audience-profile name (e.g. "codeoid")
	// this refresh family was issued for by the external-principal exchange.
	// Copied verbatim onto every successor row on rotation and read back when
	// the refresh grant issues a new access token, so the refreshed token
	// carries the SAME `aud` claim (and profile scopes) as the original —
	// essential for a harness daemon that validates `aud` on every message.
	// Empty (nullzero ⇒ SQL NULL) ⇒ a normal refresh token (authorization_code
	// flow, or any pre-migration family): rotation is unchanged, no `aud`.
	Audience string `bun:"audience,nullzero" json:"audience,omitempty"`
	// Resources is the RFC 8707 resource CEILING this refresh family was issued
	// for (CAP-IDN-027). Copied verbatim onto every successor row on rotation
	// and read back when the refresh grant mints a new access token, so the
	// binding survives rotation instead of silently vanishing — which is what
	// made suppressing the refresh token necessary before this existed.
	//
	// A refresh that names `resource` must select a subset of this. One that
	// omits it re-stamps the ceiling when the ceiling holds exactly one value,
	// and is refused when it holds more — so raising the authorize-leg
	// cardinality cap can never quietly begin minting multi-audience tokens.
	//
	// Empty (nullzero ⇒ SQL NULL) ⇒ no binding on this family: the ordinary
	// authorization_code flow and every pre-migration row, whose rotation is
	// unchanged and whose successors carry no `resource` claim.
	//
	// TEXT[] though the ceiling is single-valued today: cardinality is a
	// constant, not a shape (ADR 0037 D2).
	Resources []string `bun:"resource,array,nullzero" json:"resource,omitempty"`
}
