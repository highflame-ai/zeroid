package domain

import (
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

// TokenClaims represents the claims embedded in an issued JWT.
type TokenClaims struct {
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  []string  `json:"aud,omitempty"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	JWTID     string    `json:"jti"`
	AccountID string    `json:"account_id"`
	ProjectID string    `json:"project_id"`

	// Identity claims — canonical names.
	ExternalID   string `json:"external_id,omitempty"`
	IdentityType string `json:"identity_type,omitempty"`
	SubType      string `json:"sub_type,omitempty"`
	TrustLevel   string `json:"trust_level,omitempty"`
	Status       string `json:"status,omitempty"`
	Name         string `json:"name,omitempty"`

	// Auth context.
	UserID          string   `json:"user_id,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	GrantType       string   `json:"grant_type,omitempty"`
	DelegationDepth int      `json:"delegation_depth,omitempty"`

	// Identity metadata — embedded so downstream services
	// can make decisions without calling back to ZeroID.
	Framework    string          `json:"framework,omitempty"`
	Version      string          `json:"version,omitempty"`
	Publisher    string          `json:"publisher,omitempty"`
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
	ActorClaims  *ActorClaims    `json:"act,omitempty"`
}

// ActorClaims represents the nested "act" claim in delegated tokens (RFC 8693).
type ActorClaims struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss,omitempty"`
}

// AccessToken is the RFC 6749 §5.1 token response returned to the caller after issuance.
type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"` // "Bearer"
	ExpiresIn   int    `json:"expires_in"` // seconds
	Scope       string `json:"scope,omitempty"`
	JTI         string `json:"jti"`
	IssuedAt    int64  `json:"iat"`
	// Convenience fields — duplicated from JWT so callers don't need to decode.
	AccountID    string `json:"account_id,omitempty"`
	ProjectID    string `json:"project_id,omitempty"`
	ExternalID   string `json:"external_id,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// OAuthClient represents a registered OAuth2 client scoped to a tenant.
// The ClientSecret field stores a bcrypt hash and is never serialised to JSON.
// For public clients (PKCE), ClientSecret is empty.
type OAuthClient struct {
	bun.BaseModel `bun:"table:oauth_clients"`

	ID           string    `bun:"id,pk"             json:"id"`
	AccountID    string    `bun:"account_id"        json:"account_id"`
	ProjectID    string    `bun:"project_id"        json:"project_id"`
	ClientID     string    `bun:"client_id"         json:"client_id"`
	ClientSecret string    `bun:"client_secret"     json:"-"`
	Name         string    `bun:"name"              json:"name"`
	IdentityID   string    `bun:"identity_id,nullzero" json:"identity_id,omitempty"`
	GrantTypes   []string  `bun:"grant_types,array" json:"grant_types"`
	RedirectURIs []string  `bun:"redirect_uris,array" json:"redirect_uris"`
	Scopes       []string  `bun:"scopes,array"      json:"scopes"`
	IsActive     bool      `bun:"is_active"         json:"is_active"`
	CreatedAt    time.Time `bun:"created_at"        json:"created_at"`
	UpdatedAt    time.Time `bun:"updated_at"        json:"updated_at"`
}

// ProofToken represents a persisted WIMSE Proof Token (WPT).
// WPTs are single-use; the nonce column has a DB UNIQUE constraint that provides
// atomic replay prevention without a separate pre-check query.
type ProofToken struct {
	bun.BaseModel `bun:"table:proof_tokens"`

	ID         string     `bun:"id,pk"          json:"id"`
	IdentityID string     `bun:"identity_id"    json:"identity_id"`
	AccountID  string     `bun:"account_id"     json:"account_id"`
	ProjectID  string     `bun:"project_id"     json:"project_id"`
	JTI        string     `bun:"jti"            json:"jti"`
	Nonce      string     `bun:"nonce"          json:"nonce"`
	Audience   string     `bun:"audience"       json:"audience"`
	IssuedAt   time.Time  `bun:"issued_at"      json:"issued_at"`
	ExpiresAt  time.Time  `bun:"expires_at"     json:"expires_at"`
	IsUsed     bool       `bun:"is_used"        json:"is_used"`
	UsedAt     *time.Time `bun:"used_at"        json:"used_at,omitempty"`
	CreatedAt  time.Time  `bun:"created_at"     json:"created_at"`
}
