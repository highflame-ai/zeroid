package domain

import (
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

// DownstreamToken stores an encrypted OAuth token for accessing a third-party
// MCP server on behalf of a specific user. Firehog fetches these tokens at
// request time and injects them into downstream MCP requests.
type DownstreamToken struct {
	bun.BaseModel `bun:"table:downstream_tokens,alias:dt"`

	ID           string          `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	AccountID    string          `bun:"account_id,notnull"                        json:"account_id"`
	ProjectID    string          `bun:"project_id,notnull"                        json:"project_id"`
	UserID       string          `bun:"user_id,notnull"                           json:"user_id"`
	ServerSlug   string          `bun:"server_slug,notnull"                       json:"server_slug"`
	AccessToken  string          `bun:"access_token,notnull"                      json:"-"`
	RefreshToken string          `bun:"refresh_token"                             json:"-"`
	TokenType    string          `bun:"token_type,notnull,default:'Bearer'"       json:"token_type"`
	Scopes       string          `bun:"scopes"                                    json:"scopes"`
	ExpiresAt    *time.Time      `bun:"expires_at"                                json:"expires_at,omitempty"`
	OAuthConfig  json.RawMessage `bun:"oauth_config,type:jsonb"                   json:"-"`
	CreatedAt    time.Time       `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt    time.Time       `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}

// DownstreamTokenStatus is a safe view of a token (no secrets).
type DownstreamTokenStatus struct {
	ServerSlug  string `json:"server_slug"`
	UserID      string `json:"user_id"`
	Connected   bool   `json:"connected"`
	TokenType   string `json:"token_type"`
	Scopes      string `json:"scopes"`
	ConnectedAt string `json:"connected_at"`
}
