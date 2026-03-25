package domain

import (
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

// API key states.
const (
	APIKeyStateActive  = "active"
	APIKeyStateRevoked = "revoked"
	APIKeyStateExpired = "expired"
)

// API key prefixes.
const (
	APIKeyPrefix     = "zid_sk"
	APIKeyByteLength = 24
)

// APIKey represents an API key used for SDK/CLI authentication.
// Keys are SHA-256 hashed — plaintext is shown once at creation, never stored.
type APIKey struct {
	bun.BaseModel `bun:"table:service_keys,alias:sk"`

	ID                 string          `bun:"id,pk,type:uuid"          json:"id"`
	Name               string          `bun:"name"                     json:"name"`
	Description        string          `bun:"description"              json:"description"`
	KeyPrefix          string          `bun:"key_prefix"               json:"key_prefix"`
	KeyHash            string          `bun:"key_hash,unique"          json:"-"`
	KeyVersion         int             `bun:"key_version"              json:"key_version"`
	AccountID          string          `bun:"account_id"               json:"account_id"`
	ProjectID          string          `bun:"project_id"               json:"project_id"`
	IdentityID         string          `bun:"identity_id,type:uuid"    json:"identity_id"`
	CreatedBy          string          `bun:"created_by"               json:"created_by"`
	Scopes             []string        `bun:"scopes,array"             json:"scopes"`
	Product            string          `bun:"product"                  json:"product"`
	Environment        string          `bun:"environment"              json:"environment"`
	ExpiresAt          *time.Time      `bun:"expires_at"               json:"expires_at,omitempty"`
	State              string          `bun:"state"                    json:"state"`
	RevokedAt          *time.Time      `bun:"revoked_at"               json:"revoked_at,omitempty"`
	RevokedBy          string          `bun:"revoked_by"               json:"revoked_by,omitempty"`
	RevokeReason       string          `bun:"revoke_reason"            json:"revoke_reason,omitempty"`
	LastUsedAt         *time.Time      `bun:"last_used_at"             json:"last_used_at,omitempty"`
	LastUsedIP         string          `bun:"last_used_ip"             json:"last_used_ip,omitempty"`
	UsageCount         int64           `bun:"usage_count"              json:"usage_count"`
	Metadata           json.RawMessage `bun:"metadata,type:jsonb"      json:"metadata,omitempty"`
	IPAllowlist        []string        `bun:"ip_allowlist,array"       json:"ip_allowlist,omitempty"`
	CredentialPolicyID string          `bun:"credential_policy_id,type:uuid" json:"credential_policy_id"`
	RateLimitRPS       int             `bun:"rate_limit_rps"           json:"rate_limit_rps,omitempty"`
	ReplacedBy         string          `bun:"replaced_by,type:uuid,nullzero" json:"replaced_by,omitempty"`
	CreatedAt          time.Time       `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt          time.Time       `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}
