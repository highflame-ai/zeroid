// Package domain defines the core types for ZeroID — the identity layer for
// autonomous agents and non-human workloads.
package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// ErrIdentityExpired is returned by every issuance path (chokepoint
// IssueCredential, GenerateProofToken, attestation post-issuance, agent
// rotate-key) when the target identity has aged out. Service-layer
// callers wrap with %w so handlers can errors.Is and consistently map to
// a 4xx — OAuth flows emit invalid_grant, admin endpoints emit 400.
var ErrIdentityExpired = errors.New("identity_expired")

// ErrIdentityNotUsable is returned by the same paths when the identity
// is suspended or deactivated. Same handler-mapping pattern.
var ErrIdentityNotUsable = errors.New("identity is not usable")

// ErrCredentialExpired is returned by IssueCredential when a per-credential
// time bound (typically API key sk.ExpiresAt) has already passed. Same
// handler-mapping pattern as the identity sentinels above — wrap with %w
// at the service layer so handlers can errors.Is and map to 4xx.
var ErrCredentialExpired = errors.New("credential_expired")

// ──────────────────────────────────────────────────────────────────────────────
// Trust Level
// ──────────────────────────────────────────────────────────────────────────────

// TrustLevel represents the verified trust level of an identity.
// Trust levels advance through attestation: unverified → verified_third_party → first_party.
// Applies to all identity types — agents, applications, MCP servers, services.
type TrustLevel string

const (
	TrustLevelFirstParty         TrustLevel = "first_party"
	TrustLevelVerifiedThirdParty TrustLevel = "verified_third_party"
	TrustLevelUnverified         TrustLevel = "unverified"
)

func (t TrustLevel) Valid() bool {
	switch t {
	case TrustLevelFirstParty, TrustLevelVerifiedThirdParty, TrustLevelUnverified:
		return true
	}
	return false
}

// TrustLevelRank returns a numeric rank for trust level ordering.
// Higher rank = higher trust. Used for >= comparisons in policy enforcement.
func TrustLevelRank(level string) int {
	switch TrustLevel(level) {
	case TrustLevelUnverified:
		return 0
	case TrustLevelVerifiedThirdParty:
		return 1
	case TrustLevelFirstParty:
		return 2
	default:
		return -1
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Identity Type
// ──────────────────────────────────────────────────────────────────────────────

// IdentityType classifies the kind of identity registered in ZeroID.
type IdentityType string

const (
	IdentityTypeAgent       IdentityType = "agent"
	IdentityTypeApplication IdentityType = "application"
	IdentityTypeMCPServer   IdentityType = "mcp_server"
	IdentityTypeService     IdentityType = "service"
)

func (t IdentityType) Valid() bool {
	switch t {
	case IdentityTypeAgent, IdentityTypeApplication, IdentityTypeMCPServer, IdentityTypeService:
		return true
	}
	return false
}

// ──────────────────────────────────────────────────────────────────────────────
// Sub Type — role within an identity type
// ──────────────────────────────────────────────────────────────────────────────

// SubType classifies the operational role within an identity type.
// Sub types are validated against their parent identity type at the service layer.
type SubType string

const (
	// Agent sub-types.
	SubTypeOrchestrator SubType = "orchestrator"
	SubTypeAutonomous   SubType = "autonomous"
	SubTypeToolAgent    SubType = "tool_agent"
	SubTypeHumanProxy   SubType = "human_proxy"
	SubTypeEvaluator    SubType = "evaluator"

	// Application sub-types.
	SubTypeChatbot    SubType = "chatbot"
	SubTypeAssistant  SubType = "assistant"
	SubTypeAPIService SubType = "api_service"
	SubTypeCustom     SubType = "custom"
	SubTypeCodeAgent  SubType = "code_agent"

	// Service sub-types.
	SubTypeLLMProvider SubType = "llm_provider"
)

// agentSubTypes is the set of sub-types valid for identity_type = "agent".
var agentSubTypes = map[SubType]bool{
	SubTypeOrchestrator: true,
	SubTypeAutonomous:   true,
	SubTypeToolAgent:    true,
	SubTypeHumanProxy:   true,
	SubTypeEvaluator:    true,
}

// applicationSubTypes is the set of sub-types valid for identity_type = "application".
var applicationSubTypes = map[SubType]bool{
	SubTypeChatbot:    true,
	SubTypeAssistant:  true,
	SubTypeAPIService: true,
	SubTypeCustom:     true,
	SubTypeCodeAgent:  true,
}

// serviceSubTypes is the set of sub-types valid for identity_type = "service".
var serviceSubTypes = map[SubType]bool{
	SubTypeLLMProvider: true,
}

// ValidForIdentityType reports whether s is a valid sub-type for the given identity type.
// Empty sub-type is always valid (no sub-classification).
func (s SubType) ValidForIdentityType(t IdentityType) bool {
	if s == "" {
		return true
	}
	switch t {
	case IdentityTypeAgent:
		return agentSubTypes[s]
	case IdentityTypeApplication:
		return applicationSubTypes[s]
	case IdentityTypeMCPServer:
		return s == ""
	case IdentityTypeService:
		return serviceSubTypes[s]
	default:
		return false
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Identity Status — lifecycle state machine
// ──────────────────────────────────────────────────────────────────────────────

// IdentityStatus represents the lifecycle state of an identity.
//
// State machine:
//
//	pending → active → suspended → active (reactivation)
//	                 → deactivated (terminal)
//	pending → deactivated (registration rejected)
type IdentityStatus string

const (
	IdentityStatusPending     IdentityStatus = "pending"
	IdentityStatusActive      IdentityStatus = "active"
	IdentityStatusSuspended   IdentityStatus = "suspended"
	IdentityStatusDeactivated IdentityStatus = "deactivated"
)

func (s IdentityStatus) Valid() bool {
	switch s {
	case IdentityStatusPending, IdentityStatusActive, IdentityStatusSuspended, IdentityStatusDeactivated:
		return true
	}
	return false
}

// CanTransitionTo reports whether the identity can move from its current status to the target.
func (s IdentityStatus) CanTransitionTo(target IdentityStatus) bool {
	switch s {
	case IdentityStatusPending:
		return target == IdentityStatusActive || target == IdentityStatusDeactivated
	case IdentityStatusActive:
		return target == IdentityStatusSuspended || target == IdentityStatusDeactivated
	case IdentityStatusSuspended:
		return target == IdentityStatusActive || target == IdentityStatusDeactivated
	case IdentityStatusDeactivated:
		return target == IdentityStatusActive
	default:
		return false
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Risk + assurance metadata enums (CoSAI §3.2 capability–risk matrix +
// NIST SP 800-63 Identity Assurance Levels referenced in CoSAI §3.5).
// Empty string is the "unclassified" default and is always valid.
// ──────────────────────────────────────────────────────────────────────────────

const (
	CapabilityTierLow  = "low"
	CapabilityTierHigh = "high"

	RiskTierLow  = "low"
	RiskTierHigh = "high"

	IAL1 = "ial1"
	IAL2 = "ial2"
	IAL3 = "ial3"
)

// ValidCapabilityTier reports whether v is a valid CapabilityTier value.
// Empty string is allowed and means "unclassified."
func ValidCapabilityTier(v string) bool {
	switch v {
	case "", CapabilityTierLow, CapabilityTierHigh:
		return true
	}
	return false
}

// ValidRiskTier reports whether v is a valid RiskTier value.
// Empty string is allowed and means "unclassified."
func ValidRiskTier(v string) bool {
	switch v {
	case "", RiskTierLow, RiskTierHigh:
		return true
	}
	return false
}

// ValidIAL reports whether v is a valid IAL (Identity Assurance Level).
// Empty string is allowed and means "unclassified."
func ValidIAL(v string) bool {
	switch v {
	case "", IAL1, IAL2, IAL3:
		return true
	}
	return false
}

// IsUsable reports whether an identity in this status can authenticate and receive tokens.
func (s IdentityStatus) IsUsable() bool {
	return s == IdentityStatusActive
}

// ──────────────────────────────────────────────────────────────────────────────
// Identity — the core model
// ──────────────────────────────────────────────────────────────────────────────

// Identity represents a registered identity in ZeroID — agents, applications, MCP servers,
// or internal services. This is the single source of truth for all identity metadata.
//
// Each identity is scoped to an (account_id, project_id, external_id) triple and carries
// a stable WIMSE URI used as the JWT subject claim in all issued credentials.
type Identity struct {
	bun.BaseModel `bun:"table:identities,alias:i"`

	ID         string `bun:"id,pk,type:uuid"               json:"id"`
	AccountID  string `bun:"account_id,type:varchar(255)"   json:"account_id"`
	ProjectID  string `bun:"project_id,type:varchar(255)"   json:"project_id"`
	ExternalID string `bun:"external_id,type:varchar(255)"  json:"external_id"`
	Name       string `bun:"name,type:varchar(255)"         json:"name"`
	WIMSEURI   string `bun:"wimse_uri,type:text"            json:"wimse_uri"`

	// Classification
	IdentityType IdentityType   `bun:"identity_type,type:varchar(50)" json:"identity_type"`
	SubType      SubType        `bun:"sub_type,type:varchar(50)"      json:"sub_type,omitempty"`
	TrustLevel   TrustLevel     `bun:"trust_level,type:varchar(50)"   json:"trust_level"`
	Status       IdentityStatus `bun:"status,type:varchar(50)"        json:"status"`

	// Ownership and governance.
	//
	// CredentialPolicyID is the identity policy — the authority ceiling for
	// every credential this identity can hold. Scopes, TTL, grant types,
	// delegation depth, trust level, and attestation all resolve through this
	// policy at token issuance time. API keys may carry their own (narrower)
	// policy for per-credential restriction; the effective authority is the
	// intersection of both (AWS/GCP/Azure pattern).
	//
	// Nullable only during the rollout of migration 008. After backfill every
	// identity points at the tenant's default policy unless the creator chose
	// a more specific one.
	//
	// AllowedScopes is deprecated in favour of the identity policy's
	// allowed_scopes. It is still read as a fallback during the deprecation
	// window when the identity policy does not restrict scopes (i.e. the
	// policy's allowed_scopes is empty). New code should set the scope
	// ceiling on the policy, not on the identity row.
	OwnerUserID        string   `bun:"owner_user_id,type:varchar(255)" json:"owner_user_id"`
	CredentialPolicyID string   `bun:"credential_policy_id,type:uuid,nullzero" json:"credential_policy_id,omitempty"`
	AllowedScopes      []string `bun:"allowed_scopes,array"            json:"allowed_scopes"` // Deprecated: set scopes on the identity's credential policy instead.
	PublicKeyPEM       string   `bun:"public_key_pem,type:text"        json:"public_key_pem,omitempty"`

	// Identity metadata — embedded into JWT claims for downstream services.
	Framework    string          `bun:"framework,type:varchar(100)"  json:"framework,omitempty"`
	Version      string          `bun:"version,type:varchar(50)"     json:"version,omitempty"`
	Publisher    string          `bun:"publisher,type:varchar(255)"  json:"publisher,omitempty"`
	Description  string          `bun:"description,type:text"        json:"description,omitempty"`
	Capabilities json.RawMessage `bun:"capabilities,type:jsonb"      json:"capabilities"`
	Labels       json.RawMessage `bun:"labels,type:jsonb"            json:"labels"`
	// Metadata is opaque product-specific data (UI hints, config).
	// It is never embedded in issued tokens. For authorization-relevant
	// data, use AllowedScopes or Capabilities.
	Metadata json.RawMessage `bun:"metadata,type:jsonb"          json:"metadata"`

	// Risk + assurance metadata. Optional classification fields aligned with
	// vendor-neutral standards bodies; consumed by future default-policy
	// selection (e.g. shorter TTL for high-risk agents, mandatory attestation
	// above IAL-2). Empty string means "unclassified" and is the safe default
	// for existing rows.
	//
	// CapabilityTier and RiskTier follow the CoSAI Agentic IAM §3.2
	// capability–risk matrix (low × high crossed both axes).
	// IAL follows NIST SP 800-63 Identity Assurance Levels (referenced in
	// CoSAI §3.5).
	//
	// Spec: https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agentic-identity-and-access-control.md
	//
	// `nullzero` so an empty Go string round-trips as SQL NULL — the CHECK
	// constraint on each column accepts NULL or one of the enum values, so
	// "" would otherwise violate it.
	CapabilityTier string `bun:"capability_tier,type:varchar(20),nullzero" json:"capability_tier,omitempty"`
	RiskTier       string `bun:"risk_tier,type:varchar(20),nullzero"       json:"risk_tier,omitempty"`
	IAL            string `bun:"ial,type:varchar(20),nullzero"             json:"ial,omitempty"`

	// ExpiresAt time-bounds the grant of authority itself (NOT the JWT it
	// issues). NULL means "no expiry" — the historical default. When set,
	// IssueCredential rejects new tokens past this time and the cleanup
	// worker sweeps the identity into status=deactivated.
	ExpiresAt *time.Time `bun:"expires_at" json:"expires_at,omitempty"`

	// Lifecycle
	CreatedBy  string    `bun:"created_by,type:varchar(255)"   json:"created_by,omitempty"`
	ModifiedBy string    `bun:"modified_by,type:varchar(255)"  json:"modified_by,omitempty"`
	CreatedAt  time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt  time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}

// IsExpired reports whether the identity's authority has aged out. A nil
// ExpiresAt means "no expiry" and is never expired.
func (i *Identity) IsExpired() bool {
	if i == nil || i.ExpiresAt == nil {
		return false
	}
	return !time.Now().Before(*i.ExpiresAt)
}

// ──────────────────────────────────────────────────────────────────────────────
// Identity Schema — describes valid types, sub-types, trust levels, and statuses.
// Served by GET {AdminPathPrefix}/identities/schema so frontends stay in sync.
// ──────────────────────────────────────────────────────────────────────────────

// SchemaOption describes a single valid enum value.
type SchemaOption struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// IdentityTypeSchema describes an identity type and its valid sub-types.
type IdentityTypeSchema struct {
	Value       string         `json:"value"`
	Label       string         `json:"label"`
	Description string         `json:"description"`
	SubTypes    []SchemaOption `json:"sub_types"`
}

// IdentitySchema is the full schema returned by the schema endpoint.
type IdentitySchema struct {
	IdentityTypes []IdentityTypeSchema `json:"identity_types"`
	TrustLevels   []SchemaOption       `json:"trust_levels"`
	Statuses      []SchemaOption       `json:"statuses"`
}

// GetIdentitySchema returns the canonical identity schema.
func GetIdentitySchema() *IdentitySchema {
	return &IdentitySchema{
		IdentityTypes: []IdentityTypeSchema{
			{
				Value:       string(IdentityTypeAgent),
				Label:       "AI Agent",
				Description: "Autonomous non-human identity with its own trust level and capabilities",
				SubTypes: []SchemaOption{
					{Value: string(SubTypeOrchestrator), Label: "Orchestrator", Description: "Coordinates sub-agents and workflows"},
					{Value: string(SubTypeAutonomous), Label: "Autonomous", Description: "Self-directed agent with minimal oversight"},
					{Value: string(SubTypeToolAgent), Label: "Tool Agent", Description: "Single-purpose tool execution agent"},
					{Value: string(SubTypeHumanProxy), Label: "Human Proxy", Description: "Acts on behalf of a human user"},
					{Value: string(SubTypeEvaluator), Label: "Evaluator", Description: "Judges, scores, or evaluates other agents"},
				},
			},
			{
				Value:       string(IdentityTypeApplication),
				Label:       "Application",
				Description: "User-built application that calls ZeroID-protected APIs",
				SubTypes: []SchemaOption{
					{Value: string(SubTypeChatbot), Label: "Chatbot", Description: "Conversational chat interface"},
					{Value: string(SubTypeAssistant), Label: "Assistant", Description: "AI-powered assistant"},
					{Value: string(SubTypeAPIService), Label: "API Service", Description: "Backend service or API"},
					{Value: string(SubTypeCodeAgent), Label: "Code Agent", Description: "Code generation or analysis agent"},
					{Value: string(SubTypeCustom), Label: "Custom", Description: "Custom application type"},
				},
			},
			{
				Value:       string(IdentityTypeMCPServer),
				Label:       "MCP Server",
				Description: "Model Context Protocol tool server",
				SubTypes:    []SchemaOption{},
			},
			{
				Value:       string(IdentityTypeService),
				Label:       "Service",
				Description: "Internal service or platform-level identity",
				SubTypes: []SchemaOption{
					{Value: string(SubTypeLLMProvider), Label: "LLM Provider", Description: "Upstream LLM provider (OpenAI, Anthropic, Azure OpenAI)"},
				},
			},
		},
		TrustLevels: []SchemaOption{
			{Value: string(TrustLevelFirstParty), Label: "First Party", Description: "Your own trusted identities — full access"},
			{Value: string(TrustLevelVerifiedThirdParty), Label: "Verified Third Party", Description: "Audited external identities — elevated access"},
			{Value: string(TrustLevelUnverified), Label: "Unverified", Description: "Unknown identities — restricted access"},
		},
		Statuses: []SchemaOption{
			{Value: string(IdentityStatusPending), Label: "Pending", Description: "Awaiting activation"},
			{Value: string(IdentityStatusActive), Label: "Active", Description: "Fully operational"},
			{Value: string(IdentityStatusSuspended), Label: "Suspended", Description: "Temporarily disabled"},
			{Value: string(IdentityStatusDeactivated), Label: "Deactivated", Description: "Permanently disabled"},
		},
	}
}

// MaxSPIFFEIDBytes is the SPIFFE §2.4 hard cap. The spec says SPIFFE IDs
// MUST NOT exceed 2048 bytes. Today's varchar(255) schema caps the
// assembled URI at ~1080 bytes so this is unreachable through the API
// surface, but the invariant belongs at the construction site so a future
// schema relaxation can't silently mint non-conformant SPIFFE IDs.
const MaxSPIFFEIDBytes = 2048

// ErrSPIFFEIDTooLong is returned by BuildWIMSEURI when the assembled URI
// exceeds MaxSPIFFEIDBytes. Callers can branch on this with errors.Is to
// distinguish the cap-exceeded case from generic build failures.
var ErrSPIFFEIDTooLong = errors.New("SPIFFE ID exceeds maximum length")

// BuildWIMSEURI constructs the WIMSE URI for an identity:
// spiffe://{domain}/{account_id}/{project_id}/{identity_type}/{external_id}.
// Returns ErrSPIFFEIDTooLong if the result exceeds MaxSPIFFEIDBytes — once
// persisted, every downstream system inherits a non-conformant subject claim.
func BuildWIMSEURI(wimseDomain, accountID, projectID string, identityType IdentityType, externalID string) (string, error) {
	uri := fmt.Sprintf("spiffe://%s/%s/%s/%s/%s", wimseDomain, accountID, projectID, identityType, externalID)
	if n := len(uri); n > MaxSPIFFEIDBytes {
		return "", fmt.Errorf("%w: got %d bytes, max %d: %.64q", ErrSPIFFEIDTooLong, n, MaxSPIFFEIDBytes, uri)
	}
	return uri, nil
}

// ValidateSPIFFEPathSegment rejects values that wouldn't survive a round-trip
// through a strict SPIFFE parser (§2.3 — letters, digits, dot, dash,
// underscore). Run this on anything destined for BuildWIMSEURI; once stored,
// the URI is durable and we don't re-check on read.
func ValidateSPIFFEPathSegment(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return fmt.Errorf("%s contains character %q not allowed in a SPIFFE path segment (allowed: a-z A-Z 0-9 . - _)", field, r)
		}
	}
	return nil
}
