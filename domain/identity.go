// Package domain defines the core types for ZeroID — the identity layer for
// autonomous agents and non-human workloads.
package domain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

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

	// Ownership and governance
	OwnerUserID   string   `bun:"owner_user_id,type:varchar(255)" json:"owner_user_id"`
	AllowedScopes []string `bun:"allowed_scopes,array"            json:"allowed_scopes"`
	PublicKeyPEM  string   `bun:"public_key_pem,type:text"        json:"public_key_pem,omitempty"`

	// Identity metadata — embedded into JWT claims for downstream services.
	Framework    string          `bun:"framework,type:varchar(100)"  json:"framework,omitempty"`
	Version      string          `bun:"version,type:varchar(50)"     json:"version,omitempty"`
	Publisher    string          `bun:"publisher,type:varchar(255)"  json:"publisher,omitempty"`
	Description  string          `bun:"description,type:text"        json:"description,omitempty"`
	Capabilities json.RawMessage `bun:"capabilities,type:jsonb"      json:"capabilities"`
	Labels       json.RawMessage `bun:"labels,type:jsonb"            json:"labels"`
	Metadata     json.RawMessage `bun:"metadata,type:jsonb"          json:"metadata"`

	// Lifecycle
	CreatedBy string    `bun:"created_by,type:varchar(255)"    json:"created_by,omitempty"`
	CreatedAt time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}

// ──────────────────────────────────────────────────────────────────────────────
// Identity Schema — describes valid types, sub-types, trust levels, and statuses.
// Served by GET /api/v1/identities/schema so frontends stay in sync.
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

// BuildWIMSEURI constructs the WIMSE URI for an identity.
// Format: spiffe://{domain}/{account_id}/{project_id}/{identity_type}/{external_id}
func BuildWIMSEURI(wimseDomain, accountID, projectID string, identityType IdentityType, externalID string) string {
	return fmt.Sprintf("spiffe://%s/%s/%s/%s/%s", wimseDomain, accountID, projectID, identityType, externalID)
}
