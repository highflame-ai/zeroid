// Package domain defines the core types for ZeroID — the identity layer for
// autonomous agents and non-human workloads.
package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
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
// The enum is an ISO/IEC 24760-1 §7.2-shaped identity lifecycle. `discovered`
// sits *below* "Established" — there is no SDO state for a pre-authoritative
// identity, so it is genuine prior art from ITIL/CMDB + CSPM/CIEM discovery.
// See docs/identity-lifecycle.md for the full standards mapping and the
// rationale for one registry (native ∪ discovered) keyed on `origin`+`status`.
//
// State machine:
//
//	discovered → pending  (adopt — a human owner is assigned)
//	           → active    (direct activation — first EMA/ID-JAG mint adopts+grants)
//	           → deactivated (dismiss — operator marks out-of-scope, audit-retained)
//	pending    → active → suspended → active (reactivation)
//	                    → deactivated (terminal-ish — reactivatable)
//	                    → expired (time-bound authority lapsed)
//	pending    → deactivated (registration rejected)
//
// `discovered` is an *entry-only* state: discovery writes it at ingestion and
// nothing transitions back into it. ISO mapping (24760 → ours):
// Established=pending, Active=active, Suspended=suspended, Archived=deactivated/expired.
type IdentityStatus string

const (
	// IdentityStatusDiscovered is the pre-authoritative state for an identity
	// observed in an external IdP via a discovery connector (origin != native).
	// It is owner-OPTIONAL, credential-less, and NOT usable (IsUsable is false):
	// a discovered row is a posture signal, never an auth principal, until it is
	// adopted (→pending) or directly activated (→active). identity-lifecycle.md.
	IdentityStatusDiscovered  IdentityStatus = "discovered"
	IdentityStatusPending     IdentityStatus = "pending"
	IdentityStatusActive      IdentityStatus = "active"
	IdentityStatusSuspended   IdentityStatus = "suspended"
	IdentityStatusDeactivated IdentityStatus = "deactivated"
	IdentityStatusExpired     IdentityStatus = "expired"
)

func (s IdentityStatus) Valid() bool {
	switch s {
	case IdentityStatusDiscovered, IdentityStatusPending, IdentityStatusActive, IdentityStatusSuspended, IdentityStatusDeactivated, IdentityStatusExpired:
		return true
	}
	return false
}

// CanTransitionTo reports whether the identity can move from its current status to the target.
func (s IdentityStatus) CanTransitionTo(target IdentityStatus) bool {
	switch s {
	case IdentityStatusDiscovered:
		// adopt (→pending), direct activation (→active), dismiss (→deactivated).
		// Adoption/activation additionally require an owner — enforced at the
		// service layer, not here (this method is pure status topology).
		return target == IdentityStatusPending || target == IdentityStatusActive || target == IdentityStatusDeactivated
	case IdentityStatusPending:
		return target == IdentityStatusActive || target == IdentityStatusDeactivated
	case IdentityStatusActive:
		return target == IdentityStatusSuspended || target == IdentityStatusDeactivated || target == IdentityStatusExpired
	case IdentityStatusSuspended:
		return target == IdentityStatusActive || target == IdentityStatusDeactivated || target == IdentityStatusExpired
	case IdentityStatusDeactivated:
		return target == IdentityStatusActive
	case IdentityStatusExpired:
		return target == IdentityStatusDeactivated
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

// IsUsable reports whether an identity in this status can authenticate and
// receive tokens. Only `active` is usable — `discovered` and `pending` are
// explicitly NOT usable, which is the platform's safety gate: a discovered
// (untrusted, externally-observed) row can never mint a credential regardless
// of how it was written, so table separation isn't needed to keep external
// data away from credentialed identities (identity-lifecycle.md "Safety is
// already enforced by status").
func (s IdentityStatus) IsUsable() bool {
	return s == IdentityStatusActive
}

// ──────────────────────────────────────────────────────────────────────────────
// Origin — provenance discriminator (native vs discovered)
// ──────────────────────────────────────────────────────────────────────────────

// Origin records where an identity came from (see
// docs/identity-lifecycle.md): `native` — ZeroID issued it — versus an external
// ecosystem we observed it in via a discovery connector. It is orthogonal to
// status: `origin` is provenance, `status` is lifecycle. A discovered agent and
// a native agent are rows in the *same* registry, distinguished by this field
// plus status — there is no separate discovered store.
//
// The external-ecosystem set is OPEN: each new IdP connector in the discovery
// service contributes a value, so validation (ValidOrigin) checks shape, not
// membership. The closed-enum columns (status, trust_level, identity_type) are
// platform-owned and change rarely; coupling a ZeroID release to every new
// connector via a hard origin enum would be the wrong trade.
type Origin string

const (
	// OriginNative is the default — an identity ZeroID registered itself.
	OriginNative Origin = "native"
	// The launch discovery connectors. More are added by the discovery service
	// without a ZeroID change (ValidOrigin accepts any clean identifier).
	OriginOkta            Origin = "okta"
	OriginEntra           Origin = "entra"
	OriginGoogleWorkspace Origin = "google_workspace"
)

// IsExternal reports whether the identity was discovered in an external IdP
// (origin is set and not `native`). External-origin identities enter the
// lifecycle in `discovered` and may be owner-less until adopted.
func (o Origin) IsExternal() bool {
	return o != "" && o != OriginNative
}

// ValidOrigin reports whether v is a syntactically valid origin: a non-empty
// lowercase identifier (a–z, 0–9, underscore). Membership is intentionally not
// checked — the external-ecosystem set is open (see Origin). Empty is invalid
// at the storage boundary; the service layer defaults an unset origin to
// `native` before validation.
func ValidOrigin(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_':
		default:
			return false
		}
	}
	return true
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

	// Origin is the provenance discriminator (see
	// docs/identity-lifecycle.md): `native` (ZeroID issued it) vs an external
	// ecosystem an identity was discovered in (`okta`, `entra`,
	// `google_workspace`, …). External-origin identities enter the lifecycle in
	// `discovered` and may be owner-less until adopted. Defaults to `native`.
	Origin Origin `bun:"origin,type:varchar(50),notnull,default:'native'" json:"origin"`

	// SourceID identifies the discovery source instance (e.g. a specific
	// connector) that ingested this identity, so a sync can prune only the rows
	// it owns when a tenant runs several connectors of the same origin. Opaque to
	// ZeroID — the discovery service assigns it. Empty/NULL for native
	// identities and for discovered rows ingested without a source.
	SourceID string `bun:"source_id,type:varchar(255),nullzero" json:"source_id,omitempty"`

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
	// Origins lists the known provenance values. The external set is open
	// (grows with discovery connectors), so this is the launch set, not a
	// closed enum — clients should render unknown origins gracefully.
	Origins []SchemaOption `json:"origins"`
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
			{Value: string(IdentityStatusDiscovered), Label: "Discovered", Description: "Observed in an external IdP — owner-optional, credential-less, not usable until adopted"},
			{Value: string(IdentityStatusPending), Label: "Pending", Description: "Adopted (owned & governable) — awaiting activation"},
			{Value: string(IdentityStatusActive), Label: "Active", Description: "Fully operational"},
			{Value: string(IdentityStatusSuspended), Label: "Suspended", Description: "Temporarily disabled"},
			{Value: string(IdentityStatusDeactivated), Label: "Deactivated", Description: "Soft-deleted (audit-retained, reactivatable)"},
			{Value: string(IdentityStatusExpired), Label: "Expired", Description: "Time-bound authority lapsed"},
		},
		Origins: []SchemaOption{
			{Value: string(OriginNative), Label: "Native", Description: "Registered directly in ZeroID"},
			{Value: string(OriginOkta), Label: "Okta", Description: "Discovered via the Okta connector"},
			{Value: string(OriginEntra), Label: "Microsoft Entra", Description: "Discovered via the Microsoft Entra connector"},
			{Value: string(OriginGoogleWorkspace), Label: "Google Workspace", Description: "Discovered via the Google Workspace connector"},
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

// ErrInvalidWIMSEURI is returned by ValidateWIMSEURI when the caller-supplied
// URI cannot be a SPIFFE ID. Callers branch on this with errors.Is to map to
// a 400 at the HTTP boundary.
var ErrInvalidWIMSEURI = errors.New("invalid wimse uri")

// ValidateWIMSEURI checks the shape of a caller-supplied WIMSE/SPIFFE URI
// without binding it to a specific trust domain. Used by lookup endpoints
// (e.g. GET /identities/by-wimse) that need to reject obviously malformed
// input before hitting the store, but cannot reject by trust-domain because
// the caller's tenant determines which trust domain is in play.
//
// Rules (SPIFFE §2):
//   - scheme is "spiffe"
//   - non-empty host (the trust domain)
//   - host must not include a port
//   - non-empty workload path (a bare trust-domain URI is the trust-domain ID,
//     not a workload ID — reject)
//   - path must not have a trailing slash or empty segments
//   - path segments must conform to SPIFFE §2.3 character set (delegated to
//     ValidateSPIFFEPathSegment so the read-side validator agrees with
//     BuildWIMSEURI on what's a legal segment)
//   - no query (including a trailing "?" with empty value), no fragment, no
//     user-info
//   - total length within MaxSPIFFEIDBytes
//
// Returns a wrapped ErrInvalidWIMSEURI on failure.
func ValidateWIMSEURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("%w: empty", ErrInvalidWIMSEURI)
	}
	if len(uri) > MaxSPIFFEIDBytes {
		return fmt.Errorf("%w: exceeds %d bytes", ErrInvalidWIMSEURI, MaxSPIFFEIDBytes)
	}
	// Reject obvious scheme mismatches before url.Parse so the error reason
	// is more useful than "missing scheme".
	if !strings.HasPrefix(uri, "spiffe://") {
		return fmt.Errorf("%w: scheme must be spiffe://", ErrInvalidWIMSEURI)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidWIMSEURI, err)
	}
	if u.Scheme != "spiffe" {
		return fmt.Errorf("%w: scheme must be spiffe (got %q)", ErrInvalidWIMSEURI, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: missing trust domain (host)", ErrInvalidWIMSEURI)
	}
	// SPIFFE §2.2: the trust domain is a DNS name without a port.
	// url.Host carries the host[:port] form; reject any colon to forbid ports.
	if strings.Contains(u.Host, ":") {
		return fmt.Errorf("%w: trust domain must not contain a port", ErrInvalidWIMSEURI)
	}
	if u.User != nil {
		return fmt.Errorf("%w: user-info not allowed", ErrInvalidWIMSEURI)
	}
	// ForceQuery catches a trailing "?" even when RawQuery is empty.
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%w: query/fragment not allowed", ErrInvalidWIMSEURI)
	}
	// SPIFFE IDs always have a workload path. A bare trust-domain URI like
	// "spiffe://example.org" is a trust domain identifier, not a workload ID.
	if u.Path == "" || u.Path == "/" {
		return fmt.Errorf("%w: missing workload path", ErrInvalidWIMSEURI)
	}
	if strings.HasSuffix(u.Path, "/") {
		return fmt.Errorf("%w: path must not end with a slash", ErrInvalidWIMSEURI)
	}
	if strings.Contains(u.Path, "//") {
		return fmt.Errorf("%w: path must not contain empty segments", ErrInvalidWIMSEURI)
	}
	// Validate each path segment against the same character set BuildWIMSEURI
	// enforces. The read-side validator must agree with the write-side
	// constructor on what's legal — otherwise a stored URI could fail
	// validation on lookup.
	for _, seg := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if err := ValidateSPIFFEPathSegment("path segment", seg); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidWIMSEURI, err)
		}
	}
	return nil
}
