package domain

import (
	"time"

	"github.com/uptrace/bun"
)

// PrincipalType says what kind of principal a credential's chain acts for:
// whether `sub` is a person or a workload. No standard claim carries this
// (RFC 9068 leaves `sub` untyped), so ZeroID emits it as the private claim
// `principal_type` (RFC 7519 §4.3) under the rfc8693 token profile, and
// persists it on every credential whatever the profile.
type PrincipalType string

const (
	// PrincipalUser: a human authorized the chain. Set on the six grants that
	// mint for a person (authorization_code, refresh_token, CIBA, ID-JAG,
	// ID-token exchange, and the trusted-broker principal exchange) and
	// inherited by every exchange below them. It records that a human
	// authorized the chain, not that a directory was consulted.
	PrincipalUser PrincipalType = "user"

	// PrincipalWorkload: the chain is rooted in an agent or service acting on
	// its own authority (client_credentials, NHI jwt_bearer, api_key, admin
	// issuance, attestation).
	PrincipalWorkload PrincipalType = "workload"

	// PrincipalUnknown is assigned to a child exchanged from a parent minted
	// before principals were tracked, when that parent was itself delegated.
	// The legacy profile put the actor in the parent's `sub`, so the original
	// principal is lost. A policy that requires a user subject rejects it:
	// unknown never satisfies a principal requirement (fail closed).
	PrincipalUnknown PrincipalType = "unknown"
)

// Principal requirements a credential policy may set, ordered from weakest to
// strongest: any ("") < user < owner.
const (
	RequirePrincipalAny   = ""
	RequirePrincipalUser  = "user"
	RequirePrincipalOwner = "owner"
)

// PrincipalRequirementRank orders principal requirements for subset checks:
// a narrower policy must require at least as much as the wider one. -1 for an
// unrecognised value.
func PrincipalRequirementRank(req string) int {
	switch req {
	case RequirePrincipalAny:
		return 0
	case RequirePrincipalUser:
		return 1
	case RequirePrincipalOwner:
		return 2
	}
	return -1
}

// IsValid reports whether t is one of the principal types ZeroID assigns.
func (t PrincipalType) IsValid() bool {
	switch t {
	case PrincipalUser, PrincipalWorkload, PrincipalUnknown:
		return true
	}
	return false
}

// MaxActorChainDepth is the hard cap on how many actors a token's nested `act`
// claim carries, for token size (each nested actor adds about 70 bytes). Past
// it, the deepest prior actors are dropped. RFC 8693 §4.1 allows that: prior
// actors are informational, and access control uses only the top-level claims
// and the current actor.
const MaxActorChainDepth = 16

// Actor is one entry in a token's RFC 8693 §4.1 `act` chain. Only workloads
// appear as actors: agents, and gateways that exchange on a caller's behalf.
// The person is always `sub`, never an actor.
//
// The current actor is the outermost `act`. Its own attributes (identity type,
// trust level, external id) are carried inside it under the rfc8693 profile,
// because the token's top level describes the principal, not the actor.
// Prior actors carry only their `sub`.
type Actor struct {
	Sub          string `json:"sub"`
	IdentityType string `json:"identity_type,omitempty"`
	TrustLevel   string `json:"trust_level,omitempty"`
	ExternalID   string `json:"external_id,omitempty"`
}

// TokenProfile selects the claim shape a tenant's tokens are issued in.
type TokenProfile string

const (
	// TokenProfileLegacy keeps the claim shape ZeroID has always issued, apart
	// from purely additive fixes (issued_token_type, client_id, introspection
	// fields, reserved claims). On an exchange the child's `sub` is the actor
	// and `act` holds a single level. The default.
	TokenProfileLegacy TokenProfile = "legacy"

	// TokenProfileRFC8693 issues the RFC 8693 delegation shape: `sub` is the
	// principal for the whole chain, `act` nests the actors with the current
	// one outermost, `principal_type` says whether `sub` is a person or a
	// workload, and access tokens are typed `at+jwt` with the RFC 9068 `scope`
	// string. A tenant opts in once its consumers read both shapes.
	TokenProfileRFC8693 TokenProfile = "rfc8693"
)

// IsValid reports whether p is a supported token profile.
func (p TokenProfile) IsValid() bool {
	return p == TokenProfileLegacy || p == TokenProfileRFC8693
}

// TenantSettings holds per-tenant ZeroID settings. A tenant is
// (account_id, project_id), as everywhere else in ZeroID. An absent row means
// every setting takes its default.
type TenantSettings struct {
	bun.BaseModel `bun:"table:tenant_settings,alias:ts"`

	AccountID    string       `bun:"account_id,pk,type:varchar(255)"   json:"account_id"`
	ProjectID    string       `bun:"project_id,pk,type:varchar(255)"   json:"project_id"`
	TokenProfile TokenProfile `bun:"token_profile,type:varchar(20),notnull" json:"token_profile"`
	CreatedAt    time.Time    `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt    time.Time    `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}
