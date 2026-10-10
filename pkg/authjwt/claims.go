// Package authjwt provides JWKS-based JWT verification for services consuming
// ZeroID-issued tokens. It supports both ES256 (NHI/agent) and RS256 (human/SDK)
// tokens with automatic algorithm selection via kid matching.
//
// This package is designed for customer-facing API services that verify Bearer
// JWTs from external callers.
package authjwt

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

// Claims represents the verified claims extracted from a ZeroID-issued JWT.
// Fields align with ZeroID's TokenClaims in domain/token.go.
type Claims struct {
	// Standard JWT claims
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  []string  `json:"aud,omitempty"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	JWTID     string    `json:"jti"`

	// Resource is the RFC 8707 `resource` claim — the resource(s) this token
	// was bound to AT THE MINT. Non-empty ONLY when ZeroID recorded an explicit
	// binding (today: the ID-JAG grant, ADR 0010 D4). ZeroID reserves the claim,
	// so a caller cannot inject or widen it via additional_claims.
	//
	// This — not Audience — is what a PEP must gate resource enforcement on.
	// ZeroID stamps `aud` on every token it issues, defaulting to the issuer URL
	// when nothing was requested (JWT-SVID §3), so a non-empty Audience carries
	// no information about whether the token is resource-restricted. Empty here
	// means "not resource-bound"; enforce nothing.
	Resource []string `json:"resource,omitempty"`

	// Tenant scoping
	AccountID string `json:"account_id"`
	ProjectID string `json:"project_id,omitempty"`

	// User identity (human flows: user_session, authorization_code)
	UserID      string `json:"user_id,omitempty"`
	OwnerUserID string `json:"owner_user_id,omitempty"`

	// NHI identity (agent/service flows: client_credentials, jwt_bearer, token_exchange)
	ExternalID   string   `json:"external_id,omitempty"`
	IdentityType string   `json:"identity_type,omitempty"`
	SubType      string   `json:"sub_type,omitempty"`
	TrustLevel   string   `json:"trust_level,omitempty"`
	Status       string   `json:"status,omitempty"`
	Name         string   `json:"name,omitempty"`
	Framework    string   `json:"framework,omitempty"`
	Version      string   `json:"version,omitempty"`
	Publisher    string   `json:"publisher,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`

	// Auth metadata
	GrantType       string   `json:"grant_type,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	DelegationDepth int      `json:"delegation_depth,omitempty"`

	// MissionID groups every credential in a delegation tree under one
	// stable opaque identifier. Treat as opaque — callers MUST NOT try to
	// look up a credential by this value, even though it is currently
	// populated with the root JTI. See zeroid issue #81.
	MissionID string `json:"mission_id,omitempty"`

	// RFC 8693 delegation. Under the rfc8693 token profile this is the current
	// actor, with prior actors nested in its Actor field. Under the legacy
	// profile it is a single level whose meaning depends on the grant (the
	// delegating orchestrator, or the key's creator); read it through
	// CurrentActor and PriorActors rather than directly.
	ActorClaims *ActorClaims `json:"act,omitempty"`

	// principalType is the private principal_type claim, present only on
	// tokens issued under the rfc8693 profile. Read with PrincipalType.
	principalType string

	// Custom holds any additional claims not mapped to typed fields.
	// Consuming services can use this for deployment-specific claims
	// (e.g., application_id, gateway_id, product, user_email).
	Custom map[string]any `json:"-"`
}

// ActorClaims represents the "act" claim in a delegated token (RFC 8693).
// Under the rfc8693 profile the outermost act is the current actor and carries
// its own attributes; prior actors nest in Actor, most recent first, and carry
// only their subject.
type ActorClaims struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss,omitempty"`

	// The current actor's own attributes, carried inside act under the
	// rfc8693 profile because the token's top level describes the principal.
	IdentityType string `json:"identity_type,omitempty"`
	TrustLevel   string `json:"trust_level,omitempty"`
	ExternalID   string `json:"external_id,omitempty"`

	// Actor is the prior actor, if any (RFC 8693 §4.1 nesting).
	Actor *ActorClaims `json:"act,omitempty"`
}

// maxActorChain bounds how deep parseActorClaims follows nested act claims.
// ZeroID caps the chain at 16; this guards against a hostile or malformed
// token from another issuer that this verifier might be pointed at.
const maxActorChain = 16

// Principal types reported by PrincipalType.
const (
	PrincipalUser     = "user"
	PrincipalWorkload = "workload"
	PrincipalUnknown  = "unknown"
)

// IsLegacyProfile reports whether the token was issued under ZeroID's legacy
// profile, recognised by the absence of principal_type. Under it an exchanged
// token's sub is the actor, not the principal, and act is a single level
// whose meaning depends on the grant.
func (c *Claims) IsLegacyProfile() bool {
	return c.principalType == ""
}

// PrincipalType returns whether the token's chain acts for a person ("user")
// or a workload ("workload"), or "unknown" for a chain whose principal was
// lost before principals were tracked. Empty for a legacy-profile token.
//
// The resource-server rule (RFC 8693 §4.1): decide on the top-level claims and
// the current actor. The person behind a call is Subject when PrincipalType is
// "user"; otherwise there is none.
func (c *Claims) PrincipalType() string {
	return c.principalType
}

// CurrentActor returns the party presenting the token: act.sub for an
// rfc8693-profile token that has an actor, otherwise sub. A legacy-profile
// token's act names a delegator or a key's creator rather than the party
// acting, so for those the current actor is always sub.
func (c *Claims) CurrentActor() string {
	if !c.IsLegacyProfile() && c.ActorClaims != nil && c.ActorClaims.Subject != "" {
		return c.ActorClaims.Subject
	}
	return c.Subject
}

// PriorActors returns the actors before the current one, most recent first,
// for an rfc8693-profile token. They are audit history, not grounds for access
// (RFC 8693 §4.1). Nil for a legacy-profile token, whose act is not an actor
// chain.
func (c *Claims) PriorActors() []string {
	if c.IsLegacyProfile() || c.ActorClaims == nil {
		return nil
	}
	var out []string
	for a := c.ActorClaims.Actor; a != nil && len(out) < maxActorChain; a = a.Actor {
		out = append(out, a.Subject)
	}
	return out
}

// GetCustomString returns a custom claim value as a string.
// Useful for deployment-specific claims not in the typed fields.
func (c *Claims) GetCustomString(key string) string {
	if c.Custom == nil {
		return ""
	}
	v, ok := c.Custom[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// GetCustom returns a custom claim value as interface{}.
func (c *Claims) GetCustom(key string) (any, bool) {
	if c.Custom == nil {
		return nil, false
	}
	v, ok := c.Custom[key]
	return v, ok
}

// HasScope returns true if the token's scopes include the given scope.
func (c *Claims) HasScope(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

// RequireScope returns ErrInsufficientScope if the token does not have the
// given scope. Use this for inline scope checks in handlers.
func (c *Claims) RequireScope(scope string) error {
	if !c.HasScope(scope) {
		return fmt.Errorf("%w: required %q, have %v", ErrInsufficientScope, scope, c.Scopes)
	}
	return nil
}

// Agent returns a typed AgentIdentity if this token represents an NHI
// (agent, application, service, mcp_server). Returns nil for human tokens.
func (c *Claims) Agent() *AgentIdentity {
	// Under the rfc8693 profile an exchanged token's top level describes the
	// principal, possibly a person; the agent is the current actor, whose
	// attributes are carried inside act, and the party that delegated to it
	// is the first prior actor.
	if !c.IsLegacyProfile() && c.ActorClaims != nil && c.ActorClaims.Subject != "" {
		act := c.ActorClaims
		if act.ExternalID == "" {
			return nil
		}
		a := &AgentIdentity{
			Sub:             act.Subject,
			ExternalID:      act.ExternalID,
			IdentityType:    act.IdentityType,
			SubType:         c.SubType,
			TrustLevel:      act.TrustLevel,
			Name:            c.Name,
			Framework:       c.Framework,
			Publisher:       c.Publisher,
			Capabilities:    c.Capabilities,
			Scopes:          c.Scopes,
			DelegationDepth: c.DelegationDepth,
			Owner:           c.OwnerUserID,
		}
		if prior := c.PriorActors(); len(prior) > 0 {
			a.DelegatedBy = prior[0]
		}
		return a
	}
	if c.ExternalID == "" {
		return nil
	}
	a := &AgentIdentity{
		Sub:             c.Subject,
		ExternalID:      c.ExternalID,
		IdentityType:    c.IdentityType,
		SubType:         c.SubType,
		TrustLevel:      c.TrustLevel,
		Name:            c.Name,
		Framework:       c.Framework,
		Publisher:       c.Publisher,
		Capabilities:    c.Capabilities,
		Scopes:          c.Scopes,
		DelegationDepth: c.DelegationDepth,
		Owner:           c.OwnerUserID,
	}
	if c.ActorClaims != nil {
		a.DelegatedBy = c.ActorClaims.Subject
	}
	return a
}

// AgentIdentity is the typed result object for NHI tokens.
// Matches the SDK surface: agent.sub, agent.delegated_by, agent.depth, agent.owner.
type AgentIdentity struct {
	// Sub is the WIMSE URI (e.g., spiffe://zeroid.dev/acct/proj/agent/my-agent).
	Sub string

	// ExternalID is the caller-chosen identity identifier.
	ExternalID string

	// IdentityType is the identity class: agent, application, service, mcp_server.
	IdentityType string

	// SubType is the identity sub-classification (e.g., orchestrator, llm_provider).
	SubType string

	// TrustLevel is the trust classification: first_party, verified_third_party, unverified.
	TrustLevel string

	// Name is the human-readable identity name.
	Name string

	// Framework is the agent framework (e.g., langchain, crewai).
	Framework string

	// Publisher is the identity publisher/vendor.
	Publisher string

	// Capabilities are the declared agent capabilities.
	Capabilities []string

	// Scopes are the OAuth scopes granted to this token.
	Scopes []string

	// DelegationDepth is the number of delegation hops from the original principal.
	DelegationDepth int

	// DelegatedBy is the subject of the delegating principal (from act.sub).
	// Empty if this is a direct credential, not a delegated token.
	DelegatedBy string

	// Owner is the user who provisioned this identity.
	Owner string
}

// extractClaims builds Claims from a verified jwt.Token.
func extractClaims(token jwt.Token) *Claims {
	// jwx v4: every standard accessor returns (value, present). Treat absent
	// as zero-value — the caller already validated the token, so this is a
	// projection step, not a re-validation.
	iss, _ := token.Issuer()
	sub, _ := token.Subject()
	aud, _ := token.Audience()
	iat, _ := token.IssuedAt()
	exp, _ := token.Expiration()
	jti, _ := token.JwtID()
	c := &Claims{
		Issuer:    iss,
		Subject:   sub,
		Audience:  aud,
		IssuedAt:  iat,
		ExpiresAt: exp,
		JWTID:     jti,
	}

	// jwx v4: jwt.Get[T] is the typed accessor. Distinct getters keep call
	// sites single-line below.
	getString := func(key string) string {
		v, err := jwt.Get[string](token, key)
		if err != nil {
			return ""
		}
		return v
	}

	getInt := func(key string) int {
		// JSON numbers decode as float64; some issuers may produce int/int64
		// directly. Try the most likely shape first, then fall back.
		if n, err := jwt.Get[float64](token, key); err == nil {
			return int(n)
		}
		if n, err := jwt.Get[int](token, key); err == nil {
			return n
		}
		if n, err := jwt.Get[int64](token, key); err == nil {
			return int(n)
		}
		return 0
	}

	getStringSlice := func(key string) []string {
		if s, err := jwt.Get[[]string](token, key); err == nil {
			return s
		}
		if s, err := jwt.Get[[]any](token, key); err == nil {
			result := make([]string, 0, len(s))
			for _, item := range s {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			if len(result) == 0 {
				return nil
			}
			return result
		}
		return nil
	}

	// Known ZeroID claims — mapped to typed fields.
	knownKeys := map[string]struct{}{
		"iss": {}, "sub": {}, "aud": {}, "iat": {}, "exp": {}, "nbf": {}, "jti": {},
		"resource":   {},
		"account_id": {}, "project_id": {},
		"user_id": {}, "owner_user_id": {},
		"external_id": {}, "identity_type": {}, "sub_type": {}, "trust_level": {},
		"status": {}, "name": {}, "framework": {}, "version": {}, "publisher": {},
		"capabilities": {},
		"grant_type":   {}, "scopes": {}, "delegation_depth": {},
		"act":            {},
		"mission_id":     {},
		"principal_type": {},
	}

	// RFC 8707 resource binding. Per RFC 8707 the value is a single URI string
	// OR an array of them. ZeroID mints the array shape; the string branch
	// exists so that form is not silently read as "unbound", which is the
	// direction that matters — empty means a PEP enforces nothing.
	//
	// Be precise about the limit of that guarantee: a value which is NEITHER
	// shape (a number, an object) still yields empty, i.e. unbound, i.e. fail
	// OPEN. That is tolerable only because ZeroID is the sole issuer behind
	// this verifier and always writes []string, and the value is signature-
	// verified before it gets here — it is not a general fail-closed property.
	// An issuer that could emit other shapes would need this to return an error
	// rather than a zero value.
	c.Resource = getStringSlice("resource")
	if len(c.Resource) == 0 {
		if single := getString("resource"); single != "" {
			c.Resource = []string{single}
		}
	}

	// Tenant
	c.AccountID = getString("account_id")
	c.ProjectID = getString("project_id")

	// User identity
	c.UserID = getString("user_id")
	c.OwnerUserID = getString("owner_user_id")

	// NHI identity
	c.ExternalID = getString("external_id")
	c.IdentityType = getString("identity_type")
	c.SubType = getString("sub_type")
	c.TrustLevel = getString("trust_level")
	c.Status = getString("status")
	c.Name = getString("name")
	c.Framework = getString("framework")
	c.Version = getString("version")
	c.Publisher = getString("publisher")
	c.Capabilities = getStringSlice("capabilities")

	// Auth metadata
	c.GrantType = getString("grant_type")
	c.Scopes = getStringSlice("scopes")
	c.DelegationDepth = getInt("delegation_depth")
	c.MissionID = getString("mission_id")
	c.principalType = getString("principal_type")

	// RFC 8693 delegation. The act claim is a nested object; pull it as
	// interface{} so parseActorClaims can handle any concrete shape jwx
	// produces (map[string]any, struct, etc.).
	if actRaw, err := jwt.Get[any](token, "act"); err == nil {
		c.ActorClaims = parseActorClaims(actRaw)
	}

	// Collect all unrecognized claims into Custom for deployment-specific use.
	// jwx v4: Token.Claims() yields an iter.Seq2[string, any] over every
	// claim, replacing the v2 Iterate/Pair API. Cleaner than Keys() +
	// jwt.Get[any] in a loop.
	c.Custom = make(map[string]any)
	for key, v := range token.Claims() {
		if _, known := knownKeys[key]; known {
			continue
		}
		c.Custom[key] = v
	}
	if len(c.Custom) == 0 {
		c.Custom = nil
	}

	return c
}

func parseActorClaims(raw any) *ActorClaims {
	return parseActorClaimsDepth(raw, 0)
}

func parseActorClaimsDepth(raw any, depth int) *ActorClaims {
	switch v := raw.(type) {
	case map[string]any:
		act := &ActorClaims{}
		if sub, ok := v["sub"].(string); ok {
			act.Subject = sub
		}
		if iss, ok := v["iss"].(string); ok {
			act.Issuer = iss
		}
		act.IdentityType, _ = v["identity_type"].(string)
		act.TrustLevel, _ = v["trust_level"].(string)
		act.ExternalID, _ = v["external_id"].(string)
		if nested, ok := v["act"]; ok && depth+1 < maxActorChain {
			act.Actor = parseActorClaimsDepth(nested, depth+1)
		}
		return act
	default:
		// Try a JSON roundtrip for typed maps. Decode into a plain map and
		// re-enter the map branch, not into ActorClaims, whose recursive Actor
		// field would follow nested act with no regard for maxActorChain.
		data, err := json.Marshal(raw)
		if err != nil {
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return nil
		}
		act := parseActorClaimsDepth(m, depth)
		if act == nil || act.Subject == "" {
			return nil
		}
		return act
	}
}
