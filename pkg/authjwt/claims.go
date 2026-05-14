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

	// RFC 8693 delegation
	ActorClaims *ActorClaims `json:"act,omitempty"`

	// Custom holds any additional claims not mapped to typed fields.
	// Consuming services can use this for deployment-specific claims
	// (e.g., application_id, gateway_id, product, user_email).
	Custom map[string]any `json:"-"`
}

// ActorClaims represents the "act" claim in a delegated token (RFC 8693).
type ActorClaims struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss,omitempty"`
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
		"account_id": {}, "project_id": {},
		"user_id": {}, "owner_user_id": {},
		"external_id": {}, "identity_type": {}, "sub_type": {}, "trust_level": {},
		"status": {}, "name": {}, "framework": {}, "version": {}, "publisher": {},
		"capabilities": {},
		"grant_type":   {}, "scopes": {}, "delegation_depth": {},
		"act":        {},
		"mission_id": {},
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
	switch v := raw.(type) {
	case map[string]any:
		act := &ActorClaims{}
		if sub, ok := v["sub"].(string); ok {
			act.Subject = sub
		}
		if iss, ok := v["iss"].(string); ok {
			act.Issuer = iss
		}
		return act
	default:
		// Try JSON roundtrip for typed maps
		data, err := json.Marshal(raw)
		if err != nil {
			return nil
		}
		act := &ActorClaims{}
		if err := json.Unmarshal(data, act); err != nil {
			return nil
		}
		if act.Subject == "" {
			return nil
		}
		return act
	}
}
