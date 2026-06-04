package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// mapErr converts service-layer errors to huma errors with proper HTTP status codes.
// Internal details are logged server-side; only generic messages are returned to clients.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	// Typed sentinels first. Service-layer callers wrap with these so
	// callers see a 400 instead of a 500 on caller-fixable states.
	if errors.Is(err, domain.ErrIdentityExpired) || errors.Is(err, domain.ErrIdentityNotUsable) {
		return huma.Error400BadRequest(err.Error())
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no rows in result set"), strings.Contains(msg, "not found"):
		return huma.Error404NotFound("resource not found")
	case strings.Contains(msg, "already exists"), strings.Contains(msg, "duplicate"):
		return huma.Error409Conflict("resource already exists")
	case strings.Contains(msg, "invalid status transition"):
		return huma.Error400BadRequest("invalid status transition")
	default:
		log.Error().Err(err).Msg("unexpected agent service error")
		return huma.Error500InternalServerError("internal server error")
	}
}

// ── Agent registration types ─────────────────────────────────────────────────

type RegisterAgentInput struct {
	Body struct {
		Name                     string          `json:"name" required:"true" minLength:"1" doc:"Human-readable name"`
		ExternalID               string          `json:"external_id" required:"true" minLength:"1" doc:"Unique identifier within this project"`
		IdentityType             string          `json:"identity_type,omitempty" enum:"agent,application,mcp_server,service" doc:"Identity type (defaults to agent)"`
		SubType                  string          `json:"sub_type,omitempty" enum:"orchestrator,autonomous,tool_agent,human_proxy,evaluator,chatbot,assistant,api_service,custom,code_agent" doc:"Operational role"`
		TrustLevel               string          `json:"trust_level,omitempty" enum:"unverified,verified_third_party,first_party" doc:"Trust level (defaults to unverified)"`
		Framework                string          `json:"framework,omitempty" doc:"Agent framework (e.g. langchain, autogen, crewai)"`
		Version                  string          `json:"version,omitempty" doc:"Agent version string"`
		Publisher                string          `json:"publisher,omitempty" doc:"Agent publisher or organization"`
		Description              string          `json:"description,omitempty" doc:"Human-readable description"`
		Capabilities             json.RawMessage `json:"capabilities,omitempty" doc:"JSON array of capabilities"`
		Labels                   json.RawMessage `json:"labels,omitempty" doc:"JSON object of key-value labels"`
		Metadata                 json.RawMessage `json:"metadata,omitempty" doc:"JSON object of opaque product-specific metadata"`
		AllowedScopes            []string        `json:"allowed_scopes,omitempty" doc:"OAuth scopes this identity may request. Required for token_exchange since the exchange only grants scopes in the intersection of the subject's granted scopes and the actor's allowed_scopes."`
		CreatedBy                string          `json:"created_by,omitempty" doc:"User ID of the creator"`
		PublicKeyPEM             string          `json:"public_key_pem,omitempty" doc:"PEM-encoded EC P-256 public key for JWT bearer and token_exchange grants"`
		CredentialPolicyID       string          `json:"credential_policy_id,omitempty" doc:"Identity policy — authority ceiling. Also applied to the auto-created API key unless api_key_credential_policy_id is set. Defaults to the tenant default policy."`
		APIKeyCredentialPolicyID string          `json:"api_key_credential_policy_id,omitempty" doc:"Optional narrower policy for the auto-created API key. Must be a subset of the identity policy (scopes, TTL, grant types, delegation depth, trust level, attestation). When empty, the API key inherits the identity policy."`
		// ExpiresAt time-bounds the grant of authority and propagates to the
		// auto-created API key. RFC3339. Omit for no expiry.
		ExpiresAt *time.Time `json:"expires_at,omitempty" doc:"RFC3339 timestamp after which the agent and its bootstrap API key are auto-deactivated"`
		// Fields injected by management API from trusted headers (overridden server-side):
		AccountID string `json:"account_id,omitempty"`
		ProjectID string `json:"project_id,omitempty"`
	}
}

type RegisterAgentOutput struct {
	Body *service.AgentRegistrationResponse
}

type GetAgentInput struct {
	ID string `path:"id" doc:"Agent identity UUID"`
}

type GetAgentOutput struct {
	Body *service.AgentResponse
}

type ListAgentsInput struct {
	AgentType    string   `query:"agent_type" doc:"Filter by agent type"`
	IdentityType []string `query:"identity_type" doc:"Filter by identity type. Comma-separated for multiple (e.g. agent,application)."`
	Label        string   `query:"label" doc:"Filter by label (key:value, e.g. product:guardrails)"`
	TrustLevel   string   `query:"trust_level" doc:"Filter by trust level"`
	IsActive     string   `query:"is_active" doc:"Filter by active status"`
	Search       string   `query:"search" doc:"Search by name or external_id"`
	Limit        int      `query:"limit" default:"20" doc:"Items per page (max 100)"`
	Offset       int      `query:"offset" default:"0" doc:"Offset for pagination"`
}

type ListAgentsOutput struct {
	Body *service.AgentListResponse
}

type UpdateAgentInput struct {
	ID   string `path:"id" doc:"Agent identity UUID"`
	Body struct {
		Name         *string         `json:"name,omitempty" doc:"Human-readable name"`
		SubType      *string         `json:"sub_type,omitempty" enum:"orchestrator,autonomous,tool_agent,human_proxy" doc:"Agent role"`
		TrustLevel   *string         `json:"trust_level,omitempty" enum:"unverified,verified_third_party,first_party" doc:"Trust level"`
		Framework    *string         `json:"framework,omitempty" doc:"Framework"`
		Version      *string         `json:"version,omitempty" doc:"Version"`
		Publisher    *string         `json:"publisher,omitempty" doc:"Publisher"`
		Description  *string         `json:"description,omitempty" doc:"Description"`
		Capabilities json.RawMessage `json:"capabilities,omitempty" doc:"Capabilities"`
		Labels       json.RawMessage `json:"labels,omitempty" doc:"Key-value labels"`
		Metadata     json.RawMessage `json:"metadata,omitempty" doc:"Product-specific metadata"`
		Status       *string         `json:"status,omitempty" enum:"active,suspended,deactivated" doc:"Identity status"`
		UpdatedBy    string          `json:"updated_by,omitempty" doc:"User ID of the updater"`
		// PublicKeyPEM force-sets the actor-assertion key without proof-of-
		// possession — the admin recovery path. This route is secret-gated
		// (management API), so admin authority is the authorization. Agents
		// rotate their own key via POST /agents/self/public-key with proofs.
		PublicKeyPEM *string `json:"public_key_pem,omitempty" doc:"Force-set the agent's actor-assertion public key (admin recovery; no proof-of-possession)."`
	}
}

type AgentActionInput struct {
	ID string `path:"id" doc:"Agent identity UUID"`
}

type AgentActionOutput struct {
	Body *service.AgentResponse
}

type RotateKeyOutput struct {
	Body *service.AgentRegistrationResponse
}

// ── Agent routes ─────────────────────────────────────────────────────────────

func (a *API) registerAgentRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "register-agent",
		Method:        http.MethodPost,
		Path:          "/agents/register",
		Summary:       "Register a new agent (creates identity + API key atomically)",
		Tags:          []string{"Agents"},
		DefaultStatus: http.StatusCreated,
	}, a.registerAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-agent",
		Method:      http.MethodGet,
		Path:        "/agents/registry/{id}",
		Summary:     "Get an agent by identity ID",
		Tags:        []string{"Agents"},
	}, a.getAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-agents",
		Method:      http.MethodGet,
		Path:        "/agents/registry",
		Summary:     "List agents for the current tenant",
		Tags:        []string{"Agents"},
	}, a.listAgentsOp)

	huma.Register(api, huma.Operation{
		OperationID: "update-agent",
		Method:      http.MethodPatch,
		Path:        "/agents/registry/{id}",
		Summary:     "Update mutable fields of an agent",
		Tags:        []string{"Agents"},
	}, a.updateAgentOp)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-agent",
		Method:        http.MethodDelete,
		Path:          "/agents/registry/{id}",
		Summary:       "Deactivate an agent (soft delete) and revoke its keys",
		Tags:          []string{"Agents"},
		DefaultStatus: http.StatusOK,
	}, a.deleteAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "activate-agent",
		Method:      http.MethodPost,
		Path:        "/agents/registry/{id}/activate",
		Summary:     "Activate a previously deactivated agent",
		Tags:        []string{"Agents"},
	}, a.activateAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "deactivate-agent",
		Method:      http.MethodPost,
		Path:        "/agents/registry/{id}/deactivate",
		Summary:     "Deactivate an agent without deleting it",
		Tags:        []string{"Agents"},
	}, a.deactivateAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "rotate-agent-key",
		Method:      http.MethodPost,
		Path:        "/agents/registry/{id}/rotate-key",
		Summary:     "Rotate an agent's API key (revokes old, issues new)",
		Tags:        []string{"Agents"},
	}, a.rotateAgentKeyOp)
}

// registerAgentSelfServiceRoute registers the agent self-service actor-key
// endpoint. It MUST be mounted on the public router behind AgentAuthMiddleware
// (not the secret-gated admin group) so an agent can reach it directly with its
// own access token. The identity is taken from the validated token claims, never
// from the path — an agent can only set its own key.
func (a *API) registerAgentSelfServiceRoute(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "set-own-public-key",
		Method:      http.MethodPost,
		Path:        "/agents/self/public-key",
		Summary:     "Enroll or rotate the calling agent's actor-assertion public key",
		Tags:        []string{"Agents"},
	}, a.setOwnPublicKeyOp)
}

// SetOwnPublicKeyInput is the body for POST /agents/self/public-key. The target
// identity is the authenticated caller (from its access token), so there is no
// id in the path or body.
type SetOwnPublicKeyInput struct {
	Body struct {
		NewPublicKeyPEM string `json:"new_public_key_pem" required:"true" minLength:"1" doc:"SPKI EC P-256 public key (PEM) to enroll or rotate to."`
		NewKeyProof     string `json:"new_key_proof" required:"true" minLength:"1" doc:"Compact ES256 JWS signed by the NEW key, proving control of it. Claims: aud=<issuer>/agents/self/public-key, sub=<caller WIMSE URI>, plus jti, iat, exp (lifetime <= 2m)."`
		CurrentKeyProof string `json:"current_key_proof,omitempty" doc:"Required only when rotating an already-enrolled key: compact ES256 JWS signed by the CURRENT key, same claims plus nkt=base64url(SHA-256(new SPKI DER)) binding it to the new key."`
	}
}

type SetOwnPublicKeyOutput struct {
	Body *service.AgentResponse
}

// setOwnPublicKeyOp enrolls or rotates the actor-assertion public key for the
// authenticated agent identity (self-service). Identity + tenant come from the
// agent's own access-token claims (AgentAuthMiddleware), never from caller input.
func (a *API) setOwnPublicKeyOp(ctx context.Context, input *SetOwnPublicKeyInput) (*SetOwnPublicKeyOutput, error) {
	claims, ok := internalMiddleware.GetAgentClaims(ctx)
	if !ok || claims.IdentityID == "" {
		return nil, huma.Error401Unauthorized("missing or invalid agent token")
	}

	// Attribute the key change to the agent itself in the audit trail (this
	// endpoint runs outside TenantContextMiddleware, so modified_by is otherwise
	// unset).
	ctx = internalMiddleware.SetCallerName(ctx, claims.Subject)

	resp, err := a.agentSvc.SetPublicKey(ctx, claims.IdentityID, claims.AccountID, claims.ProjectID, service.SetPublicKeyRequest{
		NewPublicKeyPEM: input.Body.NewPublicKeyPEM,
		NewKeyProof:     input.Body.NewKeyProof,
		CurrentKeyProof: input.Body.CurrentKeyProof,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrKeyProofInvalid):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrInvalidIdentityField):
			return nil, huma.Error400BadRequest(err.Error())
		case errors.Is(err, service.ErrIdentityNotFound):
			return nil, huma.Error404NotFound("identity not found")
		default:
			log.Error().Err(err).Str("identity_id", claims.IdentityID).Msg("failed to set actor public key")
			return nil, huma.Error500InternalServerError("failed to set public key")
		}
	}
	return &SetOwnPublicKeyOutput{Body: resp}, nil
}

func (a *API) registerAgentOp(ctx context.Context, input *RegisterAgentInput) (*RegisterAgentOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	createdBy := input.Body.CreatedBy
	if createdBy == "" {
		createdBy = internalMiddleware.GetCallerName(ctx)
	}

	resp, err := a.agentSvc.RegisterAgent(ctx, service.RegisterAgentRequest{
		AccountID:                tenant.AccountID,
		ProjectID:                tenant.ProjectID,
		Name:                     input.Body.Name,
		ExternalID:               input.Body.ExternalID,
		IdentityType:             domain.IdentityType(input.Body.IdentityType),
		SubType:                  domain.SubType(input.Body.SubType),
		TrustLevel:               domain.TrustLevel(input.Body.TrustLevel),
		Framework:                input.Body.Framework,
		Version:                  input.Body.Version,
		Publisher:                input.Body.Publisher,
		Description:              input.Body.Description,
		Capabilities:             input.Body.Capabilities,
		Labels:                   input.Body.Labels,
		Metadata:                 input.Body.Metadata,
		AllowedScopes:            input.Body.AllowedScopes,
		CreatedBy:                createdBy,
		PublicKeyPEM:             input.Body.PublicKeyPEM,
		CredentialPolicyID:       input.Body.CredentialPolicyID,
		APIKeyCredentialPolicyID: input.Body.APIKeyCredentialPolicyID,
		ExpiresAt:                input.Body.ExpiresAt,
	})
	if err != nil {
		if errors.Is(err, service.ErrIdentityAlreadyExists) {
			return nil, huma.Error409Conflict("identity with this external_id already exists")
		}
		// Caller-supplied credential_policy_id that doesn't exist in this tenant
		// is a client error, not a server error.
		if errors.Is(err, service.ErrPolicyNotFound) {
			return nil, huma.Error400BadRequest("credential policy not found in this tenant")
		}
		// Subset invariant violation — the requested key policy is broader
		// than the owning identity's policy along at least one axis.
		if errors.Is(err, service.ErrPolicySubsetViolation) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		// SPIFFE path-segment validation failures are caller-fixable.
		if errors.Is(err, service.ErrInvalidIdentityField) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		log.Error().Err(err).Str("external_id", input.Body.ExternalID).Msg("failed to register agent")
		return nil, huma.Error500InternalServerError("failed to register agent")
	}

	return &RegisterAgentOutput{Body: resp}, nil
}

func (a *API) getAgentOp(ctx context.Context, input *GetAgentInput) (*GetAgentOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	resp, err := a.agentSvc.GetAgent(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, mapErr(err)
	}

	return &GetAgentOutput{Body: resp}, nil
}

func (a *API) listAgentsOp(ctx context.Context, input *ListAgentsInput) (*ListAgentsOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	resp, err := a.agentSvc.ListAgents(ctx, tenant.AccountID, tenant.ProjectID, input.IdentityType, input.Label, input.TrustLevel, input.IsActive, input.Search, input.Limit, input.Offset)
	if err != nil {
		return nil, mapErr(err)
	}

	return &ListAgentsOutput{Body: resp}, nil
}

func (a *API) updateAgentOp(ctx context.Context, input *UpdateAgentInput) (*GetAgentOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	resp, err := a.agentSvc.UpdateAgent(ctx, input.ID, tenant.AccountID, tenant.ProjectID, service.UpdateAgentRequest{
		Name:         input.Body.Name,
		SubType:      input.Body.SubType,
		TrustLevel:   input.Body.TrustLevel,
		Framework:    input.Body.Framework,
		Version:      input.Body.Version,
		Publisher:    input.Body.Publisher,
		Description:  input.Body.Description,
		Capabilities: input.Body.Capabilities,
		Labels:       input.Body.Labels,
		Metadata:     input.Body.Metadata,
		Status:       input.Body.Status,
		PublicKeyPEM: input.Body.PublicKeyPEM,
	})
	if err != nil {
		return nil, mapErr(err)
	}

	return &GetAgentOutput{Body: resp}, nil
}

func (a *API) deleteAgentOp(ctx context.Context, input *AgentActionInput) (*AgentActionOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	resp, err := a.agentSvc.DeleteAgent(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, mapErr(err)
	}

	return &AgentActionOutput{Body: resp}, nil
}

func (a *API) activateAgentOp(ctx context.Context, input *AgentActionInput) (*AgentActionOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	resp, err := a.agentSvc.ActivateAgent(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, mapErr(err)
	}

	return &AgentActionOutput{Body: resp}, nil
}

func (a *API) deactivateAgentOp(ctx context.Context, input *AgentActionInput) (*AgentActionOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	resp, err := a.agentSvc.DeactivateAgent(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, mapErr(err)
	}

	return &AgentActionOutput{Body: resp}, nil
}

func (a *API) rotateAgentKeyOp(ctx context.Context, input *AgentActionInput) (*RotateKeyOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	resp, err := a.agentSvc.RotateKey(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, mapErr(err)
	}

	return &RotateKeyOutput{Body: resp}, nil
}
