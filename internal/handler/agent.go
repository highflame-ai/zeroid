package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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
		Name         string          `json:"name" required:"true" minLength:"1" doc:"Human-readable name"`
		ExternalID   string          `json:"external_id" required:"true" minLength:"1" doc:"Unique identifier within this project"`
		IdentityType string          `json:"identity_type,omitempty" enum:"agent,application,mcp_server,service" doc:"Identity type (defaults to agent)"`
		SubType      string          `json:"sub_type,omitempty" enum:"orchestrator,autonomous,tool_agent,human_proxy,evaluator,chatbot,assistant,api_service,custom,code_agent" doc:"Operational role"`
		TrustLevel   string          `json:"trust_level,omitempty" enum:"unverified,verified_third_party,first_party" doc:"Trust level (defaults to unverified)"`
		Framework    string          `json:"framework,omitempty" doc:"Agent framework (e.g. langchain, autogen, crewai)"`
		Version      string          `json:"version,omitempty" doc:"Agent version string"`
		Publisher    string          `json:"publisher,omitempty" doc:"Agent publisher or organization"`
		Description  string          `json:"description,omitempty" doc:"Human-readable description"`
		Capabilities json.RawMessage `json:"capabilities,omitempty" doc:"JSON array of capabilities"`
		Labels       json.RawMessage `json:"labels,omitempty" doc:"JSON object of key-value labels"`
		Metadata     json.RawMessage `json:"metadata,omitempty" doc:"JSON object of opaque product-specific metadata"`
		CreatedBy    string          `json:"created_by,omitempty" doc:"User ID of the creator"`
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
	AgentType    string `query:"agent_type" doc:"Filter by agent type"`
	IdentityType string `query:"identity_type" doc:"Filter by identity type (agent, application, mcp_server, service)"`
	Product      string `query:"product" doc:"Filter by product label"`
	TrustLevel   string `query:"trust_level" doc:"Filter by trust level"`
	IsActive     string `query:"is_active" doc:"Filter by active status"`
	Limit        int    `query:"limit" default:"20" doc:"Items per page (max 100)"`
	Offset       int    `query:"offset" default:"0" doc:"Offset for pagination"`
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
		Path:          "/api/v1/agents/register",
		Summary:       "Register a new agent (creates identity + API key atomically)",
		Tags:          []string{"Agents"},
		DefaultStatus: http.StatusCreated,
	}, a.registerAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-agent",
		Method:      http.MethodGet,
		Path:        "/api/v1/agents/registry/{id}",
		Summary:     "Get an agent by identity ID",
		Tags:        []string{"Agents"},
	}, a.getAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-agents",
		Method:      http.MethodGet,
		Path:        "/api/v1/agents/registry",
		Summary:     "List agents for the current tenant",
		Tags:        []string{"Agents"},
	}, a.listAgentsOp)

	huma.Register(api, huma.Operation{
		OperationID: "update-agent",
		Method:      http.MethodPatch,
		Path:        "/api/v1/agents/registry/{id}",
		Summary:     "Update mutable fields of an agent",
		Tags:        []string{"Agents"},
	}, a.updateAgentOp)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-agent",
		Method:        http.MethodDelete,
		Path:          "/api/v1/agents/registry/{id}",
		Summary:       "Deactivate an agent (soft delete) and revoke its keys",
		Tags:          []string{"Agents"},
		DefaultStatus: http.StatusOK,
	}, a.deleteAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "activate-agent",
		Method:      http.MethodPost,
		Path:        "/api/v1/agents/registry/{id}/activate",
		Summary:     "Activate a previously deactivated agent",
		Tags:        []string{"Agents"},
	}, a.activateAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "deactivate-agent",
		Method:      http.MethodPost,
		Path:        "/api/v1/agents/registry/{id}/deactivate",
		Summary:     "Deactivate an agent without deleting it",
		Tags:        []string{"Agents"},
	}, a.deactivateAgentOp)

	huma.Register(api, huma.Operation{
		OperationID: "rotate-agent-key",
		Method:      http.MethodPost,
		Path:        "/api/v1/agents/registry/{id}/rotate-key",
		Summary:     "Rotate an agent's API key (revokes old, issues new)",
		Tags:        []string{"Agents"},
	}, a.rotateAgentKeyOp)
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
		AccountID:    tenant.AccountID,
		ProjectID:    tenant.ProjectID,
		Name:         input.Body.Name,
		ExternalID:   input.Body.ExternalID,
		IdentityType: domain.IdentityType(input.Body.IdentityType),
		SubType:      domain.SubType(input.Body.SubType),
		TrustLevel:   domain.TrustLevel(input.Body.TrustLevel),
		Framework:    input.Body.Framework,
		Version:      input.Body.Version,
		Publisher:    input.Body.Publisher,
		Description:  input.Body.Description,
		Capabilities: input.Body.Capabilities,
		Labels:       input.Body.Labels,
		Metadata:     input.Body.Metadata,
		CreatedBy:    createdBy,
	})
	if err != nil {
		if errors.Is(err, service.ErrIdentityAlreadyExists) {
			return nil, huma.Error409Conflict("identity with this external_id already exists")
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

	resp, err := a.agentSvc.ListAgents(ctx, tenant.AccountID, tenant.ProjectID, input.IdentityType, input.Product, input.Limit, input.Offset)
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
