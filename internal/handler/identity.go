package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── Identity types ───────────────────────────────────────────────────────────

type CreateIdentityInput struct {
	Body struct {
		ExternalID         string          `json:"external_id" required:"true" minLength:"1" doc:"Unique identifier within this project"`
		Name               string          `json:"name,omitempty" doc:"Human-readable identity name"`
		TrustLevel         string          `json:"trust_level,omitempty" enum:"unverified,verified_third_party,first_party" doc:"Trust level"`
		IdentityType       string          `json:"identity_type,omitempty" enum:"agent,application,mcp_server,service" doc:"Identity type"`
		SubType            string          `json:"sub_type,omitempty" enum:"orchestrator,autonomous,tool_agent,human_proxy,evaluator,chatbot,assistant,api_service,custom,code_agent" doc:"Sub-type within identity type"`
		OwnerUserID        string          `json:"owner_user_id" required:"true" minLength:"1" doc:"User ID of the identity owner"`
		AllowedScopes      []string        `json:"allowed_scopes,omitempty" doc:"OAuth scopes this identity may request"`
		PublicKeyPEM       string          `json:"public_key_pem,omitempty" doc:"ECDSA P-256 public key in PEM format for jwt_bearer grant"`
		Framework          string          `json:"framework,omitempty" doc:"Agent framework (e.g. langchain, autogen, crewai)"`
		Version            string          `json:"version,omitempty" doc:"Agent version string"`
		Publisher          string          `json:"publisher,omitempty" doc:"Agent publisher or organization"`
		Description        string          `json:"description,omitempty" doc:"Human-readable description of the identity"`
		Capabilities       json.RawMessage `json:"capabilities,omitempty" doc:"JSON array of capabilities"`
		Labels             json.RawMessage `json:"labels,omitempty" doc:"JSON object of key-value labels"`
	}
}

type IdentityOutput struct {
	Body *domain.Identity
}

type IdentityIDInput struct {
	ID string `path:"id" doc:"Identity UUID"`
}

type IdentityListOutput struct {
	Body struct {
		Identities []*domain.Identity `json:"identities"`
		Total      int                `json:"total"`
	}
}

type UpdateIdentityInput struct {
	ID   string `path:"id" doc:"Identity UUID"`
	Body struct {
		Name               string          `json:"name,omitempty" doc:"Human-readable identity name"`
		TrustLevel         string          `json:"trust_level,omitempty" enum:"unverified,verified_third_party,first_party" doc:"Trust level"`
		IdentityType       string          `json:"identity_type,omitempty" enum:"agent,application,mcp_server,service" doc:"Identity type"`
		SubType            string          `json:"sub_type,omitempty" enum:"orchestrator,autonomous,tool_agent,human_proxy,evaluator,chatbot,assistant,api_service,custom,code_agent" doc:"Sub-type"`
		OwnerUserID        string          `json:"owner_user_id,omitempty" doc:"Owner user ID"`
		AllowedScopes      []string        `json:"allowed_scopes,omitempty" doc:"OAuth scopes"`
		PublicKeyPEM       string          `json:"public_key_pem,omitempty" doc:"ECDSA public key PEM"`
		Framework          *string         `json:"framework,omitempty" doc:"Agent framework"`
		Version            *string         `json:"version,omitempty" doc:"Agent version"`
		Publisher          *string         `json:"publisher,omitempty" doc:"Agent publisher"`
		Description        *string         `json:"description,omitempty" doc:"Agent description"`
		Capabilities       json.RawMessage `json:"capabilities,omitempty" doc:"Capabilities"`
		Labels             json.RawMessage `json:"labels,omitempty" doc:"Key-value labels"`
		Status             *string         `json:"status,omitempty" enum:"active,suspended,deactivated" doc:"Identity status"`
	}
}

type DeleteOutput struct {
	// 204 No Content — empty body
}

// ── Identity routes ──────────────────────────────────────────────────────────

func (a *API) registerIdentityRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "identity-schema",
		Method:      http.MethodGet,
		Path:        "/api/v1/identities/schema",
		Summary:     "Get the identity type schema (valid types, sub-types, trust levels, statuses)",
		Tags:        []string{"Identities"},
	}, a.identitySchemaOp)

	huma.Register(api, huma.Operation{
		OperationID:   "create-identity",
		Method:        http.MethodPost,
		Path:          "/api/v1/identities",
		Summary:       "Register a new identity",
		Tags:          []string{"Identities"},
		DefaultStatus: http.StatusCreated,
	}, a.createIdentityOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-identity",
		Method:      http.MethodGet,
		Path:        "/api/v1/identities/{id}",
		Summary:     "Get an identity by ID",
		Tags:        []string{"Identities"},
	}, a.getIdentityOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-identities",
		Method:      http.MethodGet,
		Path:        "/api/v1/identities",
		Summary:     "List all identities for the current tenant",
		Tags:        []string{"Identities"},
	}, a.listIdentitiesOp)

	huma.Register(api, huma.Operation{
		OperationID: "update-identity",
		Method:      http.MethodPatch,
		Path:        "/api/v1/identities/{id}",
		Summary:     "Update mutable fields of an identity",
		Tags:        []string{"Identities"},
	}, a.updateIdentityOp)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-identity",
		Method:        http.MethodDelete,
		Path:          "/api/v1/identities/{id}",
		Summary:       "Deactivate an identity (soft delete)",
		Tags:          []string{"Identities"},
		DefaultStatus: http.StatusNoContent,
	}, a.deleteIdentityOp)
}

type IdentitySchemaOutput struct {
	Body *domain.IdentitySchema
}

func (a *API) identitySchemaOp(_ context.Context, _ *struct{}) (*IdentitySchemaOutput, error) {
	return &IdentitySchemaOutput{Body: domain.GetIdentitySchema()}, nil
}

func (a *API) createIdentityOp(ctx context.Context, input *CreateIdentityInput) (*IdentityOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	trustLevel := domain.TrustLevel(input.Body.TrustLevel)
	if trustLevel != "" && !trustLevel.Valid() {
		return nil, huma.Error400BadRequest("invalid trust_level: must be unverified, verified_third_party, or first_party")
	}

	identityType := domain.IdentityType(input.Body.IdentityType)
	if identityType != "" && !identityType.Valid() {
		return nil, huma.Error400BadRequest("invalid identity_type: must be agent, application, mcp_server, or service")
	}

	subType := domain.SubType(input.Body.SubType)
	if subType != "" && !subType.ValidForIdentityType(identityType) {
		return nil, huma.Error400BadRequest("invalid sub_type for the given identity_type")
	}

	createdBy := internalMiddleware.GetCallerName(ctx)

	identity, err := a.identitySvc.RegisterIdentity(ctx, service.RegisterIdentityRequest{
		AccountID:     tenant.AccountID,
		ProjectID:     tenant.ProjectID,
		ExternalID:    input.Body.ExternalID,
		Name:          input.Body.Name,
		TrustLevel:    trustLevel,
		IdentityType:  identityType,
		SubType:       subType,
		OwnerUserID:   input.Body.OwnerUserID,
		AllowedScopes: input.Body.AllowedScopes,
		PublicKeyPEM:  input.Body.PublicKeyPEM,
		Framework:     input.Body.Framework,
		Version:       input.Body.Version,
		Publisher:     input.Body.Publisher,
		Description:   input.Body.Description,
		Capabilities:  input.Body.Capabilities,
		Labels:        input.Body.Labels,
		CreatedBy:     createdBy,
	})
	if err != nil {
		if errors.Is(err, service.ErrIdentityAlreadyExists) {
			return nil, huma.Error409Conflict("identity with this external_id already exists")
		}
		log.Error().Err(err).Str("external_id", input.Body.ExternalID).Msg("failed to register identity")
		return nil, huma.Error500InternalServerError("failed to create identity")
	}

	return &IdentityOutput{Body: identity}, nil
}

func (a *API) getIdentityOp(ctx context.Context, input *IdentityIDInput) (*IdentityOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	identity, err := a.identitySvc.GetIdentity(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("identity not found")
	}

	return &IdentityOutput{Body: identity}, nil
}

func (a *API) listIdentitiesOp(ctx context.Context, _ *struct{}) (*IdentityListOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	identities, err := a.identitySvc.ListIdentities(ctx, tenant.AccountID, tenant.ProjectID, "", "")
	if err != nil {
		log.Error().Err(err).Msg("failed to list identities")
		return nil, huma.Error500InternalServerError("failed to list identities")
	}

	if identities == nil {
		identities = []*domain.Identity{}
	}
	out := &IdentityListOutput{}
	out.Body.Identities = identities
	out.Body.Total = len(identities)
	return out, nil
}

func (a *API) updateIdentityOp(ctx context.Context, input *UpdateIdentityInput) (*IdentityOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	trustLevel := domain.TrustLevel(input.Body.TrustLevel)
	if trustLevel != "" && !trustLevel.Valid() {
		return nil, huma.Error400BadRequest("invalid trust_level")
	}
	identityType := domain.IdentityType(input.Body.IdentityType)
	if identityType != "" && !identityType.Valid() {
		return nil, huma.Error400BadRequest("invalid identity_type")
	}
	subType := domain.SubType(input.Body.SubType)
	if subType != "" && !subType.ValidForIdentityType(identityType) {
		return nil, huma.Error400BadRequest("invalid sub_type")
	}

	var status *domain.IdentityStatus
	if input.Body.Status != nil {
		s := domain.IdentityStatus(*input.Body.Status)
		if !s.Valid() {
			return nil, huma.Error400BadRequest("invalid status")
		}
		status = &s
	}

	identity, err := a.identitySvc.UpdateIdentity(ctx, input.ID, tenant.AccountID, tenant.ProjectID, service.UpdateIdentityRequest{
		Name:          input.Body.Name,
		TrustLevel:    trustLevel,
		IdentityType:  identityType,
		SubType:       subType,
		OwnerUserID:   input.Body.OwnerUserID,
		AllowedScopes: input.Body.AllowedScopes,
		PublicKeyPEM:  input.Body.PublicKeyPEM,
		Framework:     input.Body.Framework,
		Version:       input.Body.Version,
		Publisher:     input.Body.Publisher,
		Description:   input.Body.Description,
		Capabilities:  input.Body.Capabilities,
		Labels:        input.Body.Labels,
		Status:        status,
	})
	if err != nil {
		log.Error().Err(err).Str("identity_id", input.ID).Msg("failed to update identity")
		return nil, huma.Error500InternalServerError("failed to update identity")
	}

	return &IdentityOutput{Body: identity}, nil
}

func (a *API) deleteIdentityOp(ctx context.Context, input *IdentityIDInput) (*struct{}, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	if err := a.identitySvc.DeleteIdentity(ctx, input.ID, tenant.AccountID, tenant.ProjectID); err != nil {
		log.Error().Err(err).Str("identity_id", input.ID).Msg("failed to delete identity")
		return nil, huma.Error500InternalServerError("failed to delete identity")
	}

	return nil, nil
}
