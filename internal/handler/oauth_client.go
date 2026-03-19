package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── OAuth Client types ──────────────────────────────────────────────────────

type CreateOAuthClientInput struct {
	Body struct {
		Name       string   `json:"name" required:"true" minLength:"1" doc:"Client display name"`
		ExternalID string   `json:"external_id" required:"true" minLength:"1" doc:"Identity external_id — used as client_id and to resolve the linked identity"`
		GrantTypes []string `json:"grant_types,omitempty" doc:"Permitted OAuth grant types"`
		Scopes     []string `json:"scopes,omitempty" doc:"Permitted OAuth scopes"`
	}
}

type OAuthClientCreatedOutput struct {
	Body struct {
		Client       *domain.OAuthClient `json:"client"`
		ClientSecret string              `json:"client_secret" doc:"Save now — will not be shown again"`
		Note         string              `json:"note"`
	}
}

type OAuthClientIDInput struct {
	ID string `path:"id" doc:"OAuth client UUID"`
}

type OAuthClientOutput struct {
	Body *domain.OAuthClient
}

type OAuthClientListOutput struct {
	Body struct {
		Clients []*domain.OAuthClient `json:"clients"`
		Total   int                   `json:"total"`
	}
}

type DeleteOAuthClientOutput struct {
	Body struct {
		Deleted bool   `json:"deleted"`
		ID      string `json:"id"`
	}
}

// ── OAuth Client routes ─────────────────────────────────────────────────────

func (a *API) registerOAuthClientRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-oauth-client",
		Method:        http.MethodPost,
		Path:          "/api/v1/oauth/clients",
		Summary:       "Register an OAuth2 client",
		Tags:          []string{"OAuth Clients"},
		DefaultStatus: http.StatusCreated,
	}, a.createOAuthClientOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-oauth-client",
		Method:      http.MethodGet,
		Path:        "/api/v1/oauth/clients/{id}",
		Summary:     "Get an OAuth2 client by ID",
		Tags:        []string{"OAuth Clients"},
	}, a.getOAuthClientOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-oauth-clients",
		Method:      http.MethodGet,
		Path:        "/api/v1/oauth/clients",
		Summary:     "List OAuth2 clients for the current tenant",
		Tags:        []string{"OAuth Clients"},
	}, a.listOAuthClientsOp)

	huma.Register(api, huma.Operation{
		OperationID: "rotate-oauth-client-secret",
		Method:      http.MethodPost,
		Path:        "/api/v1/oauth/clients/{id}/rotate-secret",
		Summary:     "Rotate an OAuth2 client secret",
		Tags:        []string{"OAuth Clients"},
	}, a.rotateOAuthClientSecretOp)

	huma.Register(api, huma.Operation{
		OperationID: "delete-oauth-client",
		Method:      http.MethodDelete,
		Path:        "/api/v1/oauth/clients/{id}",
		Summary:     "Delete an OAuth2 client",
		Tags:        []string{"OAuth Clients"},
	}, a.deleteOAuthClientOp)
}

func (a *API) createOAuthClientOp(ctx context.Context, input *CreateOAuthClientInput) (*OAuthClientCreatedOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	// Resolve identity by external_id within the tenant.
	identity, err := a.identitySvc.GetIdentityByExternalID(ctx, input.Body.ExternalID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("no identity found with external_id: " + input.Body.ExternalID)
	}

	client, plainSecret, err := a.oauthClientSvc.RegisterClient(
		ctx, tenant.AccountID, tenant.ProjectID,
		input.Body.Name, input.Body.GrantTypes, input.Body.Scopes,
		identity.ExternalID, identity.ID,
	)
	if err != nil {
		if errors.Is(err, service.ErrOAuthClientAlreadyExists) {
			return nil, huma.Error409Conflict("oauth client with this client_id already exists")
		}
		log.Error().Err(err).Msg("failed to register oauth client")
		return nil, huma.Error500InternalServerError("failed to register oauth client")
	}

	out := &OAuthClientCreatedOutput{}
	out.Body.Client = client
	out.Body.ClientSecret = plainSecret
	out.Body.Note = "Save client_secret now — it will not be shown again."
	return out, nil
}

func (a *API) getOAuthClientOp(ctx context.Context, input *OAuthClientIDInput) (*OAuthClientOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	client, err := a.oauthClientSvc.GetClient(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		if errors.Is(err, service.ErrOAuthClientNotFound) {
			return nil, huma.Error404NotFound("oauth client not found")
		}
		log.Error().Err(err).Str("client_id", input.ID).Msg("failed to get oauth client")
		return nil, huma.Error500InternalServerError("failed to get oauth client")
	}

	return &OAuthClientOutput{Body: client}, nil
}

func (a *API) listOAuthClientsOp(ctx context.Context, _ *struct{}) (*OAuthClientListOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	clients, err := a.oauthClientSvc.ListClients(ctx, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		log.Error().Err(err).Msg("failed to list oauth clients")
		return nil, huma.Error500InternalServerError("failed to list oauth clients")
	}

	if clients == nil {
		clients = []*domain.OAuthClient{}
	}
	out := &OAuthClientListOutput{}
	out.Body.Clients = clients
	out.Body.Total = len(clients)
	return out, nil
}

func (a *API) rotateOAuthClientSecretOp(ctx context.Context, input *OAuthClientIDInput) (*OAuthClientCreatedOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	client, plainSecret, err := a.oauthClientSvc.RotateSecret(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		if errors.Is(err, service.ErrOAuthClientNotFound) {
			return nil, huma.Error404NotFound("oauth client not found")
		}
		log.Error().Err(err).Str("client_id", input.ID).Msg("failed to rotate oauth client secret")
		return nil, huma.Error500InternalServerError("failed to rotate secret")
	}

	out := &OAuthClientCreatedOutput{}
	out.Body.Client = client
	out.Body.ClientSecret = plainSecret
	out.Body.Note = "Save client_secret now — it will not be shown again."
	return out, nil
}

func (a *API) deleteOAuthClientOp(ctx context.Context, input *OAuthClientIDInput) (*DeleteOAuthClientOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	if err := a.oauthClientSvc.DeleteClient(ctx, input.ID, tenant.AccountID, tenant.ProjectID); err != nil {
		log.Error().Err(err).Str("client_id", input.ID).Msg("failed to delete oauth client")
		return nil, huma.Error500InternalServerError("failed to delete oauth client")
	}

	out := &DeleteOAuthClientOutput{}
	out.Body.Deleted = true
	out.Body.ID = input.ID
	return out, nil
}
