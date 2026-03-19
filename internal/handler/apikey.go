package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── API key types ────────────────────────────────────────────────────────────

type CreateAPIKeyInput struct {
	Body struct {
		Name          string          `json:"name" required:"true" minLength:"1" doc:"Human-readable key name"`
		Description   string          `json:"description,omitempty" doc:"Key description"`
		IdentityID    string          `json:"identity_id,omitempty" doc:"Optional identity link"`
		Scopes        []string        `json:"scopes,omitempty" doc:"Allowed scopes"`
		Environment   string          `json:"environment,omitempty" enum:"live,test" doc:"Environment (default: live)"`
		ExpiresInDays *int            `json:"expires_in_days,omitempty" doc:"Expiry in days (nil = never)"`
		Metadata      json.RawMessage `json:"metadata,omitempty" doc:"Arbitrary JSON metadata for extensions"`
	}
}

type CreateAPIKeyOutput struct {
	Body *service.CreateAPIKeyResponse
}

type APIKeyIDInput struct {
	ID string `path:"id" doc:"API key UUID"`
}

type APIKeyOutput struct {
	Body *domain.APIKey
}

type APIKeyListInput struct {
	Page  int `query:"page" default:"1" doc:"Page number"`
	Limit int `query:"limit" default:"20" doc:"Items per page (max 100)"`
}

type APIKeyListOutput struct {
	Body struct {
		Keys  []*domain.APIKey `json:"keys"`
		Total int              `json:"total"`
		Page  int              `json:"page"`
		Limit int              `json:"limit"`
	}
}

type RevokeAPIKeyInput struct {
	ID   string `path:"id" doc:"API key UUID"`
	Body struct {
		Reason string `json:"reason,omitempty" doc:"Revocation reason"`
	}
}

type RevokeAPIKeyOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

// ── API key routes ───────────────────────────────────────────────────────────

func (a *API) registerAPIKeyRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-api-key",
		Method:        http.MethodPost,
		Path:          "/api/v1/api-keys",
		Summary:       "Create a new API key",
		Tags:          []string{"API Keys"},
		DefaultStatus: http.StatusCreated,
	}, a.createAPIKeyOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-api-key",
		Method:      http.MethodGet,
		Path:        "/api/v1/api-keys/{id}",
		Summary:     "Get an API key by ID",
		Tags:        []string{"API Keys"},
	}, a.getAPIKeyOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-api-keys",
		Method:      http.MethodGet,
		Path:        "/api/v1/api-keys",
		Summary:     "List API keys for the current tenant",
		Tags:        []string{"API Keys"},
	}, a.listAPIKeysOp)

	huma.Register(api, huma.Operation{
		OperationID: "revoke-api-key",
		Method:      http.MethodPost,
		Path:        "/api/v1/api-keys/{id}/revoke",
		Summary:     "Revoke an API key",
		Tags:        []string{"API Keys"},
	}, a.revokeAPIKeyOp)
}

func (a *API) createAPIKeyOp(ctx context.Context, input *CreateAPIKeyInput) (*CreateAPIKeyOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	createdBy := internalMiddleware.GetCallerName(ctx)

	resp, err := a.apiKeySvc.CreateKey(ctx, service.CreateAPIKeyRequest{
		AccountID:     tenant.AccountID,
		ProjectID:     tenant.ProjectID,
		CreatedBy:     createdBy,
		Name:          input.Body.Name,
		Description:   input.Body.Description,
		IdentityID:    input.Body.IdentityID,
		Scopes:        input.Body.Scopes,
		Environment:   input.Body.Environment,
		ExpiresInDays: input.Body.ExpiresInDays,
		Metadata:      input.Body.Metadata,
	})
	if err != nil {
		log.Error().Err(err).Str("name", input.Body.Name).Msg("failed to create API key")
		return nil, huma.Error500InternalServerError("failed to create API key")
	}

	return &CreateAPIKeyOutput{Body: resp}, nil
}

func (a *API) getAPIKeyOp(ctx context.Context, input *APIKeyIDInput) (*APIKeyOutput, error) {
	if _, err := internalMiddleware.GetTenant(ctx); err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	sk, err := a.apiKeySvc.GetKey(ctx, input.ID)
	if err != nil {
		return nil, huma.Error404NotFound("API key not found")
	}

	return &APIKeyOutput{Body: sk}, nil
}

func (a *API) listAPIKeysOp(ctx context.Context, input *APIKeyListInput) (*APIKeyListOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	keys, total, err := a.apiKeySvc.ListKeys(ctx, tenant.AccountID, tenant.ProjectID, "", "", input.Page, input.Limit)
	if err != nil {
		log.Error().Err(err).Msg("failed to list API keys")
		return nil, huma.Error500InternalServerError("failed to list API keys")
	}

	if keys == nil {
		keys = []*domain.APIKey{}
	}
	out := &APIKeyListOutput{}
	out.Body.Keys = keys
	out.Body.Total = total
	out.Body.Page = input.Page
	out.Body.Limit = input.Limit
	return out, nil
}

func (a *API) revokeAPIKeyOp(ctx context.Context, input *RevokeAPIKeyInput) (*RevokeAPIKeyOutput, error) {
	if _, err := internalMiddleware.GetTenant(ctx); err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	revokedBy := internalMiddleware.GetCallerName(ctx)

	if err := a.apiKeySvc.RevokeKey(ctx, input.ID, revokedBy, input.Body.Reason); err != nil {
		log.Error().Err(err).Str("key_id", input.ID).Msg("failed to revoke API key")
		return nil, huma.Error500InternalServerError("failed to revoke API key")
	}

	out := &RevokeAPIKeyOutput{}
	out.Body.Message = "API key revoked"
	return out, nil
}
