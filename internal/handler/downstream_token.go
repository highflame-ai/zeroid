package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/rs/zerolog/log"
)

// --- Input/Output types ---

type StoreDownstreamTokenInput struct {
	ServerSlug string `path:"server_slug" doc:"MCP server slug"`
	Body       struct {
		AccessToken  string          `json:"access_token" required:"true" doc:"Downstream access token"`
		RefreshToken string          `json:"refresh_token,omitempty" doc:"Downstream refresh token"`
		TokenType    string          `json:"token_type,omitempty" doc:"Token type (default: Bearer)"`
		Scopes       string          `json:"scopes,omitempty" doc:"Space-separated scopes"`
		ExpiresIn    *int            `json:"expires_in,omitempty" doc:"Seconds until expiry"`
		OAuthConfig  json.RawMessage `json:"oauth_config,omitempty" doc:"OAuth provider config for refresh"`
	}
}

type StoreDownstreamTokenOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

type GetDownstreamTokenInput struct {
	ServerSlug string `path:"server_slug" doc:"MCP server slug"`
}

type GetDownstreamTokenOutput struct {
	Body *service.GetTokenResponse
}

type DeleteDownstreamTokenInput struct {
	ServerSlug string `path:"server_slug" doc:"MCP server slug"`
}

type DeleteDownstreamTokenOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

type ListDownstreamTokensOutput struct {
	Body struct {
		Tokens []domain.DownstreamTokenStatus `json:"tokens"`
	}
}

// --- Route registration ---

func (a *API) registerDownstreamTokenRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "store-downstream-token",
		Method:        http.MethodPost,
		Path:          "/api/v1/downstream-tokens/{server_slug}",
		Summary:       "Store a downstream OAuth token for the current user",
		Tags:          []string{"Downstream Tokens"},
		DefaultStatus: http.StatusCreated,
	}, a.storeDownstreamTokenOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-downstream-token",
		Method:      http.MethodGet,
		Path:        "/api/v1/downstream-tokens/{server_slug}",
		Summary:     "Get a decrypted downstream token (for firehog injection)",
		Tags:        []string{"Downstream Tokens"},
	}, a.getDownstreamTokenOp)

	huma.Register(api, huma.Operation{
		OperationID: "delete-downstream-token",
		Method:      http.MethodDelete,
		Path:        "/api/v1/downstream-tokens/{server_slug}",
		Summary:     "Delete a downstream token (disconnect)",
		Tags:        []string{"Downstream Tokens"},
	}, a.deleteDownstreamTokenOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-downstream-tokens",
		Method:      http.MethodGet,
		Path:        "/api/v1/downstream-tokens",
		Summary:     "List connected downstream servers for the current user",
		Tags:        []string{"Downstream Tokens"},
	}, a.listDownstreamTokensOp)
}

// --- Operations ---

func (a *API) checkDownstreamTokenSvc() error {
	if a.downstreamTokenSvc == nil {
		return huma.Error503ServiceUnavailable("downstream token service not configured (set ZEROID_TOKEN_ENCRYPTION_KEY)")
	}
	return nil
}

func (a *API) storeDownstreamTokenOp(ctx context.Context, input *StoreDownstreamTokenInput) (*StoreDownstreamTokenOutput, error) {
	if err := a.checkDownstreamTokenSvc(); err != nil {
		return nil, err
	}
	tenant, err := middleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	userID := middleware.GetCallerName(ctx)
	if userID == "" {
		return nil, huma.Error401Unauthorized("missing user context")
	}

	err = a.downstreamTokenSvc.StoreToken(ctx, tenant.AccountID, tenant.ProjectID, userID, input.ServerSlug, &service.StoreTokenRequest{
		AccessToken:  input.Body.AccessToken,
		RefreshToken: input.Body.RefreshToken,
		TokenType:    input.Body.TokenType,
		Scopes:       input.Body.Scopes,
		ExpiresIn:    input.Body.ExpiresIn,
		OAuthConfig:  input.Body.OAuthConfig,
	})
	if err != nil {
		log.Error().Err(err).Str("server", input.ServerSlug).Str("user", userID).Msg("failed to store downstream token")
		return nil, huma.Error500InternalServerError("failed to store token")
	}

	out := &StoreDownstreamTokenOutput{}
	out.Body.Message = "Token stored successfully"
	return out, nil
}

func (a *API) getDownstreamTokenOp(ctx context.Context, input *GetDownstreamTokenInput) (*GetDownstreamTokenOutput, error) {
	if err := a.checkDownstreamTokenSvc(); err != nil {
		return nil, err
	}
	tenant, err := middleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	userID := middleware.GetCallerName(ctx)
	if userID == "" {
		return nil, huma.Error401Unauthorized("missing user context")
	}

	resp, err := a.downstreamTokenSvc.GetToken(ctx, tenant.AccountID, tenant.ProjectID, userID, input.ServerSlug)
	if err != nil {
		log.Warn().Err(err).Str("server", input.ServerSlug).Str("user", userID).Msg("downstream token not found")
		return nil, huma.Error404NotFound("downstream token not found")
	}

	return &GetDownstreamTokenOutput{Body: resp}, nil
}

func (a *API) deleteDownstreamTokenOp(ctx context.Context, input *DeleteDownstreamTokenInput) (*DeleteDownstreamTokenOutput, error) {
	if err := a.checkDownstreamTokenSvc(); err != nil {
		return nil, err
	}
	tenant, err := middleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	userID := middleware.GetCallerName(ctx)
	if userID == "" {
		return nil, huma.Error401Unauthorized("missing user context")
	}

	if err := a.downstreamTokenSvc.DeleteToken(ctx, tenant.AccountID, tenant.ProjectID, userID, input.ServerSlug); err != nil {
		log.Error().Err(err).Str("server", input.ServerSlug).Str("user", userID).Msg("failed to delete downstream token")
		return nil, huma.Error500InternalServerError("failed to delete token")
	}

	out := &DeleteDownstreamTokenOutput{}
	out.Body.Message = "Token deleted successfully"
	return out, nil
}

func (a *API) listDownstreamTokensOp(ctx context.Context, _ *struct{}) (*ListDownstreamTokensOutput, error) {
	if err := a.checkDownstreamTokenSvc(); err != nil {
		return nil, err
	}
	tenant, err := middleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	userID := middleware.GetCallerName(ctx)
	if userID == "" {
		return nil, huma.Error401Unauthorized("missing user context")
	}

	statuses, err := a.downstreamTokenSvc.ListByUser(ctx, tenant.AccountID, tenant.ProjectID, userID)
	if err != nil {
		log.Error().Err(err).Str("user", userID).Msg("failed to list downstream tokens")
		return nil, huma.Error500InternalServerError("failed to list tokens")
	}

	if statuses == nil {
		statuses = []domain.DownstreamTokenStatus{}
	}

	out := &ListDownstreamTokensOutput{}
	out.Body.Tokens = statuses
	return out, nil
}
