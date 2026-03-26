package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── OAuth Client types ──────────────────────────────────────────────────────

type CreateOAuthClientInput struct {
	Body struct {
		// Core
		ClientID    string `json:"client_id" required:"true" minLength:"1" doc:"Globally unique client identifier"`
		Name        string `json:"name" required:"true" minLength:"1" doc:"Client display name"`
		Description string `json:"description,omitempty" doc:"Human-readable description"`

		// Classification
		Confidential            bool   `json:"confidential,omitempty" doc:"If true, generates a client_secret for M2M flows"`
		TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty" doc:"Auth method: none, client_secret_basic, client_secret_post, private_key_jwt"`

		// OAuth configuration
		GrantTypes   []string `json:"grant_types,omitempty" doc:"Permitted OAuth grant types"`
		Scopes       []string `json:"scopes,omitempty" doc:"Permitted OAuth scopes"`
		RedirectURIs []string `json:"redirect_uris,omitempty" doc:"Allowed redirect URIs (required for authorization_code clients)"`

		// Token lifetime (0 = server default)
		AccessTokenTTL  int `json:"access_token_ttl,omitempty" doc:"Access token lifetime in seconds"`
		RefreshTokenTTL int `json:"refresh_token_ttl,omitempty" doc:"Refresh token lifetime in seconds"`

		// Key material (for private_key_jwt)
		JWKSURI string          `json:"jwks_uri,omitempty" doc:"URL to client's public JWK Set"`
		JWKS    json.RawMessage `json:"jwks,omitempty" doc:"Inline JWK Set (when no URI available)"`

		// Software identity (RFC 7591)
		SoftwareID      string `json:"software_id,omitempty" doc:"Identifies the client software"`
		SoftwareVersion string `json:"software_version,omitempty" doc:"Client software version"`

		// Ownership
		Contacts []string `json:"contacts,omitempty" doc:"Email addresses of responsible parties"`

		// Extensibility
		Metadata json.RawMessage `json:"metadata,omitempty" doc:"Arbitrary JSON metadata"`
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
		Summary:     "List all registered OAuth2 clients",
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
	client, plainSecret, err := a.oauthClientSvc.RegisterClient(ctx, service.RegisterClientRequest{
		ClientID:                input.Body.ClientID,
		Name:                    input.Body.Name,
		Description:             input.Body.Description,
		Confidential:            input.Body.Confidential,
		TokenEndpointAuthMethod: input.Body.TokenEndpointAuthMethod,
		GrantTypes:              input.Body.GrantTypes,
		Scopes:                  input.Body.Scopes,
		RedirectURIs:            input.Body.RedirectURIs,
		AccessTokenTTL:          input.Body.AccessTokenTTL,
		RefreshTokenTTL:         input.Body.RefreshTokenTTL,
		JWKSURI:                 input.Body.JWKSURI,
		JWKS:                    input.Body.JWKS,
		SoftwareID:              input.Body.SoftwareID,
		SoftwareVersion:         input.Body.SoftwareVersion,
		Contacts:                input.Body.Contacts,
		Metadata:                input.Body.Metadata,
	})
	if err != nil {
		if errors.Is(err, service.ErrOAuthClientAlreadyExists) {
			return nil, huma.Error409Conflict("oauth client with this client_id already exists")
		}
		log.Error().Err(err).Msg("failed to register oauth client")
		return nil, huma.Error500InternalServerError("failed to register oauth client")
	}

	out := &OAuthClientCreatedOutput{}
	out.Body.Client = client
	if input.Body.Confidential {
		out.Body.ClientSecret = plainSecret
		out.Body.Note = "Save client_secret now — it will not be shown again."
	} else {
		out.Body.Note = "Public PKCE client registered — no client_secret (use PKCE code_challenge instead)."
	}
	return out, nil
}

func (a *API) getOAuthClientOp(ctx context.Context, input *OAuthClientIDInput) (*OAuthClientOutput, error) {
	client, err := a.oauthClientSvc.GetClient(ctx, input.ID)
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
	clients, err := a.oauthClientSvc.ListClients(ctx)
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
	client, plainSecret, err := a.oauthClientSvc.RotateSecret(ctx, input.ID)
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
	if err := a.oauthClientSvc.DeleteClient(ctx, input.ID); err != nil {
		log.Error().Err(err).Str("client_id", input.ID).Msg("failed to delete oauth client")
		return nil, huma.Error500InternalServerError("failed to delete oauth client")
	}

	out := &DeleteOAuthClientOutput{}
	out.Body.Deleted = true
	out.Body.ID = input.ID
	return out, nil
}
