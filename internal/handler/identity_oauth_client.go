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

// An identity's OAuth clients, scoped to the caller's tenant.
//
// /oauth/clients is an operator surface: it lists every client and deletes any
// client by UUID, because a client carries no tenant of its own. These routes
// reach a client only through an identity resolved in the caller's tenant, so
// a tenant admin can find and remove the clients linked to one of its
// identities, for example to free a client_id for another identity, and
// nothing else.

// IdentityOAuthClientInput names one OAuth client of one identity.
type IdentityOAuthClientInput struct {
	ID         string `path:"id" doc:"Identity UUID"`
	ClientUUID string `path:"client_uuid" doc:"OAuth client UUID (the client's id, not its client_id)"`
}

func (a *API) registerIdentityOAuthClientRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-identity-oauth-clients",
		Method:      http.MethodGet,
		Path:        "/identities/{id}/oauth-clients",
		Summary:     "List the OAuth2 clients linked to an identity",
		Description: "Returns the clients whose identity_id is this identity. The identity must be in the caller's tenant; otherwise 404.",
		Tags:        []string{"Identities"},
	}, a.listIdentityOAuthClientsOp)

	huma.Register(api, huma.Operation{
		OperationID: "delete-identity-oauth-client",
		Method:      http.MethodDelete,
		Path:        "/identities/{id}/oauth-clients/{client_uuid}",
		Summary:     "Delete an OAuth2 client linked to an identity",
		Description: "Hard-deletes the client only while it is linked to this identity, which frees its client_id for another identity. " +
			"The identity must be in the caller's tenant. A client linked to another identity, or to none, is 404.",
		Tags: []string{"Identities"},
	}, a.deleteIdentityOAuthClientOp)
}

// identityInTenant resolves id in the caller's tenant, as a 404 when it is not
// there, so a caller cannot tell another tenant's identity from a missing one.
func (a *API) identityInTenant(ctx context.Context, id string) (*domain.Identity, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	identity, err := a.identitySvc.GetIdentity(ctx, id, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("identity not found")
	}

	return identity, nil
}

func (a *API) listIdentityOAuthClientsOp(ctx context.Context, input *IdentityIDInput) (*OAuthClientListOutput, error) {
	identity, err := a.identityInTenant(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	clients, err := a.oauthClientSvc.ListClientsForIdentity(ctx, identity.ID)
	if err != nil {
		log.Error().Err(err).Str("identity_id", identity.ID).Msg("failed to list oauth clients for identity")
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

func (a *API) deleteIdentityOAuthClientOp(ctx context.Context, input *IdentityOAuthClientInput) (*DeleteOAuthClientOutput, error) {
	identity, err := a.identityInTenant(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if err := a.oauthClientSvc.DeleteClientForIdentity(ctx, identity.ID, input.ClientUUID); err != nil {
		if herr := approvalChannelWriteError(err); herr != nil {
			return nil, herr
		}
		if errors.Is(err, service.ErrOAuthClientNotFound) {
			return nil, huma.Error404NotFound("oauth client not found for this identity")
		}
		log.Error().Err(err).Str("identity_id", identity.ID).Str("oauth_client", input.ClientUUID).
			Msg("failed to delete oauth client for identity")
		return nil, huma.Error500InternalServerError("failed to delete oauth client")
	}

	log.Info().Str("identity_id", identity.ID).Str("account_id", identity.AccountID).
		Str("oauth_client", input.ClientUUID).Msg("oauth client deleted for identity")

	out := &DeleteOAuthClientOutput{}
	out.Body.Deleted = true
	out.Body.ID = input.ClientUUID
	return out, nil
}
