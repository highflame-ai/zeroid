package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── Credential types ─────────────────────────────────────────────────────────

type IssueCredentialInput struct {
	Body struct {
		IdentityID string   `json:"identity_id" required:"true" minLength:"1" doc:"UUID of the agent identity"`
		Scopes     []string `json:"scopes,omitempty" doc:"Requested OAuth scopes"`
		TTL        int      `json:"ttl_seconds,omitempty" doc:"Requested token TTL in seconds"`
		GrantType  string   `json:"grant_type,omitempty" doc:"OAuth grant type"`
		Audience   []string `json:"audience,omitempty" doc:"Intended audience for the token"`
	}
}

type IssueCredentialOutput struct {
	Body struct {
		Token      *domain.AccessToken      `json:"token"`
		Credential *domain.IssuedCredential `json:"credential"`
	}
}

type CredentialIDInput struct {
	ID string `path:"id" doc:"Credential UUID"`
}

type CredentialOutput struct {
	Body *domain.IssuedCredential
}

type CredentialListInput struct {
	IdentityID string `query:"identity_id" required:"true" doc:"Filter by identity UUID"`
}

type CredentialListOutput struct {
	Body struct {
		Credentials []*domain.IssuedCredential `json:"credentials"`
		Total       int                        `json:"total"`
	}
}

type RevokeCredentialInput struct {
	ID   string `path:"id" doc:"Credential UUID"`
	Body struct {
		Reason string `json:"reason,omitempty" doc:"Revocation reason"`
	}
}

type CredentialRevokeOutput struct {
	Body struct {
		Revoked bool   `json:"revoked"`
		ID      string `json:"id"`
	}
}

// ── Credential routes ────────────────────────────────────────────────────────

func (a *API) registerCredentialRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "issue-credential",
		Method:        http.MethodPost,
		Path:          "/api/v1/credentials/issue",
		Summary:       "Issue a short-lived JWT credential for an agent identity",
		Tags:          []string{"Credentials"},
		DefaultStatus: http.StatusCreated,
	}, a.issueCredentialOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-credential",
		Method:      http.MethodGet,
		Path:        "/api/v1/credentials/{id}",
		Summary:     "Get a credential record by ID",
		Tags:        []string{"Credentials"},
	}, a.getCredentialOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-credentials",
		Method:      http.MethodGet,
		Path:        "/api/v1/credentials",
		Summary:     "List credentials for an identity",
		Tags:        []string{"Credentials"},
	}, a.listCredentialsOp)

	huma.Register(api, huma.Operation{
		OperationID: "revoke-credential",
		Method:      http.MethodPost,
		Path:        "/api/v1/credentials/{id}/revoke",
		Summary:     "Revoke a credential",
		Tags:        []string{"Credentials"},
	}, a.revokeCredentialOp)

	huma.Register(api, huma.Operation{
		OperationID:   "rotate-credential",
		Method:        http.MethodPost,
		Path:          "/api/v1/credentials/{id}/rotate",
		Summary:       "Rotate a credential (revoke old + issue new)",
		Tags:          []string{"Credentials"},
		DefaultStatus: http.StatusCreated,
	}, a.rotateCredentialOp)
}

func (a *API) issueCredentialOp(ctx context.Context, input *IssueCredentialInput) (*IssueCredentialOutput, error) {
	_ = time.Now() // preserve start-time pattern for future metrics

	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	identity, err := a.identitySvc.GetIdentity(ctx, input.Body.IdentityID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("identity not found")
	}

	grantType := domain.GrantType(input.Body.GrantType)
	if grantType == "" {
		grantType = domain.GrantTypeClientCredentials
	}

	accessToken, cred, err := a.credSvc.IssueCredential(ctx, service.IssueRequest{
		Identity:  identity,
		Scopes:    input.Body.Scopes,
		TTL:       input.Body.TTL,
		GrantType: grantType,
		Audience:  input.Body.Audience,
	})
	if err != nil {
		log.Error().Err(err).Str("identity_id", input.Body.IdentityID).Msg("failed to issue credential")
		return nil, huma.Error500InternalServerError("failed to issue credential")
	}

	out := &IssueCredentialOutput{}
	out.Body.Token = accessToken
	out.Body.Credential = cred
	return out, nil
}

func (a *API) getCredentialOp(ctx context.Context, input *CredentialIDInput) (*CredentialOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	cred, err := a.credSvc.GetCredential(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("credential not found")
	}

	return &CredentialOutput{Body: cred}, nil
}

func (a *API) listCredentialsOp(ctx context.Context, input *CredentialListInput) (*CredentialListOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	creds, err := a.credSvc.ListCredentials(ctx, input.IdentityID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		log.Error().Err(err).Str("identity_id", input.IdentityID).Msg("failed to list credentials")
		return nil, huma.Error500InternalServerError("failed to list credentials")
	}

	out := &CredentialListOutput{}
	out.Body.Credentials = creds
	out.Body.Total = len(creds)
	return out, nil
}

func (a *API) revokeCredentialOp(ctx context.Context, input *RevokeCredentialInput) (*CredentialRevokeOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	if err := a.credSvc.RevokeCredential(ctx, input.ID, tenant.AccountID, tenant.ProjectID, input.Body.Reason); err != nil {
		log.Error().Err(err).Str("credential_id", input.ID).Msg("failed to revoke credential")
		return nil, huma.Error500InternalServerError("failed to revoke credential")
	}

	out := &CredentialRevokeOutput{}
	out.Body.Revoked = true
	out.Body.ID = input.ID
	return out, nil
}

func (a *API) rotateCredentialOp(ctx context.Context, input *CredentialIDInput) (*IssueCredentialOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	old, err := a.credSvc.GetCredential(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("credential not found")
	}

	if old.IdentityID == nil {
		return nil, huma.Error400BadRequest("credential has no linked identity and cannot be rotated")
	}
	identity, err := a.identitySvc.GetIdentity(ctx, *old.IdentityID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("identity not found")
	}

	accessToken, newCred, err := a.credSvc.RotateCredential(ctx, input.ID, tenant.AccountID, tenant.ProjectID, identity)
	if err != nil {
		log.Error().Err(err).Str("credential_id", input.ID).Msg("failed to rotate credential")
		return nil, huma.Error500InternalServerError("failed to rotate credential")
	}

	out := &IssueCredentialOutput{}
	out.Body.Token = accessToken
	out.Body.Credential = newCred
	return out, nil
}
