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

// ── Credential Policy types ──────────────────────────────────────────────────

type CreatePolicyInput struct {
	Body struct {
		Name                string   `json:"name" required:"true" minLength:"1" doc:"Policy name (unique per tenant)"`
		Description         string   `json:"description,omitempty" doc:"Policy description"`
		MaxTTLSeconds       int      `json:"max_ttl_seconds,omitempty" doc:"Maximum token TTL in seconds"`
		AllowedGrantTypes   []string `json:"allowed_grant_types,omitempty" doc:"Permitted OAuth grant types"`
		AllowedScopes       []string `json:"allowed_scopes,omitempty" doc:"Permitted OAuth scopes"`
		RequiredTrustLevel  string   `json:"required_trust_level,omitempty" doc:"Minimum trust level required"`
		RequiredAttestation string   `json:"required_attestation,omitempty" doc:"Minimum attestation level required"`
		MaxDelegationDepth  int      `json:"max_delegation_depth,omitempty" doc:"Maximum delegation chain depth"`
	}
}

type PolicyOutput struct {
	Body *domain.CredentialPolicy
}

type PolicyIDInput struct {
	ID string `path:"id" doc:"Policy UUID"`
}

type PolicyListOutput struct {
	Body struct {
		CredentialPolicies []*domain.CredentialPolicy `json:"credential_policies"`
		Total              int                        `json:"total"`
	}
}

type UpdatePolicyInput struct {
	ID   string `path:"id" doc:"Policy UUID"`
	Body struct {
		Name                string   `json:"name,omitempty" doc:"Policy name"`
		Description         *string  `json:"description,omitempty" doc:"Policy description"`
		MaxTTLSeconds       *int     `json:"max_ttl_seconds,omitempty" doc:"Maximum token TTL"`
		AllowedGrantTypes   []string `json:"allowed_grant_types,omitempty" doc:"Permitted grant types"`
		AllowedScopes       []string `json:"allowed_scopes,omitempty" doc:"Permitted scopes"`
		RequiredTrustLevel  *string  `json:"required_trust_level,omitempty" doc:"Required trust level"`
		RequiredAttestation *string  `json:"required_attestation,omitempty" doc:"Required attestation level"`
		MaxDelegationDepth  *int     `json:"max_delegation_depth,omitempty" doc:"Max delegation depth"`
		IsActive            *bool    `json:"is_active,omitempty" doc:"Active status"`
	}
}

// ── Credential Policy routes ─────────────────────────────────────────────────

func (a *API) registerCredentialPolicyRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-credential-policy",
		Method:        http.MethodPost,
		Path:          "/api/v1/credential-policies",
		Summary:       "Create a credential policy",
		Tags:          []string{"Credential Policies"},
		DefaultStatus: http.StatusCreated,
	}, a.createPolicyOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-credential-policy",
		Method:      http.MethodGet,
		Path:        "/api/v1/credential-policies/{id}",
		Summary:     "Get a credential policy by ID",
		Tags:        []string{"Credential Policies"},
	}, a.getPolicyOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-credential-policies",
		Method:      http.MethodGet,
		Path:        "/api/v1/credential-policies",
		Summary:     "List credential policies for the current tenant",
		Tags:        []string{"Credential Policies"},
	}, a.listPoliciesOp)

	huma.Register(api, huma.Operation{
		OperationID: "update-credential-policy",
		Method:      http.MethodPatch,
		Path:        "/api/v1/credential-policies/{id}",
		Summary:     "Update a credential policy",
		Tags:        []string{"Credential Policies"},
	}, a.updatePolicyOp)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-credential-policy",
		Method:        http.MethodDelete,
		Path:          "/api/v1/credential-policies/{id}",
		Summary:       "Delete a credential policy",
		Tags:          []string{"Credential Policies"},
		DefaultStatus: http.StatusNoContent,
	}, a.deletePolicyOp)
}

func (a *API) createPolicyOp(ctx context.Context, input *CreatePolicyInput) (*PolicyOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	policy, err := a.credentialPolicySvc.CreatePolicy(ctx, service.CreatePolicyRequest{
		AccountID:           tenant.AccountID,
		ProjectID:           tenant.ProjectID,
		Name:                input.Body.Name,
		Description:         input.Body.Description,
		MaxTTLSeconds:       input.Body.MaxTTLSeconds,
		AllowedGrantTypes:   input.Body.AllowedGrantTypes,
		AllowedScopes:       input.Body.AllowedScopes,
		RequiredTrustLevel:  input.Body.RequiredTrustLevel,
		RequiredAttestation: input.Body.RequiredAttestation,
		MaxDelegationDepth:  input.Body.MaxDelegationDepth,
	})
	if err != nil {
		if errors.Is(err, service.ErrPolicyNameConflict) {
			return nil, huma.Error409Conflict("credential policy with this name already exists")
		}
		log.Error().Err(err).Str("name", input.Body.Name).Msg("failed to create credential policy")
		return nil, huma.Error500InternalServerError("failed to create credential policy")
	}

	return &PolicyOutput{Body: policy}, nil
}

func (a *API) getPolicyOp(ctx context.Context, input *PolicyIDInput) (*PolicyOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	policy, err := a.credentialPolicySvc.GetPolicy(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("credential policy not found")
	}

	return &PolicyOutput{Body: policy}, nil
}

func (a *API) listPoliciesOp(ctx context.Context, _ *struct{}) (*PolicyListOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	policies, err := a.credentialPolicySvc.ListPolicies(ctx, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		log.Error().Err(err).Msg("failed to list credential policies")
		return nil, huma.Error500InternalServerError("failed to list credential policies")
	}

	if policies == nil {
		policies = []*domain.CredentialPolicy{}
	}
	out := &PolicyListOutput{}
	out.Body.CredentialPolicies = policies
	out.Body.Total = len(policies)
	return out, nil
}

func (a *API) updatePolicyOp(ctx context.Context, input *UpdatePolicyInput) (*PolicyOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	policy, err := a.credentialPolicySvc.UpdatePolicy(ctx, input.ID, tenant.AccountID, tenant.ProjectID, service.UpdatePolicyRequest{
		Name:                input.Body.Name,
		Description:         input.Body.Description,
		MaxTTLSeconds:       input.Body.MaxTTLSeconds,
		AllowedGrantTypes:   input.Body.AllowedGrantTypes,
		AllowedScopes:       input.Body.AllowedScopes,
		RequiredTrustLevel:  input.Body.RequiredTrustLevel,
		RequiredAttestation: input.Body.RequiredAttestation,
		MaxDelegationDepth:  input.Body.MaxDelegationDepth,
		IsActive:            input.Body.IsActive,
	})
	if err != nil {
		if errors.Is(err, service.ErrPolicyNotFound) {
			return nil, huma.Error404NotFound("credential policy not found")
		}
		log.Error().Err(err).Str("policy_id", input.ID).Msg("failed to update credential policy")
		return nil, huma.Error500InternalServerError("failed to update credential policy")
	}

	return &PolicyOutput{Body: policy}, nil
}

func (a *API) deletePolicyOp(ctx context.Context, input *PolicyIDInput) (*struct{}, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	if err := a.credentialPolicySvc.DeletePolicy(ctx, input.ID, tenant.AccountID, tenant.ProjectID); err != nil {
		log.Error().Err(err).Str("policy_id", input.ID).Msg("failed to delete credential policy")
		return nil, huma.Error500InternalServerError("failed to delete credential policy")
	}

	return nil, nil
}
