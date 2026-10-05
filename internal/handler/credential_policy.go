package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── Credential Policy types ──────────────────────────────────────────────────

type CreatePolicyInput struct {
	Body struct {
		Name                  string     `json:"name" required:"true" minLength:"1" doc:"Policy name (unique per tenant)"`
		Description           string     `json:"description,omitempty" doc:"Policy description"`
		MaxTTLSeconds         int        `json:"max_ttl_seconds,omitempty" doc:"Maximum token TTL in seconds"`
		AllowedGrantTypes     []string   `json:"allowed_grant_types,omitempty" doc:"Permitted OAuth grant types"`
		AllowedScopes         []string   `json:"allowed_scopes,omitempty" doc:"Permitted OAuth scopes"`
		RequiredTrustLevel    string     `json:"required_trust_level,omitempty" doc:"Minimum trust level required"`
		RequiredAttestation   string     `json:"required_attestation,omitempty" doc:"Minimum attestation level required"`
		MaxDelegationDepth    int        `json:"max_delegation_depth,omitempty" doc:"Maximum delegation chain depth"`
		Source                string     `json:"source,omitempty" doc:"Provenance of an auto-derived policy (e.g. 'discovery'); omit for user-authored policies"`
		SourceKey             string     `json:"source_key,omitempty" doc:"Stable dedup identity within the source; when set, create is idempotent by (source, source_key)"`
		ExpiresAt             *time.Time `json:"expires_at,omitempty" doc:"RFC3339 timestamp after which the policy is no longer valid"`
		UserGrantScopes       []string   `json:"user_grant_scopes,omitempty" doc:"Caps what this identity may hold for a person (tokens acting for a user). allowed_scopes keeps capping its own authority. Omit for no extra cap: the person's own grant bounds the chain."`
		RequiredPrincipalType string     `json:"required_principal_type,omitempty" enum:"user" doc:"Require that the token's chain is rooted in a person. user: tokens for this identity must be acting for a signed-in person, which also stops the identity minting its own workload tokens. Omit for any principal."`
		JWTTyp                string     `json:"jwt_typ,omitempty" enum:"at+jwt,JWT" doc:"Access token JOSE typ header under the rfc8693 token profile. at+jwt (the default) types the token per RFC 9068; JWT keeps it a conformant JWT-SVID for SPIFFE-strict consumers. The two specs disagree, so a token can satisfy only one. Ignored under the legacy profile, which always issues JWT."`
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
		// ExpiresAt tri-state: omit to leave unchanged, "" to clear (no expiry),
		// RFC3339 string to set.
		ExpiresAt *string `json:"expires_at,omitempty" doc:"RFC3339 expiry, or empty string to clear"`
		// JWTTyp: omit to leave unchanged, "" to reset to the profile default.
		UserGrantScopes       []string `json:"user_grant_scopes,omitempty" doc:"Caps what this identity may hold for a person; an empty list clears the cap"`
		RequiredPrincipalType *string  `json:"required_principal_type,omitempty" doc:"user to require a person-rooted chain, or empty string to allow any principal"`
		JWTTyp                *string  `json:"jwt_typ,omitempty" doc:"Access token typ header under the rfc8693 profile: at+jwt or JWT, or empty string to reset to the default (at+jwt)"`
	}
}

// ── Credential Policy routes ─────────────────────────────────────────────────

func (a *API) registerCredentialPolicyRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-credential-policy",
		Method:        http.MethodPost,
		Path:          "/credential-policies",
		Summary:       "Create a credential policy",
		Tags:          []string{"Credential Policies"},
		DefaultStatus: http.StatusCreated,
	}, a.createPolicyOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-credential-policy",
		Method:      http.MethodGet,
		Path:        "/credential-policies/{id}",
		Summary:     "Get a credential policy by ID",
		Tags:        []string{"Credential Policies"},
	}, a.getPolicyOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-credential-policies",
		Method:      http.MethodGet,
		Path:        "/credential-policies",
		Summary:     "List credential policies for the current tenant",
		Tags:        []string{"Credential Policies"},
	}, a.listPoliciesOp)

	huma.Register(api, huma.Operation{
		OperationID: "update-credential-policy",
		Method:      http.MethodPatch,
		Path:        "/credential-policies/{id}",
		Summary:     "Update a credential policy",
		Tags:        []string{"Credential Policies"},
	}, a.updatePolicyOp)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-credential-policy",
		Method:        http.MethodDelete,
		Path:          "/credential-policies/{id}",
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
		AccountID:             tenant.AccountID,
		ProjectID:             tenant.ProjectID,
		Name:                  input.Body.Name,
		Description:           input.Body.Description,
		MaxTTLSeconds:         input.Body.MaxTTLSeconds,
		AllowedGrantTypes:     input.Body.AllowedGrantTypes,
		AllowedScopes:         input.Body.AllowedScopes,
		RequiredTrustLevel:    input.Body.RequiredTrustLevel,
		RequiredAttestation:   input.Body.RequiredAttestation,
		MaxDelegationDepth:    input.Body.MaxDelegationDepth,
		Source:                input.Body.Source,
		SourceKey:             input.Body.SourceKey,
		ExpiresAt:             input.Body.ExpiresAt,
		JWTTyp:                input.Body.JWTTyp,
		RequiredPrincipalType: input.Body.RequiredPrincipalType,
		UserGrantScopes:       input.Body.UserGrantScopes,
	})
	if err != nil {
		if errors.Is(err, service.ErrPolicyNameConflict) {
			return nil, huma.Error409Conflict("credential policy with this name already exists")
		}
		if errors.Is(err, service.ErrInvalidPolicyField) {
			return nil, huma.Error400BadRequest(err.Error())
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
		Name:                  input.Body.Name,
		Description:           input.Body.Description,
		MaxTTLSeconds:         input.Body.MaxTTLSeconds,
		AllowedGrantTypes:     input.Body.AllowedGrantTypes,
		AllowedScopes:         input.Body.AllowedScopes,
		RequiredTrustLevel:    input.Body.RequiredTrustLevel,
		RequiredAttestation:   input.Body.RequiredAttestation,
		MaxDelegationDepth:    input.Body.MaxDelegationDepth,
		IsActive:              input.Body.IsActive,
		ExpiresAt:             input.Body.ExpiresAt,
		JWTTyp:                input.Body.JWTTyp,
		RequiredPrincipalType: input.Body.RequiredPrincipalType,
		UserGrantScopes:       input.Body.UserGrantScopes,
	})
	if err != nil {
		if errors.Is(err, service.ErrPolicyNotFound) {
			return nil, huma.Error404NotFound("credential policy not found")
		}
		if errors.Is(err, service.ErrInvalidPolicyField) {
			return nil, huma.Error400BadRequest(err.Error())
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
		if errors.Is(err, service.ErrPolicyInUse) {
			// Safe to surface: the delete dialog already tells the operator
			// the policy is still attached to keys. Tenant-scoped query means
			// no cross-tenant information leaks.
			return nil, huma.Error409Conflict("credential policy is still in use by one or more service keys")
		}
		if errors.Is(err, service.ErrPolicyNotFound) {
			return nil, huma.Error404NotFound("credential policy not found")
		}
		log.Error().Err(err).Str("policy_id", input.ID).Msg("failed to delete credential policy")
		return nil, huma.Error500InternalServerError("failed to delete credential policy")
	}

	return nil, nil
}
