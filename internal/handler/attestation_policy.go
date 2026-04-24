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

// ── Attestation policy types ─────────────────────────────────────────────────

// UpsertAttestationPolicyInput is the request body for creating or updating
// a tenant's policy for a specific proof type. The unique (tenant, proof_type)
// key means there's no separate create vs. update endpoint — callers PUT
// whatever shape they want and the service routes to insert or update.
type UpsertAttestationPolicyInput struct {
	Body struct {
		ProofType string          `json:"proof_type" required:"true" enum:"image_hash,oidc_token,tpm" doc:"Proof type this policy governs"`
		Config    json.RawMessage `json:"config" required:"true" doc:"Verifier-specific configuration (shape depends on proof_type)"`
		IsActive  *bool           `json:"is_active,omitempty" doc:"Set false to disable without deleting (default: true)"`
	}
}

type AttestationPolicyOutput struct {
	Body *domain.AttestationPolicy
}

type AttestationPolicyListOutput struct {
	Body struct {
		Policies []*domain.AttestationPolicy `json:"policies"`
	}
}

type AttestationPolicyIDInput struct {
	ID string `path:"id" doc:"Attestation policy UUID"`
}

// ── Attestation policy routes ────────────────────────────────────────────────

func (a *API) registerAttestationPolicyRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "upsert-attestation-policy",
		Method:        http.MethodPut,
		Path:          "/attestation-policies",
		Summary:       "Create or update an attestation policy for a proof type",
		Description:   "One policy per (tenant, proof_type). PUT is upsert — the unique constraint on the underlying row means repeated calls overwrite the existing config.",
		Tags:          []string{"Attestation Policy"},
		DefaultStatus: http.StatusOK,
	}, a.upsertAttestationPolicyOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-attestation-policies",
		Method:      http.MethodGet,
		Path:        "/attestation-policies",
		Summary:     "List attestation policies for the current tenant",
		Tags:        []string{"Attestation Policy"},
	}, a.listAttestationPoliciesOp)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-attestation-policy",
		Method:        http.MethodDelete,
		Path:          "/attestation-policies/{id}",
		Summary:       "Delete an attestation policy",
		Tags:          []string{"Attestation Policy"},
		DefaultStatus: http.StatusNoContent,
	}, a.deleteAttestationPolicyOp)
}

func (a *API) upsertAttestationPolicyOp(ctx context.Context, input *UpsertAttestationPolicyInput) (*AttestationPolicyOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	pt := domain.ProofType(input.Body.ProofType)
	if !pt.Valid() {
		return nil, huma.Error400BadRequest("invalid proof_type")
	}

	policy, err := a.attestationPolicySvc.UpsertPolicy(ctx, service.UpsertAttestationPolicyRequest{
		AccountID: tenant.AccountID,
		ProjectID: tenant.ProjectID,
		ProofType: pt,
		Config:    input.Body.Config,
		IsActive:  input.Body.IsActive,
	})
	if err != nil {
		// Validation errors (bad config, non-https issuer URL, etc.) are
		// client-fixable — return 400 with the cause so the admin can
		// correct the payload. Everything else is infrastructure.
		if errors.Is(err, service.ErrInvalidAttestationPolicy) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		log.Error().Err(err).Str("proof_type", input.Body.ProofType).Msg("failed to upsert attestation policy")
		return nil, huma.Error500InternalServerError("failed to upsert attestation policy")
	}
	return &AttestationPolicyOutput{Body: policy}, nil
}

func (a *API) listAttestationPoliciesOp(ctx context.Context, _ *struct{}) (*AttestationPolicyListOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	policies, err := a.attestationPolicySvc.ListPolicies(ctx, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		log.Error().Err(err).Msg("failed to list attestation policies")
		return nil, huma.Error500InternalServerError("failed to list attestation policies")
	}
	if policies == nil {
		policies = []*domain.AttestationPolicy{}
	}
	out := &AttestationPolicyListOutput{}
	out.Body.Policies = policies
	return out, nil
}

func (a *API) deleteAttestationPolicyOp(ctx context.Context, input *AttestationPolicyIDInput) (*struct{}, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	if err := a.attestationPolicySvc.DeletePolicy(ctx, input.ID, tenant.AccountID, tenant.ProjectID); err != nil {
		log.Error().Err(err).Str("policy_id", input.ID).Msg("failed to delete attestation policy")
		return nil, huma.Error500InternalServerError("failed to delete attestation policy")
	}
	return nil, nil
}
