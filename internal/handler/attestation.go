package handler

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
)

// ── Attestation types ────────────────────────────────────────────────────────

type SubmitAttestationInput struct {
	Body struct {
		IdentityID string `json:"identity_id" required:"true" minLength:"1" doc:"UUID of the agent identity"`
		Level      string `json:"level,omitempty" enum:"software,platform,hardware" doc:"Attestation level"`
		ProofType  string `json:"proof_type" required:"true" enum:"image_hash,oidc_token,tpm" doc:"Type of attestation proof"`
		ProofValue string `json:"proof_value" required:"true" minLength:"1" doc:"Attestation proof value"`
	}
}

type AttestationOutput struct {
	Body *domain.AttestationRecord
}

type AttestationIDInput struct {
	ID string `path:"id" doc:"Attestation record UUID"`
}

type VerifyAttestationInput struct {
	Body struct {
		AttestationID string `json:"attestation_id" required:"true" minLength:"1" doc:"UUID of the attestation record to verify"`
	}
}

type VerifyAttestationOutput struct {
	Body struct {
		Record     *domain.AttestationRecord `json:"record"`
		Token      *domain.AccessToken       `json:"token"`
		Credential *domain.IssuedCredential  `json:"credential"`
	}
}

// ── Attestation routes ───────────────────────────────────────────────────────

func (a *API) registerAttestationRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "submit-attestation",
		Method:        http.MethodPost,
		Path:          "/api/v1/attestation/submit",
		Summary:       "Submit an attestation proof for an agent identity",
		Tags:          []string{"Attestation"},
		DefaultStatus: http.StatusCreated,
	}, a.submitAttestationOp)

	huma.Register(api, huma.Operation{
		OperationID: "verify-attestation",
		Method:      http.MethodPost,
		Path:        "/api/v1/attestation/verify",
		Summary:     "Verify an attestation and promote trust level",
		Tags:        []string{"Attestation"},
	}, a.verifyAttestationOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-attestation",
		Method:      http.MethodGet,
		Path:        "/api/v1/attestation/{id}",
		Summary:     "Get an attestation record by ID",
		Tags:        []string{"Attestation"},
	}, a.getAttestationOp)
}

func (a *API) submitAttestationOp(ctx context.Context, input *SubmitAttestationInput) (*AttestationOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	level := domain.AttestationLevel(input.Body.Level)
	if level == "" {
		level = domain.AttestationLevelSoftware
	}

	proofType := domain.ProofType(input.Body.ProofType)

	record, err := a.attestationSvc.SubmitAttestation(
		ctx, input.Body.IdentityID, tenant.AccountID, tenant.ProjectID,
		level, proofType, input.Body.ProofValue,
	)
	if err != nil {
		log.Error().Err(err).Str("identity_id", input.Body.IdentityID).Msg("failed to submit attestation")
		return nil, huma.Error500InternalServerError("failed to submit attestation")
	}

	return &AttestationOutput{Body: record}, nil
}

func (a *API) verifyAttestationOp(ctx context.Context, input *VerifyAttestationInput) (*VerifyAttestationOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	result, err := a.attestationSvc.VerifyAttestation(ctx, input.Body.AttestationID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		log.Error().Err(err).Str("attestation_id", input.Body.AttestationID).Msg("attestation verification failed")
		return nil, huma.Error500InternalServerError("attestation verification failed")
	}

	out := &VerifyAttestationOutput{}
	out.Body.Record = result.Record
	out.Body.Token = result.AccessToken
	out.Body.Credential = result.Credential
	return out, nil
}

func (a *API) getAttestationOp(ctx context.Context, input *AttestationIDInput) (*AttestationOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	record, err := a.attestationSvc.GetAttestation(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("attestation record not found")
	}

	return &AttestationOutput{Body: record}, nil
}
