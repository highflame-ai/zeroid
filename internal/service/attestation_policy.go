package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// AttestationPolicyService is a thin wrapper around the policy repo. The
// verifier registry holds the concrete verification code; this service
// just manages the per-tenant configuration those verifiers read.
type AttestationPolicyService struct {
	repo *postgres.AttestationPolicyRepository
}

// NewAttestationPolicyService creates a new service.
func NewAttestationPolicyService(repo *postgres.AttestationPolicyRepository) *AttestationPolicyService {
	return &AttestationPolicyService{repo: repo}
}

// UpsertAttestationPolicyRequest captures the payload accepted by the
// admin API. Config is JSONB and its shape depends on ProofType.
type UpsertAttestationPolicyRequest struct {
	AccountID string
	ProjectID string
	ProofType domain.ProofType
	Config    json.RawMessage
	IsActive  *bool
}

// UpsertPolicy creates a policy if none exists for the (tenant, proof_type)
// pair, or updates the existing one in place. The unique index
// uq_attestation_policy_tenant_type guarantees a single row per key, so
// this is the admin API's natural write shape.
func (s *AttestationPolicyService) UpsertPolicy(ctx context.Context, req UpsertAttestationPolicyRequest) (*domain.AttestationPolicy, error) {
	if !req.ProofType.Valid() {
		return nil, fmt.Errorf("invalid proof_type: %s", req.ProofType)
	}
	if len(req.Config) == 0 {
		return nil, fmt.Errorf("config is required")
	}

	existing, err := s.repo.GetByTenantProofType(ctx, req.AccountID, req.ProjectID, req.ProofType)
	switch err {
	case nil:
		existing.Config = req.Config
		if req.IsActive != nil {
			existing.IsActive = *req.IsActive
		}
		if err := s.repo.Update(ctx, existing); err != nil {
			return nil, err
		}
		return existing, nil
	case postgres.ErrAttestationPolicyNotFound:
		active := true
		if req.IsActive != nil {
			active = *req.IsActive
		}
		p := &domain.AttestationPolicy{
			ID:        uuid.New().String(),
			AccountID: req.AccountID,
			ProjectID: req.ProjectID,
			ProofType: req.ProofType,
			Config:    req.Config,
			IsActive:  active,
		}
		if err := s.repo.Create(ctx, p); err != nil {
			return nil, err
		}
		return p, nil
	default:
		return nil, err
	}
}

// GetPolicy returns the policy for the given tenant + proof type, or
// ErrAttestationPolicyNotFound if unset. Used by the verification path.
func (s *AttestationPolicyService) GetPolicy(ctx context.Context, accountID, projectID string, pt domain.ProofType) (*domain.AttestationPolicy, error) {
	return s.repo.GetByTenantProofType(ctx, accountID, projectID, pt)
}

// ListPolicies returns all policies for a tenant.
func (s *AttestationPolicyService) ListPolicies(ctx context.Context, accountID, projectID string) ([]*domain.AttestationPolicy, error) {
	return s.repo.List(ctx, accountID, projectID)
}

// DeletePolicy removes a policy by ID. Policies not belonging to the tenant
// are silently no-op per the repo's idempotent delete semantics.
func (s *AttestationPolicyService) DeletePolicy(ctx context.Context, id, accountID, projectID string) error {
	return s.repo.Delete(ctx, id, accountID, projectID)
}
