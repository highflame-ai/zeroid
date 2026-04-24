package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// AttestationPolicyRepository handles CRUD for per-tenant attestation
// verification policies. The lookup path (GetByTenantProofType) is the
// hot one — called on every /attestation/verify — and is the one guarded
// by the uq_attestation_policy_tenant_type unique index.
type AttestationPolicyRepository struct {
	db *bun.DB
}

// NewAttestationPolicyRepository creates a new AttestationPolicyRepository.
func NewAttestationPolicyRepository(db *bun.DB) *AttestationPolicyRepository {
	return &AttestationPolicyRepository{db: db}
}

// ErrAttestationPolicyNotFound is returned by GetByTenantProofType when no
// active policy row exists for the tenant + proof type. Callers at the
// verification hot path use this to fail closed.
var ErrAttestationPolicyNotFound = errors.New("attestation policy not found")

// Create inserts a new policy row.
func (r *AttestationPolicyRepository) Create(ctx context.Context, p *domain.AttestationPolicy) error {
	_, err := r.db.NewInsert().Model(p).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create attestation policy: %w", err)
	}
	return nil
}

// GetByID retrieves a policy by ID, scoped to tenant.
func (r *AttestationPolicyRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.AttestationPolicy, error) {
	p := &domain.AttestationPolicy{}
	err := r.db.NewSelect().Model(p).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAttestationPolicyNotFound
		}
		return nil, fmt.Errorf("failed to get attestation policy: %w", err)
	}
	return p, nil
}

// GetByTenantProofType fetches the active policy for the tenant + proof
// type. This is the verification hot path; absence is a normal condition
// (fail-closed semantics) so we return ErrAttestationPolicyNotFound rather
// than an opaque wrapped error.
func (r *AttestationPolicyRepository) GetByTenantProofType(ctx context.Context, accountID, projectID string, pt domain.ProofType) (*domain.AttestationPolicy, error) {
	p := &domain.AttestationPolicy{}
	err := r.db.NewSelect().Model(p).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("proof_type = ?", string(pt)).
		Where("is_active = TRUE").
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAttestationPolicyNotFound
		}
		return nil, fmt.Errorf("failed to get attestation policy: %w", err)
	}
	return p, nil
}

// Upsert inserts a new policy row or updates the existing row for the
// tenant + proof_type in a single atomic statement. Two concurrent admin
// requests for the same key race only on the DB's row-lock — neither 500s
// with a unique-constraint violation, which the prior read-then-write
// pattern could hit. Last-writer-wins semantics on the config column.
//
// When updateIsActive is true, EXCLUDED.is_active overwrites the stored
// value; when false (caller didn't specify), the existing is_active is
// preserved so a PUT-without-is_active cannot silently re-enable a
// previously disabled policy.
//
// Bun's INSERT ... RETURNING populates p back with the row's authoritative
// state (on conflict, the existing row's id and created_at are kept; only
// the SET columns change).
func (r *AttestationPolicyRepository) Upsert(ctx context.Context, p *domain.AttestationPolicy, updateIsActive bool) error {
	q := r.db.NewInsert().Model(p).
		On("CONFLICT (account_id, project_id, proof_type) DO UPDATE").
		Set("config = EXCLUDED.config").
		Set("updated_at = NOW()")
	if updateIsActive {
		q = q.Set("is_active = EXCLUDED.is_active")
	}
	if _, err := q.Returning("*").Exec(ctx); err != nil {
		return fmt.Errorf("failed to upsert attestation policy: %w", err)
	}
	return nil
}

// List returns all policies for a tenant.
func (r *AttestationPolicyRepository) List(ctx context.Context, accountID, projectID string) ([]*domain.AttestationPolicy, error) {
	var policies []*domain.AttestationPolicy
	err := r.db.NewSelect().Model(&policies).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list attestation policies: %w", err)
	}
	return policies, nil
}

// Update overwrites an existing policy's mutable fields (config, is_active).
func (r *AttestationPolicyRepository) Update(ctx context.Context, p *domain.AttestationPolicy) error {
	_, err := r.db.NewUpdate().Model(p).
		Set("config = ?", p.Config).
		Set("is_active = ?", p.IsActive).
		Set("updated_at = NOW()").
		Where("id = ?", p.ID).
		Where("account_id = ?", p.AccountID).
		Where("project_id = ?", p.ProjectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update attestation policy: %w", err)
	}
	return nil
}

// Delete removes a policy by ID, scoped to tenant. Returns nil even if no
// rows matched (idempotent delete semantics — callers that need strict
// existence checking should GetByID first).
func (r *AttestationPolicyRepository) Delete(ctx context.Context, id, accountID, projectID string) error {
	_, err := r.db.NewDelete().Model((*domain.AttestationPolicy)(nil)).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete attestation policy: %w", err)
	}
	return nil
}
