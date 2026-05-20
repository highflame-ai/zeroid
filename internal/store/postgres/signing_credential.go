package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// SigningCredentialRepository handles persistence for workload-attested
// ephemeral signing keys. Only public key material is stored.
type SigningCredentialRepository struct {
	db *bun.DB
}

// NewSigningCredentialRepository creates a new SigningCredentialRepository.
func NewSigningCredentialRepository(db *bun.DB) *SigningCredentialRepository {
	return &SigningCredentialRepository{db: db}
}

// Create inserts a freshly attested signing credential.
func (r *SigningCredentialRepository) Create(ctx context.Context, c *domain.SigningCredential) error {
	if _, err := r.db.NewInsert().Model(c).Exec(ctx); err != nil {
		return fmt.Errorf("failed to create signing credential: %w", err)
	}

	return nil
}

// GetByKID resolves a credential by kid within a tenant for
// VERIFICATION. It deliberately does NOT filter on not_after — an expired
// (rotated / pod-gone) key must still resolve so historical attestations
// verify within the audit-retention window. Revoked/retention semantics
// are the caller's (domain.SigningCredential.VerifiableNow). Returns
// (nil, nil) when no such kid exists for the tenant.
func (r *SigningCredentialRepository) GetByKID(ctx context.Context, kid, accountID, projectID string) (*domain.SigningCredential, error) {
	c := &domain.SigningCredential{}

	err := r.db.NewSelect().Model(c).
		Where("kid = ?", kid).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get signing credential: %w", err)
	}

	return c, nil
}

// ListVerifiable returns every credential whose public key may currently
// verify an attestation for a purpose: non-revoked AND inside the
// audit-retention window (independent of not_after). This is the JWKS
// source — it intentionally includes operationally-expired keys so
// already-emitted attestations keep verifying after key rotation.
func (r *SigningCredentialRepository) ListVerifiable(ctx context.Context, purpose string, now time.Time) ([]*domain.SigningCredential, error) {
	var creds []*domain.SigningCredential

	err := r.db.NewSelect().Model(&creds).
		Where("purpose = ?", purpose).
		Where("revoked = ?", false).
		Where("audit_retention_until > ?", now).
		Order("kid ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list verifiable signing credentials: %w", err)
	}

	return creds, nil
}

// RevokeWorkload revokes every non-revoked credential for a workload
// within a tenant — the CAE entry point. A revoked key fails
// verification immediately, regardless of its retention window.
func (r *SigningCredentialRepository) RevokeWorkload(ctx context.Context, workload, accountID, projectID, reason string, at time.Time) (int64, error) {
	res, err := r.db.NewUpdate().
		Model((*domain.SigningCredential)(nil)).
		Set("revoked = ?", true).
		Set("revoked_reason = ?", reason).
		Set("revoked_at = ?", at).
		Where("workload = ?", workload).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("revoked = ?", false).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke workload signing credentials: %w", err)
	}

	n, _ := res.RowsAffected()

	return n, nil
}

// RevokeKID revokes a single credential by kid within a tenant, scoped
// to its attesting workload (no cross-tenant or cross-workload
// revocation through this path).
func (r *SigningCredentialRepository) RevokeKID(ctx context.Context, kid, workload, accountID, projectID, reason string, at time.Time) (int64, error) {
	res, err := r.db.NewUpdate().
		Model((*domain.SigningCredential)(nil)).
		Set("revoked = ?", true).
		Set("revoked_reason = ?", reason).
		Set("revoked_at = ?", at).
		Where("kid = ?", kid).
		Where("workload = ?", workload).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("revoked = ?", false).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke signing credential: %w", err)
	}

	n, _ := res.RowsAffected()

	return n, nil
}

// PruneExpiredRetention deletes non-revoked credentials whose
// audit-retention window has fully elapsed (housekeeping). Revoked rows
// are kept as a tamper-evidence trail.
func (r *SigningCredentialRepository) PruneExpiredRetention(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.NewDelete().
		Model((*domain.SigningCredential)(nil)).
		Where("revoked = ?", false).
		Where("audit_retention_until <= ?", now).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to prune expired signing credentials: %w", err)
	}

	n, _ := res.RowsAffected()

	return n, nil
}
