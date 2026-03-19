package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// CredentialRepository handles database operations for issued credentials.
type CredentialRepository struct {
	db *bun.DB
}

// NewCredentialRepository creates a new CredentialRepository.
func NewCredentialRepository(db *bun.DB) *CredentialRepository {
	return &CredentialRepository{db: db}
}

// Create inserts a new issued credential.
func (r *CredentialRepository) Create(ctx context.Context, cred *domain.IssuedCredential) error {
	_, err := r.db.NewInsert().Model(cred).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}
	return nil
}

// GetByID retrieves a credential by its UUID.
func (r *CredentialRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.IssuedCredential, error) {
	cred := &domain.IssuedCredential{}
	err := r.db.NewSelect().Model(cred).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	return cred, nil
}

// GetByJTI retrieves a credential by its JWT ID (jti claim).
func (r *CredentialRepository) GetByJTI(ctx context.Context, jti string) (*domain.IssuedCredential, error) {
	cred := &domain.IssuedCredential{}
	err := r.db.NewSelect().Model(cred).
		Where("jti = ?", jti).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential by jti: %w", err)
	}
	return cred, nil
}

// ListByIdentity returns all credentials for a given identity.
func (r *CredentialRepository) ListByIdentity(ctx context.Context, identityID, accountID, projectID string) ([]*domain.IssuedCredential, error) {
	var creds []*domain.IssuedCredential
	err := r.db.NewSelect().Model(&creds).
		Where("identity_id = ?", identityID).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("issued_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}
	return creds, nil
}

// RevokeAllActiveForIdentity revokes all non-expired, non-revoked credentials for an identity.
// Returns the number of credentials revoked.
func (r *CredentialRepository) RevokeAllActiveForIdentity(ctx context.Context, identityID, reason string) (int64, error) {
	now := time.Now()
	res, err := r.db.NewUpdate().
		TableExpr("issued_credentials").
		Set("is_revoked = TRUE, revoked_at = ?, revoke_reason = ?", now, reason).
		Where("identity_id = ?", identityID).
		Where("is_revoked = FALSE").
		Where("expires_at > ?", now).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke all credentials for identity: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Revoke marks a credential as revoked.
func (r *CredentialRepository) Revoke(ctx context.Context, id, accountID, projectID, reason string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		TableExpr("issued_credentials").
		Set("is_revoked = TRUE, revoked_at = ?, revoke_reason = ?", now, reason).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to revoke credential: %w", err)
	}
	return nil
}
