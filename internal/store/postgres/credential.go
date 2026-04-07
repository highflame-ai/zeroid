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

// RevokeAllActiveForIdentity revokes all non-expired, non-revoked credentials for an
// identity and cascades the revocation to every downstream delegated credential in the
// parent_jti chain (RFC 8693 token_exchange descendants), regardless of which identity
// issued those child tokens. Implemented via the revoke_credentials_cascade DB function
// (migration 007) which executes the full subtree update atomically in one statement.
// Returns the total number of credentials revoked (root + descendants).
func (r *CredentialRepository) RevokeAllActiveForIdentity(ctx context.Context, identityID, reason string) (int64, error) {
	now := time.Now()
	var count int64
	if err := r.db.NewRaw(
		"SELECT revoke_credentials_cascade(?, ?, ?)",
		identityID, now, reason,
	).Scan(ctx, &count); err != nil {
		return 0, fmt.Errorf("failed to cascade-revoke credentials for identity %s: %w", identityID, err)
	}
	return count, nil
}

// Revoke marks a credential as revoked and cascades the revocation to every
// downstream delegated credential in the parent_jti chain (RFC 8693 descendants).
// account_id and project_id are enforced on the anchor as tenant-safety guards.
// Implemented via the revoke_credential_cascade DB function (migration 008).
func (r *CredentialRepository) Revoke(ctx context.Context, id, accountID, projectID, reason string) error {
	now := time.Now()
	var count int64
	if err := r.db.NewRaw(
		"SELECT revoke_credential_cascade(?, ?, ?, ?, ?)",
		id, accountID, projectID, now, reason,
	).Scan(ctx, &count); err != nil {
		return fmt.Errorf("failed to cascade-revoke credential %s: %w", id, err)
	}
	return nil
}
