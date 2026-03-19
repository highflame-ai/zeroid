package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// APIKeyRepository handles database operations for API keys (zid_sk_* keys).
type APIKeyRepository struct {
	db *bun.DB
}

// NewAPIKeyRepository creates a new APIKeyRepository.
func NewAPIKeyRepository(db *bun.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

// GetByKeyHash looks up an active API key by its SHA-256 hash.
// Returns nil if the key is not found, revoked, or expired.
func (r *APIKeyRepository) GetByKeyHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	sk := new(domain.APIKey)
	err := r.db.NewSelect().
		Model(sk).
		Where("key_hash = ?", keyHash).
		Where("state = ?", domain.APIKeyStateActive).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}

	// Check expiry.
	if sk.ExpiresAt != nil && time.Now().After(*sk.ExpiresAt) {
		return nil, fmt.Errorf("API key has expired")
	}

	return sk, nil
}

// UpdateLastUsed records usage metadata for rate limiting and audit.
func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, id, ip string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*domain.APIKey)(nil)).
		Set("last_used_at = ?", now).
		Set("last_used_ip = ?", ip).
		Set("usage_count = usage_count + 1").
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// GetByID retrieves an API key by its UUID.
func (r *APIKeyRepository) GetByID(ctx context.Context, id string) (*domain.APIKey, error) {
	sk := new(domain.APIKey)
	err := r.db.NewSelect().
		Model(sk).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}
	return sk, nil
}

// ListByAccountProject returns paginated API keys for an account/project,
// optionally filtered by application ID.
func (r *APIKeyRepository) ListByAccountProject(ctx context.Context, accountID, projectID, applicationID, product string, limit, offset int) ([]*domain.APIKey, int, error) {
	var keys []*domain.APIKey

	q := r.db.NewSelect().
		Model(&keys).
		Where("account_id = ?", accountID).
		OrderExpr("created_at DESC").
		Limit(limit).
		Offset(offset)

	if projectID != "" {
		q = q.Where("project_id = ?", projectID)
	}
	if applicationID != "" {
		q = q.Where("identity_id = ?", applicationID)
	}
	if product != "" {
		q = q.Where("product = ?", product)
	}

	count, err := q.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list API keys: %w", err)
	}

	return keys, count, nil
}

// Revoke marks an API key as revoked.
func (r *APIKeyRepository) Revoke(ctx context.Context, id, revokedBy, reason string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*domain.APIKey)(nil)).
		Set("state = ?", domain.APIKeyStateRevoked).
		Set("revoked_at = ?", now).
		Set("revoked_by = ?", revokedBy).
		Set("revoke_reason = ?", reason).
		Set("updated_at = ?", now).
		Where("id = ?", id).
		Where("state = ?", domain.APIKeyStateActive).
		Exec(ctx)
	return err
}

// GetActiveByIdentityID retrieves the active API key for an identity.
func (r *APIKeyRepository) GetActiveByIdentityID(ctx context.Context, identityID string) (*domain.APIKey, error) {
	sk := new(domain.APIKey)
	err := r.db.NewSelect().
		Model(sk).
		Where("identity_id = ?", identityID).
		Where("state = ?", domain.APIKeyStateActive).
		OrderExpr("created_at DESC").
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("API key not found for identity: %w", err)
	}
	return sk, nil
}

// RevokeByIdentityID revokes all active API keys for an identity.
func (r *APIKeyRepository) RevokeByIdentityID(ctx context.Context, identityID string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*domain.APIKey)(nil)).
		Set("state = ?", domain.APIKeyStateRevoked).
		Set("revoked_at = ?", now).
		Set("revoked_by = ?", "system:identity_revocation").
		Set("revoke_reason = ?", "identity deactivated or key rotated").
		Set("updated_at = ?", now).
		Where("identity_id = ?", identityID).
		Where("state = ?", domain.APIKeyStateActive).
		Exec(ctx)
	return err
}

// Create inserts a new API key.
func (r *APIKeyRepository) Create(ctx context.Context, sk *domain.APIKey) error {
	_, err := r.db.NewInsert().Model(sk).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create API key: %w", err)
	}
	return nil
}
