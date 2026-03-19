package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// RefreshTokenRepository handles refresh token persistence.
type RefreshTokenRepository struct {
	db *bun.DB
}

// NewRefreshTokenRepository creates a new refresh token repository.
func NewRefreshTokenRepository(db *bun.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

// Create inserts a new refresh token record.
func (r *RefreshTokenRepository) Create(ctx context.Context, token *domain.RefreshToken) error {
	_, err := r.db.NewInsert().Model(token).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}

	return nil
}

// GetByTokenHash retrieves an active, non-expired refresh token by its SHA256 hash.
func (r *RefreshTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	token := new(domain.RefreshToken)

	err := r.db.NewSelect().
		Model(token).
		Where("token_hash = ?", tokenHash).
		Where("state = ?", domain.RefreshTokenStateActive).
		Where("expires_at > ?", time.Now()).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	return token, nil
}

// GetByTokenHashIncludingRevoked retrieves a refresh token by hash regardless of state.
// Used for reuse detection — a revoked token being presented means the family is compromised.
func (r *RefreshTokenRepository) GetByTokenHashIncludingRevoked(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	token := new(domain.RefreshToken)

	err := r.db.NewSelect().
		Model(token).
		Where("token_hash = ?", tokenHash).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	return token, nil
}

// RevokeByID marks a single refresh token as revoked.
func (r *RefreshTokenRepository) RevokeByID(ctx context.Context, id string) error {
	now := time.Now()

	_, err := r.db.NewUpdate().
		Model((*domain.RefreshToken)(nil)).
		Set("state = ?", domain.RefreshTokenStateRevoked).
		Set("revoked_at = ?", now).
		Where("id = ?", id).
		Where("state = ?", domain.RefreshTokenStateActive).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

// RevokeFamily revokes all active tokens in a family (reuse detection response).
func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) (int64, error) {
	now := time.Now()

	res, err := r.db.NewUpdate().
		Model((*domain.RefreshToken)(nil)).
		Set("state = ?", domain.RefreshTokenStateRevoked).
		Set("revoked_at = ?", now).
		Where("family_id = ?", familyID).
		Where("state = ?", domain.RefreshTokenStateActive).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke refresh token family: %w", err)
	}

	count, _ := res.RowsAffected()

	return count, nil
}
