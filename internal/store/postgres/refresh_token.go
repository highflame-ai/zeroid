package postgres

import (
	"context"
	"database/sql"
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

// Create inserts a new refresh token record. Accepts a bun.IDB so the caller
// can pass either the DB pool (for standalone inserts) or a transaction (when
// the insert must roll back with a related operation, e.g., rotation).
func (r *RefreshTokenRepository) Create(ctx context.Context, db bun.IDB, token *domain.RefreshToken) error {
	_, err := db.NewInsert().Model(token).Exec(ctx)
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

// ClaimByTokenHash atomically revokes and returns an active, non-expired
// refresh token matching the given hash. Postgres row-level locking ensures
// exactly one concurrent caller wins — closing the rotation race that allowed
// two concurrent rotations to both issue successor tokens from a single input
// (RFC 6749 §6).
//
// Accepts a bun.IDB so callers that pair the claim with a successor insert can
// run both inside a single transaction. If the successor insert fails, the
// transaction rollback restores the claimed row to active, avoiding spurious
// reuse detection on a client retry after a transient DB error.
//
// Returns sql.ErrNoRows if no active non-expired token matches. Callers should
// then look up the token including revoked state to distinguish expired/missing
// from replay of an already-revoked token.
func (r *RefreshTokenRepository) ClaimByTokenHash(ctx context.Context, db bun.IDB, tokenHash string) (*domain.RefreshToken, error) {
	token := new(domain.RefreshToken)
	now := time.Now()

	res, err := db.NewUpdate().
		Model(token).
		Set("state = ?", domain.RefreshTokenStateRevoked).
		Set("revoked_at = ?", now).
		Where("token_hash = ?", tokenHash).
		Where("state = ?", domain.RefreshTokenStateActive).
		Where("expires_at > ?", now).
		Returning("*").
		Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to claim refresh token: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to check claim result: %w", err)
	}
	if n == 0 {
		return nil, sql.ErrNoRows
	}

	return token, nil
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

	count, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to check family revocation result: %w", err)
	}

	return count, nil
}
