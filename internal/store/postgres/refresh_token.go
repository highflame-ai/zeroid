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

// DeleteExpired removes refresh-token rows whose expires_at is strictly before
// the given cutoff. The cutoff MUST be lagged behind now by at least
// domain.RefreshTokenReuseGraceWindow: reuse detection (see
// service/refresh_token.go) relies on recently-revoked rows still existing so a
// replay within the grace window is treated as a benign retry rather than a
// family compromise. Deleting strictly by expires_at < (now - graceWindow)
// keeps every row that reuse detection could still consult while still bounding
// table growth under rotation. Returns the number of rows deleted.
func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.NewDelete().
		Model((*domain.RefreshToken)(nil)).
		Where("expires_at < ?", before).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}

	n, _ := res.RowsAffected()

	return n, nil
}

// RevokeFamily revokes all active tokens in a family (reuse detection response)
// and returns the rows it revoked so the service layer can fan out a
// RevocationNotifier event per revoked token. Refresh tokens are opaque (hashed)
// and carry no JWT id, so the row's UUID (RefreshToken.ID) serves as the stable,
// unique revocation handle.
func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) ([]*domain.RefreshToken, error) {
	now := time.Now()

	var revoked []*domain.RefreshToken
	err := r.db.NewUpdate().
		Model(&revoked).
		Set("state = ?", domain.RefreshTokenStateRevoked).
		Set("revoked_at = ?", now).
		Where("family_id = ?", familyID).
		Where("state = ?", domain.RefreshTokenStateActive).
		Returning("*").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke refresh token family: %w", err)
	}

	return revoked, nil
}
