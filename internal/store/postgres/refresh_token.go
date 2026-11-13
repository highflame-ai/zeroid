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
		// The model's columns, not *: a column the model lacks (schema drift)
		// fails the scan, and with it every rotation.
		Returning("?TableColumns").
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

// RestoreClaimed reverses a committed rotation: it deletes the successor row
// (by hash) and returns the claimed row to active. Both conditions are
// guarded so it only ever reverses an UNUSED successor in the same family —
// the successor must still be active, and the claimed row must still be the
// revoked predecessor. Returns false, changing nothing, when the successor is
// gone or no longer active (rotated onward, or its family revoked by reuse
// detection). Must be called with a transaction so the two statements commit
// together.
func (r *RefreshTokenRepository) RestoreClaimed(ctx context.Context, db bun.IDB, claimedID, familyID, successorHash string) (bool, error) {
	res, err := db.NewDelete().
		Model((*domain.RefreshToken)(nil)).
		Where("token_hash = ?", successorHash).
		Where("family_id = ?", familyID).
		Where("state = ?", domain.RefreshTokenStateActive).
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to delete refresh token successor: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read successor delete result: %w", err)
	}
	if n == 0 {
		return false, nil
	}

	res, err = db.NewUpdate().
		Model((*domain.RefreshToken)(nil)).
		Set("state = ?", domain.RefreshTokenStateActive).
		Set("revoked_at = NULL").
		Where("id = ?", claimedID).
		Where("family_id = ?", familyID).
		Where("state = ?", domain.RefreshTokenStateRevoked).
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to reactivate claimed refresh token: %w", err)
	}
	n, err = res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read reactivation result: %w", err)
	}
	if n == 0 {
		// The successor existed but the predecessor is not in the state a
		// rotation leaves it in. Roll the delete back rather than leave the
		// family with no usable token.
		return false, fmt.Errorf("claimed refresh token %s is not a revoked predecessor", claimedID)
	}
	return true, nil
}

// FamilyHasActiveToken reports whether the family has a token in the active
// state. Reuse detection uses it to tell a token that was rotated out (its
// family still has an active successor) from one revoked with its family.
// Expiry is deliberately not checked: an expired successor still marks the
// presented token as rotated out rather than revoked.
func (r *RefreshTokenRepository) FamilyHasActiveToken(ctx context.Context, familyID string) (bool, error) {
	exists, err := r.db.NewSelect().
		Model((*domain.RefreshToken)(nil)).
		Where("family_id = ?", familyID).
		Where("state = ?", domain.RefreshTokenStateActive).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check refresh token family: %w", err)
	}
	return exists, nil
}

// DeleteExpired removes refresh-token rows whose expires_at is strictly before
// the given cutoff. The cutoff MUST be lagged behind now by at least the
// configured reuse grace window (and never less than
// domain.RefreshTokenReuseGraceWindow): reuse detection (see
// service/refresh_token.go) relies on rotated-out rows still existing, both to
// recognise a concurrent retry within the grace window and to revoke the
// family after it. A rotated-out row keeps its original expires_at, so it
// stays consultable for the token's whole lifetime; the lag keeps a row that
// was rotated just before it expired around for the whole grace window, and
// keeps the sweep from racing a lookup at the instant of expiry.
// Deleting strictly by expires_at < (now - lag) keeps every row that reuse
// detection could still consult while still bounding table growth. Returns the number of rows deleted.
func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.NewDelete().
		Model((*domain.RefreshToken)(nil)).
		Where("expires_at < ?", before).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read expired-refresh-token delete result: %w", err)
	}
	return n, nil
}

// RevokeFamily revokes all active tokens in a family (reuse detection response)
// and returns the rows it revoked so the service layer can fan out a
// RevocationNotifier event per revoked token. Refresh tokens are opaque (hashed)
// and carry no JWT id, so the row's UUID (RefreshToken.ID) serves as the stable,
// unique revocation handle.
//
// The UPDATE runs twice, because one pass can race RestoreClaimed. A restore
// deletes the unused successor and reactivates the presented token in one
// transaction. If the first pass takes its snapshot before that transaction
// commits, it sees the presented token as revoked (not a target) and the
// successor as active; it blocks on the successor's row lock, finds the row
// deleted once the restore commits, and revokes nothing — leaving the
// presented token active in a family the caller believes is revoked. Any
// restore that touches this family has either committed by the time the first
// pass returns (the pass waited on its lock) or found the successor revoked
// and changed nothing, so the second pass, with a fresh snapshot, sees every
// row a restore reactivated. TestRefreshTokenRevokeFamilyRacingRestore forces
// that interleaving.
func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) ([]*domain.RefreshToken, error) {
	var revoked []*domain.RefreshToken
	for range 2 {
		var pass []*domain.RefreshToken
		err := r.db.NewUpdate().
			Model(&pass).
			Set("state = ?", domain.RefreshTokenStateRevoked).
			Set("revoked_at = ?", time.Now()).
			Where("family_id = ?", familyID).
			Where("state = ?", domain.RefreshTokenStateActive).
			Returning("?TableColumns"). // model columns only, as in ClaimByTokenHash
			Scan(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to revoke refresh token family: %w", err)
		}
		revoked = append(revoked, pass...)
	}

	return revoked, nil
}
