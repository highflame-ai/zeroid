package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// ProofRepository handles database operations for WIMSE Proof Tokens.
type ProofRepository struct {
	db *bun.DB
}

// NewProofRepository creates a new ProofRepository.
func NewProofRepository(db *bun.DB) *ProofRepository {
	return &ProofRepository{db: db}
}

// Create persists a new proof token record.
func (r *ProofRepository) Create(ctx context.Context, pt *domain.ProofToken) error {
	_, err := r.db.NewInsert().Model(pt).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create proof token: %w", err)
	}
	return nil
}

// MarkUsed sets is_used = TRUE and records used_at for the token with the
// given JTI, returning the number of rows claimed. The conditional UPDATE is
// the single-use enforcement point: 0 rows means another verification already
// claimed the token (or the JTI is unknown), and the caller must treat that
// as a replay. A separate read-then-check is not sufficient — two concurrent
// verifications can both observe is_used = FALSE.
func (r *ProofRepository) MarkUsed(ctx context.Context, jti string) (int64, error) {
	now := time.Now()
	res, err := r.db.NewUpdate().
		TableExpr("proof_tokens").
		Set("is_used = TRUE, used_at = ?", now).
		Where("jti = ?", jti).
		Where("is_used = FALSE").
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to mark proof token as used: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read proof token claim result: %w", err)
	}
	return affected, nil
}

// GetByJTI retrieves a proof token by its JWT ID.
func (r *ProofRepository) GetByJTI(ctx context.Context, jti string) (*domain.ProofToken, error) {
	pt := &domain.ProofToken{}
	err := r.db.NewSelect().Model(pt).
		Where("jti = ?", jti).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get proof token by jti: %w", err)
	}
	return pt, nil
}
