package postgres

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// SignalRepository handles database operations for CAE signals.
type SignalRepository struct {
	db *bun.DB
}

// NewSignalRepository creates a new SignalRepository.
func NewSignalRepository(db *bun.DB) *SignalRepository {
	return &SignalRepository{db: db}
}

// Create inserts a new CAE signal.
func (r *SignalRepository) Create(ctx context.Context, signal *domain.CAESignal) error {
	_, err := r.db.NewInsert().Model(signal).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create CAE signal: %w", err)
	}
	return nil
}

// List returns signals for a given tenant, optionally filtered.
func (r *SignalRepository) List(ctx context.Context, accountID, projectID string, limit int) ([]*domain.CAESignal, error) {
	var signals []*domain.CAESignal
	q := r.db.NewSelect().Model(&signals).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("created_at DESC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to list CAE signals: %w", err)
	}
	return signals, nil
}

// ListByIdentity returns signals for a specific identity.
func (r *SignalRepository) ListByIdentity(ctx context.Context, identityID, accountID, projectID string) ([]*domain.CAESignal, error) {
	var signals []*domain.CAESignal
	err := r.db.NewSelect().Model(&signals).
		Where("identity_id = ?", identityID).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list signals by identity: %w", err)
	}
	return signals, nil
}
