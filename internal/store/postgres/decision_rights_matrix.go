package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// DRMRepository persists DecisionRightsMatrix rows. The table is
// append-only via DB trigger — there is intentionally no Update or
// Delete method.
type DRMRepository struct {
	db *bun.DB
}

func NewDRMRepository(db *bun.DB) *DRMRepository {
	return &DRMRepository{db: db}
}

func (r *DRMRepository) Create(ctx context.Context, drm *domain.DecisionRightsMatrix) error {
	if _, err := r.db.NewInsert().Model(drm).Exec(ctx); err != nil {
		return fmt.Errorf("failed to create DRM: %w", err)
	}
	return nil
}

// GetActive returns the most-recently-effective DRM whose effective_at is
// in the past and which has not expired. Returns (nil, nil) when the
// tenant has no DRM configured — callers treat this as "no DRM
// enforcement" rather than an error (backward compat).
func (r *DRMRepository) GetActive(ctx context.Context, accountID, projectID string) (*domain.DecisionRightsMatrix, error) {
	drm := &domain.DecisionRightsMatrix{}
	err := r.db.NewSelect().Model(drm).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("effective_at <= NOW()").
		Where("expires_at IS NULL OR expires_at > NOW()").
		OrderExpr("effective_at DESC").
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get active DRM: %w", err)
	}
	return drm, nil
}

func (r *DRMRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.DecisionRightsMatrix, error) {
	drm := &domain.DecisionRightsMatrix{}
	err := r.db.NewSelect().Model(drm).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get DRM: %w", err)
	}
	return drm, nil
}

func (r *DRMRepository) List(ctx context.Context, accountID, projectID string) ([]*domain.DecisionRightsMatrix, error) {
	var rows []*domain.DecisionRightsMatrix
	err := r.db.NewSelect().Model(&rows).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("effective_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list DRMs: %w", err)
	}
	return rows, nil
}
