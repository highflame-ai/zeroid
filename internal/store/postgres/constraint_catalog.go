package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// ConstraintCatalogRepository persists ConstraintCatalogVersion rows.
// Rows are append-only by convention — a new effective version is a
// fresh row, and a 24h liveness re-sign of an unchanged document is also
// a fresh row with the same Hash but a new SignedAt.
type ConstraintCatalogRepository struct {
	db *bun.DB
}

func NewConstraintCatalogRepository(db *bun.DB) *ConstraintCatalogRepository {
	return &ConstraintCatalogRepository{db: db}
}

func (r *ConstraintCatalogRepository) Create(ctx context.Context, v *domain.ConstraintCatalogVersion) error {
	if _, err := r.db.NewInsert().Model(v).Exec(ctx); err != nil {
		return fmt.Errorf("failed to create constraint catalog version: %w", err)
	}
	return nil
}

// GetActive returns the most recently signed catalog row for the tenant.
// Returns (nil, nil) when no catalog is configured.
func (r *ConstraintCatalogRepository) GetActive(ctx context.Context, accountID, projectID string) (*domain.ConstraintCatalogVersion, error) {
	v := &domain.ConstraintCatalogVersion{}
	err := r.db.NewSelect().Model(v).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("signed_at DESC").
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get active catalog: %w", err)
	}
	return v, nil
}

// ListTenants returns each (account_id, project_id) that has at least one
// catalog row. Used by the 24h re-sign worker to enumerate tenants
// without holding a separate index.
func (r *ConstraintCatalogRepository) ListTenants(ctx context.Context) ([]TenantKey, error) {
	var rows []TenantKey
	err := r.db.NewSelect().
		TableExpr("constraint_catalog_versions").
		ColumnExpr("DISTINCT account_id, project_id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("failed to list catalog tenants: %w", err)
	}
	return rows, nil
}

// TenantKey is a minimal (account, project) tuple used by worker
// iterators that don't need a full row.
type TenantKey struct {
	AccountID string `bun:"account_id"`
	ProjectID string `bun:"project_id"`
}
