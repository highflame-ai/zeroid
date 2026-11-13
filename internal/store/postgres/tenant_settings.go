package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// TenantSettingsRepository reads and writes per-tenant settings. Get is on
// the token-issuance hot path (the token profile is read for every token), so
// it is a single primary-key lookup.
type TenantSettingsRepository struct {
	db *bun.DB
}

// NewTenantSettingsRepository creates a new TenantSettingsRepository.
func NewTenantSettingsRepository(db *bun.DB) *TenantSettingsRepository {
	return &TenantSettingsRepository{db: db}
}

// Get returns the tenant's settings row, or (nil, nil) when the tenant has
// none. Absence is the normal case, meaning every setting takes its default,
// so it is not an error.
//
// It reads through dbOrTx, like every repository on the issuance path,
// because IssueCredential runs inside a caller's transaction on some paths
// (attestation verification holds a row lock across issuance). Reading on the
// pool instead takes a second connection while the first is held, and under
// concurrency the pool empties into a deadlock that only a read timeout breaks.
func (r *TenantSettingsRepository) Get(ctx context.Context, accountID, projectID string) (*domain.TenantSettings, error) {
	s := &domain.TenantSettings{}
	err := dbOrTx(ctx, r.db).NewSelect().Model(s).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant settings: %w", err)
	}
	return s, nil
}

// UpsertTokenProfile sets the tenant's token profile in one atomic statement,
// so two concurrent admin writes race only on the row lock and neither fails
// on the primary key. Last writer wins. s is populated with the stored row.
func (r *TenantSettingsRepository) UpsertTokenProfile(ctx context.Context, s *domain.TenantSettings) error {
	_, err := dbOrTx(ctx, r.db).NewInsert().Model(s).
		On("CONFLICT (account_id, project_id) DO UPDATE").
		Set("token_profile = EXCLUDED.token_profile").
		Set("updated_at = NOW()").
		Returning("*").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to upsert tenant settings: %w", err)
	}
	return nil
}
