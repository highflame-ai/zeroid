package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// ExternalIssuerRepository stores per-account trusted issuers and their
// credential bindings (ADR 0042 D4, D6). The grant paths read it on every
// federated mint, by issuer and by (issuer row, subject key); both are
// indexed lookups.
type ExternalIssuerRepository struct {
	db *bun.DB
}

// NewExternalIssuerRepository creates an ExternalIssuerRepository.
func NewExternalIssuerRepository(db *bun.DB) *ExternalIssuerRepository {
	return &ExternalIssuerRepository{db: db}
}

// DB returns the handle writers open transactions on.
func (r *ExternalIssuerRepository) DB() *bun.DB { return r.db }

// LockIssuer serialises writers for one issuer value until the transaction
// ends. The uniqueness rules span accounts and kinds, which no single unique
// index expresses, so writers check them under this lock.
func (r *ExternalIssuerRepository) LockIssuer(ctx context.Context, issuer string) error {
	if !hasTx(ctx) {
		return errors.New("LockIssuer requires a transaction")
	}
	_, err := dbOrTx(ctx, r.db).ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended(?, 4200056))", issuer)
	if err != nil {
		return fmt.Errorf("failed to lock issuer: %w", err)
	}
	return nil
}

// LockAccount serialises issuer writers for one account until the
// transaction ends, so the per-account cap holds under concurrent creates.
// Take it before LockIssuer.
func (r *ExternalIssuerRepository) LockAccount(ctx context.Context, accountID string) error {
	if !hasTx(ctx) {
		return errors.New("LockAccount requires a transaction")
	}
	_, err := dbOrTx(ctx, r.db).ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended(?, 4200057))", accountID)
	if err != nil {
		return fmt.Errorf("failed to lock account issuers: %w", err)
	}
	return nil
}

// SetAuditActor names who makes this transaction's writes, for the audit
// trigger (the only way a DELETE can record it).
func (r *ExternalIssuerRepository) SetAuditActor(ctx context.Context, actor string) error {
	if !hasTx(ctx) {
		return errors.New("SetAuditActor requires a transaction")
	}
	_, err := dbOrTx(ctx, r.db).ExecContext(ctx, "SELECT set_config('zeroid.audit_actor', ?, true)", actor)
	return err
}

// ListByIssuer returns every row for an issuer value, in any account.
func (r *ExternalIssuerRepository) ListByIssuer(ctx context.Context, issuer string) ([]*domain.ExternalIssuer, error) {
	var rows []*domain.ExternalIssuer
	err := dbOrTx(ctx, r.db).NewSelect().Model(&rows).
		Where("issuer = ?", issuer).
		Where("deleted_at IS NULL").
		OrderExpr("created_at, id").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list issuer rows: %w", err)
	}
	return rows, nil
}

// ListByCanonicalIssuer returns every row whose issuer is canon up to
// trailing slashes, in any account: the set uniqueness is decided over.
func (r *ExternalIssuerRepository) ListByCanonicalIssuer(ctx context.Context, canon string) ([]*domain.ExternalIssuer, error) {
	var rows []*domain.ExternalIssuer
	err := dbOrTx(ctx, r.db).NewSelect().Model(&rows).
		Where("rtrim(issuer, '/') = ?", canon).
		Where("deleted_at IS NULL").
		OrderExpr("created_at, id").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list issuer rows: %w", err)
	}
	return rows, nil
}

// CountByAccount returns how many rows an account has.
func (r *ExternalIssuerRepository) CountByAccount(ctx context.Context, accountID string) (int, error) {
	n, err := dbOrTx(ctx, r.db).NewSelect().Model((*domain.ExternalIssuer)(nil)).
		Where("account_id = ?", accountID).
		Where("deleted_at IS NULL").
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count issuers: %w", err)
	}
	return n, nil
}

// Insert writes a new row.
func (r *ExternalIssuerRepository) Insert(ctx context.Context, row *domain.ExternalIssuer) error {
	if _, err := dbOrTx(ctx, r.db).NewInsert().Model(row).Returning("*").Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert issuer: %w", err)
	}
	return nil
}

// Get returns one row of an account. sql.ErrNoRows (wrapped) when the row is
// absent or belongs to another account.
func (r *ExternalIssuerRepository) Get(ctx context.Context, id, accountID string) (*domain.ExternalIssuer, error) {
	row := &domain.ExternalIssuer{}
	err := dbOrTx(ctx, r.db).NewSelect().Model(row).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer: %w", err)
	}
	return row, nil
}

// GetForShare is Get holding a share lock until the transaction ends, so a
// concurrent delete waits for it (or it sees the delete).
func (r *ExternalIssuerRepository) GetForShare(ctx context.Context, id, accountID string) (*domain.ExternalIssuer, error) {
	if !hasTx(ctx) {
		return nil, errors.New("GetForShare requires a transaction")
	}
	row := &domain.ExternalIssuer{}
	err := dbOrTx(ctx, r.db).NewSelect().Model(row).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("deleted_at IS NULL").
		For("SHARE").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer: %w", err)
	}
	return row, nil
}

// List returns an account's rows.
func (r *ExternalIssuerRepository) List(ctx context.Context, accountID string) ([]*domain.ExternalIssuer, error) {
	var rows []*domain.ExternalIssuer
	err := dbOrTx(ctx, r.db).NewSelect().Model(&rows).
		Where("account_id = ?", accountID).
		Where("deleted_at IS NULL").
		OrderExpr("created_at, id").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list issuers: %w", err)
	}
	return rows, nil
}

// Update rewrites a row's mutable columns and bumps updated_at. Cached JWKS
// clients are keyed by (jwks_uri, refresh interval), not by row version.
func (r *ExternalIssuerRepository) Update(ctx context.Context, row *domain.ExternalIssuer) error {
	res, err := dbOrTx(ctx, r.db).NewUpdate().Model(row).
		Column("display_name", "audiences", "algorithms", "claim_mapping", "propagate_claims",
			"claim_constraints", "constraints_key", "max_token_age_seconds", "jwks_cache_ttl_seconds",
			"trust_email", "enabled", "updated_by").
		Set("updated_at = clock_timestamp()").
		Where("id = ?", row.ID).
		Where("account_id = ?", row.AccountID).
		Where("deleted_at IS NULL").
		Returning("*").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update issuer: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("failed to update issuer: %w", sql.ErrNoRows)
	}
	return nil
}

// SetJWKSURI moves a row to a re-discovered key set.
func (r *ExternalIssuerRepository) SetJWKSURI(ctx context.Context, row *domain.ExternalIssuer) error {
	res, err := dbOrTx(ctx, r.db).NewUpdate().Model(row).
		Column("jwks_uri", "updated_by").
		Set("updated_at = clock_timestamp()").
		Where("id = ?", row.ID).
		Where("account_id = ?", row.AccountID).
		Where("deleted_at IS NULL").
		Returning("*").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update issuer keys: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("failed to update issuer keys: %w", sql.ErrNoRows)
	}
	return nil
}

// Delete soft-deletes a row and its live bindings. Requires a transaction.
func (r *ExternalIssuerRepository) Delete(ctx context.Context, id, accountID string) error {
	if !hasTx(ctx) {
		return errors.New("Delete requires a transaction")
	}
	db := dbOrTx(ctx, r.db)
	res, err := db.NewUpdate().Model((*domain.ExternalIssuer)(nil)).
		Set("deleted_at = clock_timestamp()").
		Set("enabled = false").
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete issuer: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("failed to delete issuer: %w", sql.ErrNoRows)
	}
	if _, err := db.NewUpdate().Model((*domain.IssuerBinding)(nil)).
		Set("deleted_at = clock_timestamp()").
		Set("enabled = false").
		Where("issuer_id = ?", id).
		Where("deleted_at IS NULL").
		Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete the issuer's bindings: %w", err)
	}
	return nil
}

// ── Bindings ─────────────────────────────────────────────────────────────────

// InsertBinding writes a new binding.
func (r *ExternalIssuerRepository) InsertBinding(ctx context.Context, b *domain.IssuerBinding) error {
	if _, err := dbOrTx(ctx, r.db).NewInsert().Model(b).Returning("*").Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert binding: %w", err)
	}
	return nil
}

// GetBinding returns one binding of an issuer row in an account.
func (r *ExternalIssuerRepository) GetBinding(ctx context.Context, id, issuerID, accountID string) (*domain.IssuerBinding, error) {
	b := &domain.IssuerBinding{}
	err := dbOrTx(ctx, r.db).NewSelect().Model(b).
		Where("id = ?", id).
		Where("issuer_id = ?", issuerID).
		Where("account_id = ?", accountID).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get binding: %w", err)
	}
	return b, nil
}

// ListBindings returns an account's bindings, narrowed to one issuer row
// and/or one identity when those are non-empty.
func (r *ExternalIssuerRepository) ListBindings(ctx context.Context, accountID, issuerID, identityID string) ([]*domain.IssuerBinding, error) {
	var out []*domain.IssuerBinding
	q := dbOrTx(ctx, r.db).NewSelect().Model(&out).Where("account_id = ?", accountID).Where("deleted_at IS NULL")
	if issuerID != "" {
		q = q.Where("issuer_id = ?", issuerID)
	}
	if identityID != "" {
		q = q.Where("identity_id = ?", identityID)
	}
	err := q.OrderExpr("created_at, id").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list bindings: %w", err)
	}
	return out, nil
}

// ErrBindingExplicitlyDisabled is UpdateBinding's answer to a conditional
// enable of a binding an admin disabled.
var ErrBindingExplicitlyDisabled = errors.New("binding was explicitly disabled")

// UpdateBinding rewrites a binding's enabled flag. With unlessExplicitlyDisabled
// the write happens only if the stored row is not explicitly disabled, in the
// same statement, so it cannot race an admin's disable.
func (r *ExternalIssuerRepository) UpdateBinding(ctx context.Context, b *domain.IssuerBinding, unlessExplicitlyDisabled bool) error {
	q := dbOrTx(ctx, r.db).NewUpdate().Model(b).
		Column("enabled", "explicitly_disabled", "updated_by").
		Set("updated_at = clock_timestamp()").
		Where("id = ?", b.ID).
		Where("account_id = ?", b.AccountID).
		Where("deleted_at IS NULL")
	if unlessExplicitlyDisabled {
		q = q.Where("NOT explicitly_disabled")
	}
	res, err := q.Returning("*").Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update binding: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if unlessExplicitlyDisabled {
			return ErrBindingExplicitlyDisabled
		}
		return fmt.Errorf("failed to update binding: %w", sql.ErrNoRows)
	}
	return nil
}

// DeleteBinding soft-deletes a binding.
func (r *ExternalIssuerRepository) DeleteBinding(ctx context.Context, id, issuerID, accountID string) error {
	res, err := dbOrTx(ctx, r.db).NewUpdate().Model((*domain.IssuerBinding)(nil)).
		Set("deleted_at = clock_timestamp()").
		Set("enabled = false").
		Where("id = ?", id).
		Where("issuer_id = ?", issuerID).
		Where("account_id = ?", accountID).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete binding: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("failed to delete binding: %w", sql.ErrNoRows)
	}
	return nil
}

// BindingsFor returns every binding for (issuer row, subject key), the
// enabled one first. The per-grant lookup: the disabled ones say why a
// credential maps to no usable agent.
func (r *ExternalIssuerRepository) BindingsFor(ctx context.Context, issuerID, subjectKey string) ([]*domain.IssuerBinding, error) {
	var out []*domain.IssuerBinding
	err := dbOrTx(ctx, r.db).NewSelect().Model(&out).
		Where("issuer_id = ?", issuerID).
		Where("subject_key = ?", subjectKey).
		Where("deleted_at IS NULL").
		OrderExpr("enabled DESC, created_at DESC").
		Limit(10).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read bindings: %w", err)
	}
	return out, nil
}
