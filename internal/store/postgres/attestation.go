package postgres

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// AttestationRepository handles database operations for attestation records.
type AttestationRepository struct {
	db *bun.DB
}

// NewAttestationRepository creates a new AttestationRepository.
func NewAttestationRepository(db *bun.DB) *AttestationRepository {
	return &AttestationRepository{db: db}
}

// Create inserts a new attestation record.
func (r *AttestationRepository) Create(ctx context.Context, record *domain.AttestationRecord) error {
	db := dbOrTx(ctx, r.db)
	_, err := db.NewInsert().Model(record).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create attestation record: %w", err)
	}
	return nil
}

// GetByID retrieves an attestation record by its UUID.
func (r *AttestationRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.AttestationRecord, error) {
	record := &domain.AttestationRecord{}
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(record).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation record: %w", err)
	}
	return record, nil
}

// GetByIDForUpdate retrieves an attestation record by its UUID and acquires
// a row-level write lock (Postgres SELECT ... FOR UPDATE). The lock is held
// until the surrounding transaction commits or rolls back, so this method
// MUST be called inside a transaction (postgres.WithTx).
//
// Outside an explicit transaction Postgres still executes the SELECT
// successfully, but the implicit per-statement transaction commits as
// soon as the statement returns and the lock is released — concurrent
// callers see no useful serialization. We fail fast here rather than
// downgrade silently: misuse should surface as a loud error, not a
// race that only manifests under load.
//
// Use this in flows where the same attestation must serialize against
// concurrent writers — most notably AttestationService.VerifyAttestation,
// where two simultaneous /verify calls on the same record could otherwise
// each pass the IsVerified guard, each issue a credential, and leave the
// DB with two credentials from one proof.
func (r *AttestationRepository) GetByIDForUpdate(ctx context.Context, id, accountID, projectID string) (*domain.AttestationRecord, error) {
	if !hasTx(ctx) {
		return nil, fmt.Errorf("GetByIDForUpdate must be called inside a postgres.WithTx context — the row lock is meaningless without one")
	}
	record := &domain.AttestationRecord{}
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(record).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		For("UPDATE").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation record for update: %w", err)
	}
	return record, nil
}

// GetHighestVerifiedLevel returns the highest verified attestation level for an identity.
// Returns an empty string if no verified attestation exists.
func (r *AttestationRepository) GetHighestVerifiedLevel(ctx context.Context, identityID string) (string, error) {
	var level string
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().
		TableExpr("attestation_records").
		ColumnExpr("level").
		Where("identity_id = ?", identityID).
		Where("is_verified = TRUE").
		Where("is_expired = FALSE").
		OrderExpr(`CASE level
			WHEN 'hardware' THEN 3
			WHEN 'platform' THEN 2
			WHEN 'software' THEN 1
			ELSE 0 END DESC`).
		Limit(1).
		Scan(ctx, &level)
	if err != nil {
		return "", nil // no attestation found is not an error
	}
	return level, nil
}

// Update saves changes to an attestation record (e.g., mark as verified).
// Participates in a caller-provided transaction via postgres.WithTx(ctx, tx);
// falls through to a single auto-commit update otherwise.
func (r *AttestationRepository) Update(ctx context.Context, record *domain.AttestationRecord) error {
	db := dbOrTx(ctx, r.db)
	_, err := db.NewUpdate().Model(record).
		Where("id = ?", record.ID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update attestation record: %w", err)
	}
	return nil
}
