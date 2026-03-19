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
	_, err := r.db.NewInsert().Model(record).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create attestation record: %w", err)
	}
	return nil
}

// GetByID retrieves an attestation record by its UUID.
func (r *AttestationRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.AttestationRecord, error) {
	record := &domain.AttestationRecord{}
	err := r.db.NewSelect().Model(record).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation record: %w", err)
	}
	return record, nil
}

// GetHighestVerifiedLevel returns the highest verified attestation level for an identity.
// Returns an empty string if no verified attestation exists.
func (r *AttestationRepository) GetHighestVerifiedLevel(ctx context.Context, identityID string) (string, error) {
	var level string
	err := r.db.NewSelect().
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
func (r *AttestationRepository) Update(ctx context.Context, record *domain.AttestationRecord) error {
	_, err := r.db.NewUpdate().Model(record).
		Where("id = ?", record.ID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update attestation record: %w", err)
	}
	return nil
}
