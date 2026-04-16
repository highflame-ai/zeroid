package postgres

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// AuthCodeRepository handles persistence for consumed authorization codes.
type AuthCodeRepository struct {
	db *bun.DB
}

// NewAuthCodeRepository creates a new AuthCodeRepository.
func NewAuthCodeRepository(db *bun.DB) *AuthCodeRepository {
	return &AuthCodeRepository{db: db}
}

// Consume atomically records an auth code as consumed.
// Returns true if this is the first consumption (INSERT succeeded).
// Returns false if the code was already consumed (conflict on PK).
func (r *AuthCodeRepository) Consume(ctx context.Context, code *domain.AuthCode) (bool, error) {
	res, err := r.db.NewInsert().
		Model(code).
		On("CONFLICT (jti) DO NOTHING").
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to consume auth code: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to check auth code insert result: %w", err)
	}

	return rows > 0, nil
}

// GetByJTI retrieves a consumed auth code record by its JTI.
// Used during replay detection to find the credential and refresh token
// family that need to be revoked.
func (r *AuthCodeRepository) GetByJTI(ctx context.Context, jti string) (*domain.AuthCode, error) {
	code := &domain.AuthCode{}
	err := r.db.NewSelect().Model(code).
		Where("jti = ?", jti).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth code by jti: %w", err)
	}
	return code, nil
}

// UpdateTokenInfo stores the credential JTI and refresh token family ID
// after successful token issuance. These are needed to revoke the tokens
// if a replay is detected later.
func (r *AuthCodeRepository) UpdateTokenInfo(ctx context.Context, jti, credentialJTI, refreshFamilyID string) error {
	q := r.db.NewUpdate().
		Model((*domain.AuthCode)(nil)).
		Set("credential_jti = ?", credentialJTI).
		Where("jti = ?", jti)

	if refreshFamilyID != "" {
		q = q.Set("refresh_family_id = ?::uuid", refreshFamilyID)
	}

	_, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update auth code token info: %w", err)
	}
	return nil
}

