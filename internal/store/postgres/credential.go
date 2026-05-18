package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// CredentialRepository handles database operations for issued credentials.
type CredentialRepository struct {
	db *bun.DB
}

// NewCredentialRepository creates a new CredentialRepository.
func NewCredentialRepository(db *bun.DB) *CredentialRepository {
	return &CredentialRepository{db: db}
}

// Create inserts a new issued credential. Participates in a caller-provided
// transaction via postgres.WithTx(ctx, tx); falls through to a single
// auto-commit insert otherwise.
func (r *CredentialRepository) Create(ctx context.Context, cred *domain.IssuedCredential) error {
	db := dbOrTx(ctx, r.db)
	_, err := db.NewInsert().Model(cred).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}
	return nil
}

// GetByID retrieves a credential by its UUID.
func (r *CredentialRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.IssuedCredential, error) {
	cred := &domain.IssuedCredential{}
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(cred).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	return cred, nil
}

// GetByJTI retrieves a credential by its JWT ID (jti claim).
func (r *CredentialRepository) GetByJTI(ctx context.Context, jti string) (*domain.IssuedCredential, error) {
	cred := &domain.IssuedCredential{}
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(cred).
		Where("jti = ?", jti).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential by jti: %w", err)
	}
	return cred, nil
}

// ListByIdentity returns all credentials for a given identity.
func (r *CredentialRepository) ListByIdentity(ctx context.Context, identityID, accountID, projectID string) ([]*domain.IssuedCredential, error) {
	var creds []*domain.IssuedCredential
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(&creds).
		Where("identity_id = ?", identityID).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("issued_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}
	return creds, nil
}

// ListByMissionID returns every credential in the delegation tree for the
// given mission_id, ordered root → leaves (delegation_depth ASC, then
// issued_at ASC for ties at the same depth). Issue #81. The partial
// index added in migration 017 makes this an indexed equality lookup.
func (r *CredentialRepository) ListByMissionID(ctx context.Context, missionID, accountID, projectID string) ([]*domain.IssuedCredential, error) {
	var creds []*domain.IssuedCredential
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(&creds).
		Where("mission_id = ?", missionID).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("delegation_depth ASC, issued_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials by mission: %w", err)
	}
	return creds, nil
}

// RevokeAllActiveForIdentity revokes all non-expired, non-revoked credentials for an
// identity and cascades the revocation to every downstream delegated credential in the
// parent_jti chain (RFC 8693 token_exchange descendants), regardless of which identity
// issued those child tokens. Implemented via the revoke_credentials_cascade DB function
// (migration 007) which executes the full subtree update atomically in one statement.
// Returns the total number of credentials revoked (root + descendants).
func (r *CredentialRepository) RevokeAllActiveForIdentity(ctx context.Context, identityID, reason string) (int64, error) {
	now := time.Now()
	var count int64
	db := dbOrTx(ctx, r.db)
	if err := db.NewRaw(
		"SELECT revoke_credentials_cascade(?, ?, ?)",
		identityID, now, reason,
	).Scan(ctx, &count); err != nil {
		return 0, fmt.Errorf("failed to cascade-revoke credentials for identity %s: %w", identityID, err)
	}
	return count, nil
}

// Revoke marks a credential as revoked and cascades the revocation to every
// downstream delegated credential in the parent_jti chain (RFC 8693 descendants).
// account_id and project_id are enforced on the anchor as tenant-safety guards.
// Implemented via the revoke_credential_cascade DB function (migration 008).
func (r *CredentialRepository) Revoke(ctx context.Context, id, accountID, projectID, reason string) error {
	now := time.Now()
	var count int64
	db := dbOrTx(ctx, r.db)
	if err := db.NewRaw(
		"SELECT revoke_credential_cascade(?, ?, ?, ?, ?)",
		id, accountID, projectID, now, reason,
	).Scan(ctx, &count); err != nil {
		return fmt.Errorf("failed to cascade-revoke credential %s: %w", id, err)
	}
	return nil
}

// ListIdentitiesByGovernanceHash returns the distinct identity_ids of
// non-revoked, non-expired credentials whose governance hash column
// (drm_hash or constraint_catalog_hash, selected by `kind`) matches
// `hash`. Used by policy_drift signal fan-out (issue #59).
func (r *CredentialRepository) ListIdentitiesByGovernanceHash(ctx context.Context, accountID, projectID, kind, hash string) ([]string, error) {
	var column string
	switch kind {
	case "drm":
		column = "drm_hash"
	case "constraint_catalog":
		column = "constraint_catalog_hash"
	default:
		return nil, fmt.Errorf("unknown governance hash kind: %s", kind)
	}
	var ids []string
	err := r.db.NewSelect().
		TableExpr("issued_credentials").
		ColumnExpr("DISTINCT identity_id").
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("is_revoked = FALSE").
		Where("expires_at > NOW()").
		Where("identity_id IS NOT NULL").
		Where("? = ?", bun.Ident(column), hash).
		Scan(ctx, &ids)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate identities by %s: %w", column, err)
	}
	return ids, nil
}
