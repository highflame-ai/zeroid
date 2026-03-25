package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// IdentityRepository handles database operations for identities.
type IdentityRepository struct {
	db *bun.DB
}

// NewIdentityRepository creates a new IdentityRepository.
func NewIdentityRepository(db *bun.DB) *IdentityRepository {
	return &IdentityRepository{db: db}
}

// Create inserts a new identity.
func (r *IdentityRepository) Create(ctx context.Context, identity *domain.Identity) error {
	_, err := r.db.NewInsert().Model(identity).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}
	return nil
}

// GetByID retrieves an identity by its UUID, scoped to account + project.
func (r *IdentityRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.Identity, error) {
	identity := &domain.Identity{}
	err := r.db.NewSelect().Model(identity).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}
	return identity, nil
}

// GetByExternalID retrieves an identity by external ID within a tenant.
func (r *IdentityRepository) GetByExternalID(ctx context.Context, externalID, accountID, projectID string) (*domain.Identity, error) {
	identity := &domain.Identity{}
	err := r.db.NewSelect().Model(identity).
		Where("external_id = ?", externalID).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity by external_id: %w", err)
	}
	return identity, nil
}

// GetByWIMSEURI retrieves an identity by its WIMSE URI, scoped to tenant.
func (r *IdentityRepository) GetByWIMSEURI(ctx context.Context, wimseURI, accountID, projectID string) (*domain.Identity, error) {
	identity := &domain.Identity{}
	err := r.db.NewSelect().Model(identity).
		Where("wimse_uri = ?", wimseURI).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity by wimse_uri: %w", err)
	}
	return identity, nil
}

// List returns identities for a tenant, optionally filtered by identity_type(s) and label.
// The label parameter accepts "key:value" format (e.g. "product:guardrails", "team:platform")
// and filters using JSONB containment: labels @> {"key": "value"}.
func (r *IdentityRepository) List(ctx context.Context, accountID, projectID string, identityTypes []string, label string) ([]*domain.Identity, error) {
	var identities []*domain.Identity
	q := r.db.NewSelect().Model(&identities).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("created_at DESC")

	if len(identityTypes) == 1 {
		q = q.Where("identity_type = ?", identityTypes[0])
	} else if len(identityTypes) > 1 {
		q = q.Where("identity_type IN (?)", bun.In(identityTypes))
	}
	if label != "" {
		parts := strings.SplitN(label, ":", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("invalid label format: expected non-empty-key:value, got %q", label)
		}
		labelJSON, _ := json.Marshal(map[string]string{parts[0]: parts[1]})
		q = q.Where("labels @> ?::jsonb", string(labelJSON))
	}

	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to list identities: %w", err)
	}
	return identities, nil
}

// Update saves changes to an existing identity.
func (r *IdentityRepository) Update(ctx context.Context, identity *domain.Identity) error {
	_, err := r.db.NewUpdate().Model(identity).
		Where("id = ? AND account_id = ? AND project_id = ?", identity.ID, identity.AccountID, identity.ProjectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update identity: %w", err)
	}
	return nil
}

// Delete removes an identity.
func (r *IdentityRepository) Delete(ctx context.Context, id, accountID, projectID string) error {
	_, err := r.db.NewDelete().
		TableExpr("identities").
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete identity: %w", err)
	}
	return nil
}
