package postgres

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// CredentialPolicyRepository handles database operations for credential policies.
type CredentialPolicyRepository struct {
	db *bun.DB
}

// NewCredentialPolicyRepository creates a new CredentialPolicyRepository.
func NewCredentialPolicyRepository(db *bun.DB) *CredentialPolicyRepository {
	return &CredentialPolicyRepository{db: db}
}

// Create inserts a new credential policy.
func (r *CredentialPolicyRepository) Create(ctx context.Context, policy *domain.CredentialPolicy) error {
	_, err := r.db.NewInsert().Model(policy).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create credential policy: %w", err)
	}
	return nil
}

// GetByID retrieves a credential policy by ID, scoped to tenant.
func (r *CredentialPolicyRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.CredentialPolicy, error) {
	policy := &domain.CredentialPolicy{}
	err := r.db.NewSelect().Model(policy).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential policy: %w", err)
	}
	return policy, nil
}

// List returns all credential policies for a tenant.
func (r *CredentialPolicyRepository) List(ctx context.Context, accountID, projectID string) ([]*domain.CredentialPolicy, error) {
	var policies []*domain.CredentialPolicy
	err := r.db.NewSelect().Model(&policies).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list credential policies: %w", err)
	}
	return policies, nil
}

// Update saves changes to an existing credential policy.
func (r *CredentialPolicyRepository) Update(ctx context.Context, policy *domain.CredentialPolicy) error {
	_, err := r.db.NewUpdate().Model(policy).
		Where("id = ? AND account_id = ? AND project_id = ?", policy.ID, policy.AccountID, policy.ProjectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update credential policy: %w", err)
	}
	return nil
}

// GetDefaultByTenant retrieves the "default" credential policy for a tenant.
// Returns nil, nil if no default policy exists.
func (r *CredentialPolicyRepository) GetDefaultByTenant(ctx context.Context, accountID, projectID string) (*domain.CredentialPolicy, error) {
	policy := &domain.CredentialPolicy{}
	err := r.db.NewSelect().Model(policy).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("name = ?", domain.DefaultPolicyName).
		Where("is_active = TRUE").
		Scan(ctx)
	if err != nil {
		return nil, nil //nolint:nilerr // not-found is expected
	}
	return policy, nil
}

// Delete removes a credential policy. Returns an error if any API keys still reference it.
func (r *CredentialPolicyRepository) Delete(ctx context.Context, id, accountID, projectID string) error {
	// Check if any API keys reference this policy.
	count, err := r.db.NewSelect().
		TableExpr("api_keys").
		Where("credential_policy_id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("failed to check policy references: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("credential policy is still referenced by %d API keys", count)
	}

	_, err = r.db.NewDelete().
		TableExpr("credential_policies").
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete credential policy: %w", err)
	}
	return nil
}
