package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// ErrCredentialPolicyNotFound is returned by Delete when no policy matches the
// id within the caller's tenant (including cross-tenant attempts, which are
// indistinguishable from a truly-absent policy by design).
var ErrCredentialPolicyNotFound = errors.New("credential policy not found")

// ErrCredentialPolicyInUse is returned by Delete when one or more service keys
// still reference the policy. The policy is left intact.
var ErrCredentialPolicyInUse = errors.New("credential policy is still referenced by service keys")

// CredentialPolicyRepository handles database operations for credential policies.
//
// Every method participates in a caller-provided transaction via
// postgres.WithTx(ctx, tx), falling back to the pool otherwise (dbOrTx).
// This is load-bearing, not just hygiene: attestation verification calls
// IssueCredential INSIDE its SELECT ... FOR UPDATE transaction, and the
// policy-ceiling resolution there reads (and on first use, creates) the
// tenant's policy through this repo. When these queries grabbed a fresh
// pool connection instead of riding the tx, N concurrent verifies could
// exhaust the pool — waiters held every connection while the lock-holder
// waited for one — deadlocking until the driver's read timeout fired.
type CredentialPolicyRepository struct {
	db *bun.DB
}

// NewCredentialPolicyRepository creates a new CredentialPolicyRepository.
func NewCredentialPolicyRepository(db *bun.DB) *CredentialPolicyRepository {
	return &CredentialPolicyRepository{db: db}
}

// Create inserts a new credential policy.
func (r *CredentialPolicyRepository) Create(ctx context.Context, policy *domain.CredentialPolicy) error {
	_, err := dbOrTx(ctx, r.db).NewInsert().Model(policy).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create credential policy: %w", err)
	}
	return nil
}

// GetByID retrieves a credential policy by ID, scoped to tenant.
func (r *CredentialPolicyRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.CredentialPolicy, error) {
	policy := &domain.CredentialPolicy{}
	err := dbOrTx(ctx, r.db).NewSelect().Model(policy).
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
	err := dbOrTx(ctx, r.db).NewSelect().Model(&policies).
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
	_, err := dbOrTx(ctx, r.db).NewUpdate().Model(policy).
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
	err := dbOrTx(ctx, r.db).NewSelect().Model(policy).
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

// Delete removes a credential policy, scoped to tenant. It refuses to delete a
// policy that is still referenced by any service key (returns
// ErrCredentialPolicyInUse) and reports ErrCredentialPolicyNotFound when no
// policy matches the id within the tenant.
func (r *CredentialPolicyRepository) Delete(ctx context.Context, id, accountID, projectID string) error {
	// Check whether any service key still references this policy. Use the
	// strongly-typed Bun model (domain.APIKey is bun:"table:service_keys",
	// migration 006) rather than a string literal: the original bug was a
	// hardcoded table-name typo, and Model() makes that class of error
	// impossible. credential_policy_id plus the account_id/project_id tenant
	// scope all live on service_keys.
	count, err := dbOrTx(ctx, r.db).NewSelect().
		Model((*domain.APIKey)(nil)).
		Where("credential_policy_id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("failed to check policy references: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("%w: referenced by %d service key(s)", ErrCredentialPolicyInUse, count)
	}

	res, err := dbOrTx(ctx, r.db).NewDelete().
		Model((*domain.CredentialPolicy)(nil)).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete credential policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read delete result: %w", err)
	}
	if n == 0 {
		return ErrCredentialPolicyNotFound
	}
	return nil
}

// ListExpiringSoon returns active credential policies whose expires_at falls
// within now..now+within. Used by GET /expiring-soon.
func (r *CredentialPolicyRepository) ListExpiringSoon(ctx context.Context, accountID, projectID string, now time.Time, within time.Duration) ([]*domain.CredentialPolicy, error) {
	var policies []*domain.CredentialPolicy
	if err := dbOrTx(ctx, r.db).NewSelect().Model(&policies).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("expires_at IS NOT NULL").
		Where("expires_at >= ?", now).
		Where("expires_at <= ?", now.Add(within)).
		Where("is_active = TRUE").
		Order("expires_at ASC").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("list expiring credential policies: %w", err)
	}
	return policies, nil
}
