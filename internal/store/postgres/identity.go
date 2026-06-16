package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/middleware"
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
	db := dbOrTx(ctx, r.db)
	_, err := db.NewInsert().Model(identity).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}
	return nil
}

// GetByID retrieves an identity by its UUID, scoped to account + project.
func (r *IdentityRepository) GetByID(ctx context.Context, id, accountID, projectID string) (*domain.Identity, error) {
	identity := &domain.Identity{}
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(identity).
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}
	return identity, nil
}

// GetByIDs returns identities with the given UUIDs, scoped to a tenant.
// Used for batch node enrichment in graph endpoints (issue #153) so a
// single query loads every identity referenced by a delegation chain
// instead of issuing one GetByID per node.
//
// Returns the rows that matched; missing IDs are silently dropped (the
// caller may filter ids belonging to other tenants, or pass IDs that
// have since been deleted — both are non-errors for graph rendering).
func (r *IdentityRepository) GetByIDs(ctx context.Context, ids []string, accountID, projectID string) ([]*domain.Identity, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var identities []*domain.Identity
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(&identities).
		Where("id IN (?)", bun.List(ids)).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get identities by ids: %w", err)
	}
	return identities, nil
}

// GetByExternalID retrieves an identity by external ID within a tenant.
func (r *IdentityRepository) GetByExternalID(ctx context.Context, externalID, accountID, projectID string) (*domain.Identity, error) {
	identity := &domain.Identity{}
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(identity).
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
	db := dbOrTx(ctx, r.db)
	err := db.NewSelect().Model(identity).
		Where("wimse_uri = ?", wimseURI).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity by wimse_uri: %w", err)
	}
	return identity, nil
}

// List returns identities for a tenant, optionally filtered by identity_type(s),
// label, and metadata.
//
// The label parameter accepts "key:value" format (e.g. "product:guardrails") and
// filters using JSONB containment: labels @> {"key": "value"}.
//
// The metadata parameter accepts either "key" — key presence (jsonb_exists) — or
// "key:value" — containment (metadata @> {"key": "value"}). Key-presence is used
// e.g. to list identities that have a redteam_target object configured, whose
// value is not a scalar and so can't be matched by containment.
func (r *IdentityRepository) List(ctx context.Context, accountID, projectID string, identityTypes []string, label, trustLevel, isActive, search, metadata string, limit, offset int) ([]*domain.Identity, int, error) {
	var identities []*domain.Identity
	db := dbOrTx(ctx, r.db)
	q := db.NewSelect().Model(&identities).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		OrderExpr("created_at DESC")

	if len(identityTypes) == 1 {
		q = q.Where("identity_type = ?", identityTypes[0])
	} else if len(identityTypes) > 1 {
		q = q.Where("identity_type IN (?)", bun.List(identityTypes))
	}
	if label != "" {
		parts := strings.SplitN(label, ":", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, 0, fmt.Errorf("invalid label format: expected non-empty-key:value, got %q", label)
		}
		labelJSON, _ := json.Marshal(map[string]string{parts[0]: parts[1]})
		q = q.Where("labels @> ?::jsonb", string(labelJSON))
	}
	if metadata != "" {
		parts := strings.SplitN(metadata, ":", 2)
		if parts[0] == "" {
			return nil, 0, fmt.Errorf("invalid metadata filter: expected key or key:value, got %q", metadata)
		}
		if len(parts) == 2 {
			metaJSON, _ := json.Marshal(map[string]string{parts[0]: parts[1]})
			q = q.Where("metadata @> ?::jsonb", string(metaJSON))
		} else {
			// key-presence: identities whose metadata has this top-level key.
			q = q.Where("jsonb_exists(metadata, ?)", parts[0])
		}
	}
	if trustLevel != "" {
		q = q.Where("trust_level = ?", trustLevel)
	}
	if isActive != "" {
		if active, err := strconv.ParseBool(isActive); err == nil {
			if active {
				q = q.Where("status = 'active'")
			} else {
				q = q.Where("status != 'active'")
			}
		}
	}
	if search != "" {
		searchPattern := "%" + search + "%"
		q = q.Where("(name ILIKE ? OR external_id ILIKE ?)", searchPattern, searchPattern)
	}

	total, err := q.Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count identities: %w", err)
	}

	if limit > 0 {
		q = q.Limit(limit)
	}
	if offset > 0 {
		q = q.Offset(offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("failed to list identities: %w", err)
	}
	return identities, total, nil
}

// Update saves changes to an existing identity. Participates in a caller-
// provided transaction via postgres.WithTx(ctx, tx); falls through to a
// single auto-commit update otherwise.
func (r *IdentityRepository) Update(ctx context.Context, identity *domain.Identity) error {
	identity.ModifiedBy = middleware.GetCallerName(ctx)
	db := dbOrTx(ctx, r.db)
	_, err := db.NewUpdate().Model(identity).
		Where("id = ? AND account_id = ? AND project_id = ?", identity.ID, identity.AccountID, identity.ProjectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update identity: %w", err)
	}
	return nil
}

// Delete removes an identity.
//
// The pre-DELETE UPDATE stamps modified_by so the AFTER DELETE trigger can
// read the actor from OLD.modified_by. Its error is propagated rather than
// swallowed: in Postgres, a failed statement inside a transaction aborts
// the whole tx, so the subsequent DELETE would fail with a generic
// "current transaction is aborted" message that loses the original cause.
// Outside a tx the same propagation just makes a benign-looking failure
// loud — that's still preferable to silently triggering audit gaps.
func (r *IdentityRepository) Delete(ctx context.Context, id, accountID, projectID string) error {
	db := dbOrTx(ctx, r.db)
	if callerID := middleware.GetCallerName(ctx); callerID != "" {
		if _, err := db.NewUpdate().
			TableExpr("identities").
			Set("modified_by = ?", callerID).
			Where("id = ? AND account_id = ? AND project_id = ?", id, accountID, projectID).
			Exec(ctx); err != nil {
			return fmt.Errorf("failed to stamp modified_by before delete: %w", err)
		}
	}
	_, err := db.NewDelete().
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

// DeactivateIfActive atomically flips status to 'deactivated' iff the row
// is still 'active', returning the post-update identity row and a boolean
// indicating whether this caller won the claim. Used by the cleanup
// worker's expiry sweep so that concurrent replicas don't both run the
// deactivation cascade for the same identity — only the worker whose UPDATE
// matched a still-active row gets back claimed=true and proceeds to fire
// the credential / API-key revocation + lifecycle CAE signal. The signal
// type depends on the caller's reason: the expiry sweep emits
// SignalTypeIdentityExpired; admin-initiated deactivation emits the
// generic SignalTypeRetirement.
//
// Callers that fail the claim (claimed=false) MUST silently skip; the row
// was either already deactivated by another replica or by a parallel admin
// action, and the cascade for that transition has already run (or is
// running) on that other path.
func (r *IdentityRepository) DeactivateIfActive(ctx context.Context, id, accountID, projectID string) (claimed bool, identity *domain.Identity, err error) {
	db := dbOrTx(ctx, r.db)
	identity = &domain.Identity{}
	// modified_by must be set in the UPDATE itself — the audit trigger
	// reads NEW.modified_by, so a caller_name on the context only reaches
	// the audit log when it's written into this row's column.
	q := db.NewUpdate().Model(identity).
		Set("status = ?", string(domain.IdentityStatusDeactivated)).
		Set("updated_at = ?", time.Now())
	if callerID := middleware.GetCallerName(ctx); callerID != "" {
		q = q.Set("modified_by = ?", callerID)
	}
	res, err := q.
		Where("id = ?", id).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("status = ?", string(domain.IdentityStatusActive)).
		Returning("*").
		Exec(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("deactivate-if-active: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, nil, fmt.Errorf("deactivate-if-active rows: %w", err)
	}
	if n == 0 {
		return false, nil, nil
	}
	return true, identity, nil
}

// ListExpiredActive returns identities whose expires_at has passed while
// their status is still 'active'. Used by the cleanup worker's identity
// sweep. The partial index on (expires_at) WHERE status='active' makes
// this scan O(expired-rows), not O(all-identities).
func (r *IdentityRepository) ListExpiredActive(ctx context.Context, now time.Time) ([]*domain.Identity, error) {
	var identities []*domain.Identity
	db := dbOrTx(ctx, r.db)
	if err := db.NewSelect().Model(&identities).
		Where("expires_at IS NOT NULL").
		Where("expires_at < ?", now).
		Where("status = ?", string(domain.IdentityStatusActive)).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("list expired identities: %w", err)
	}
	return identities, nil
}

// ListExpiringSoon returns identities whose expires_at falls within the given
// window (now..now+within). Used by GET /expiring-soon. Excludes already-
// deactivated identities so the result reflects what is *about to* expire,
// not what already has.
func (r *IdentityRepository) ListExpiringSoon(ctx context.Context, accountID, projectID string, now time.Time, within time.Duration) ([]*domain.Identity, error) {
	var identities []*domain.Identity
	db := dbOrTx(ctx, r.db)
	if err := db.NewSelect().Model(&identities).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("expires_at IS NOT NULL").
		Where("expires_at >= ?", now).
		Where("expires_at <= ?", now.Add(within)).
		Where("status = ?", string(domain.IdentityStatusActive)).
		Order("expires_at ASC").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("list expiring identities: %w", err)
	}
	return identities, nil
}
