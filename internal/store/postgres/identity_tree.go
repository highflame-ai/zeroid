package postgres

// Store support for the registration tree (docs/identity-tree.md): inserting
// a child under a locked, active ancestor chain, reading an identity's
// ancestors, status writes that cannot overwrite a concurrent status change,
// and the set-based deactivation walk with its cascade_pending mark.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/middleware"
)

// MaxTreeDepth is the deepest an identity may sit in a registration tree:
// the most ancestors any identity can have. Configured depth limits may not
// exceed it, and an ancestor walk that has not reached a root within it fails
// closed (a cycle or a corrupt chain, which the write path cannot create).
const MaxTreeDepth = 64

// ErrParentNotActive is returned by CreateUnderParent when, at insert time,
// the parent or an identity above it is not an active, unexpired identity in
// the child's account and project.
var ErrParentNotActive = errors.New("parent identity, or an identity above it, is not active in this account and project")

// ErrTreeTooDeep is returned by CreateUnderParent when the child would sit
// deeper than the configured depth limit.
var ErrTreeTooDeep = errors.New("the registration tree would be deeper than allowed")

// ErrTooManyChildren is returned by CreateUnderParent when the parent already
// has the configured number of children that are not deactivated.
var ErrTooManyChildren = errors.New("the parent identity has as many children as allowed")

// ErrAncestorNotActive is returned by Update with RequireActiveAncestors when
// an identity above the one being written is not active and unexpired.
var ErrAncestorNotActive = errors.New("an identity above this one in the registration tree is not active")

// ErrIdentityChanged is returned by Update when the row's status is no longer
// the one the caller read: a concurrent write (a deactivation cascade, for
// one) changed it first, and this write would have overwritten it.
var ErrIdentityChanged = errors.New("the identity's status changed while this write was in progress")

// TreeLimits bounds a registration tree at insert time. Zero fields are not
// limits; the service layer fills its defaults.
type TreeLimits struct {
	// MaxDepth is the most ancestors an identity may have.
	MaxDepth int
	// MaxChildren is the most children, not deactivated, one identity may have.
	MaxChildren int
}

// Ancestor is one identity above another in a registration tree, as
// AncestorChain returns it.
type Ancestor struct {
	ID               string                `bun:"id"`
	ParentIdentityID sql.NullString        `bun:"parent_identity_id"`
	Status           domain.IdentityStatus `bun:"status"`
	ExpiresAt        *time.Time            `bun:"expires_at"`
	TrustLevel       domain.TrustLevel     `bun:"trust_level"`
	Depth            int                   `bun:"depth"`
}

// Usable reports whether the ancestor is active and unexpired at now.
func (a Ancestor) Usable(now time.Time) bool {
	return a.Status == domain.IdentityStatusActive && (a.ExpiresAt == nil || now.Before(*a.ExpiresAt))
}

// ErrBrokenAncestorChain is returned by AncestorChain when the chain does not
// end at an identity with no parent within MaxTreeDepth, or names an identity
// outside the tenant. Callers fail closed on it.
var ErrBrokenAncestorChain = errors.New("the registration tree above this identity is broken")

// ancestorChainSQL walks up from one identity by primary key, one row per
// level, inside one account and project, and stops at MaxTreeDepth levels.
const ancestorChainSQL = `
WITH RECURSIVE up AS (
	SELECT i.id, i.parent_identity_id, i.status, i.expires_at, i.trust_level, 1 AS depth
	FROM identities i
	WHERE i.id = ? AND i.account_id = ? AND i.project_id = ?
	UNION ALL
	SELECT i.id, i.parent_identity_id, i.status, i.expires_at, i.trust_level, up.depth + 1
	FROM identities i
	JOIN up ON i.id = up.parent_identity_id
	WHERE i.account_id = ? AND i.project_id = ? AND up.depth < ?
)
SELECT id, parent_identity_id, status, expires_at, trust_level, depth FROM up ORDER BY depth`

// AncestorChain returns the identity fromID and every identity above it, the
// identity itself first and the root last, within one account and project:
// one statement of at most MaxTreeDepth primary-key lookups. A chain that
// does not end at an identity with no parent (a missing or cross-tenant
// ancestor, or one deeper than MaxTreeDepth) is ErrBrokenAncestorChain;
// sql.ErrNoRows means fromID itself is not in the tenant.
func (r *IdentityRepository) AncestorChain(ctx context.Context, fromID, accountID, projectID string) ([]Ancestor, error) {
	return ancestorChain(ctx, dbOrTx(ctx, r.db), fromID, accountID, projectID)
}

func ancestorChain(ctx context.Context, db bun.IDB, fromID, accountID, projectID string) ([]Ancestor, error) {
	var chain []Ancestor
	if err := db.NewRaw(ancestorChainSQL,
		fromID, accountID, projectID, accountID, projectID, MaxTreeDepth).Scan(ctx, &chain); err != nil {
		return nil, fmt.Errorf("read the registration tree above %s: %w", fromID, err)
	}
	if len(chain) == 0 {
		return nil, sql.ErrNoRows
	}
	if last := chain[len(chain)-1]; last.ParentIdentityID.Valid {
		return nil, fmt.Errorf("%w: %s has a parent that is missing, in another tenant, or more than %d levels up",
			ErrBrokenAncestorChain, last.ID, MaxTreeDepth)
	}
	return chain, nil
}

// MaxLineageDepth is how many credentials CredentialLineage follows up a
// delegation chain. It must equal the depth bound of the cascade revocation
// walks (`chain.depth < 50` in the latest migration that defines each
// revoke_*_cascade / revoke_credentials_by_owner function), so a credential
// is issued only where revoking its root reaches it.
// TestMaxLineageDepthMatchesCascadeMigrations (the migration files) and
// TestCascadeFunctionsWalkToMaxLineageDepth (a migrated database) fail when
// they differ. A
// chain longer than that is ErrLineageTooLong, and callers fail closed on it.
const MaxLineageDepth = 50

// ErrLineageTooLong is returned by CredentialLineage when a delegation chain
// is longer than MaxLineageDepth credentials.
var ErrLineageTooLong = fmt.Errorf("the delegation chain above this credential is longer than %d credentials", MaxLineageDepth)

// ErrBrokenLineage is returned by CredentialLineage when a delegation chain
// loops.
var ErrBrokenLineage = errors.New("the delegation chain above this credential loops")

// LineageIdentity is an identity that a credential, or one of the credentials
// it was delegated from, was issued to, in that credential's own tenant.
type LineageIdentity struct {
	IdentityID string `bun:"identity_id"`
	AccountID  string `bun:"account_id"`
	ProjectID  string `bun:"project_id"`
	Depth      int    `bun:"depth"`
	IsCycle    bool   `bun:"is_cycle"`
}

// credentialLineageSQL follows parent_jti up from one credential, one row per
// credential, and stops one level past MaxLineageDepth so a longer chain can
// be told apart from one that ends there.
const credentialLineageSQL = `
WITH RECURSIVE lineage(jti, parent_jti, identity_id, account_id, project_id, depth) AS (
	SELECT jti, parent_jti, identity_id, account_id, project_id, 1
	FROM issued_credentials
	WHERE jti = ?
	UNION ALL
	SELECT ic.jti, ic.parent_jti, ic.identity_id, ic.account_id, ic.project_id, lineage.depth + 1
	FROM issued_credentials ic
	JOIN lineage ON ic.jti = lineage.parent_jti
	WHERE lineage.depth <= ?
) CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
SELECT COALESCE(identity_id::text, '') AS identity_id, account_id, project_id, depth, is_cycle FROM lineage`

// CredentialLineage returns the identities that the credential jti and every
// credential it was delegated from (parent_jti, up to the root) were issued
// to, each once, in their own tenant. Credentials issued to no identity (a
// person's session) contribute nothing. A parent row that no longer exists
// ends the chain. A chain longer than MaxLineageDepth is ErrLineageTooLong,
// and one that loops is ErrBrokenLineage. An unknown jti returns nothing.
func (r *IdentityRepository) CredentialLineage(ctx context.Context, jti string) ([]LineageIdentity, error) {
	var rows []LineageIdentity
	if err := dbOrTx(ctx, r.db).NewRaw(credentialLineageSQL, jti, MaxLineageDepth).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the delegation chain above %s: %w", jti, err)
	}
	seen := make(map[LineageIdentity]bool, len(rows))
	out := make([]LineageIdentity, 0, len(rows))
	for _, row := range rows {
		if row.IsCycle {
			return nil, ErrBrokenLineage
		}
		if row.Depth > MaxLineageDepth {
			return nil, ErrLineageTooLong
		}
		if row.IdentityID == "" {
			continue
		}
		key := LineageIdentity{IdentityID: row.IdentityID, AccountID: row.AccountID, ProjectID: row.ProjectID}
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	return out, nil
}

// lockUsableChain locks the chain from parentID up, which must be active and
// unexpired throughout, for the rest of the caller's transaction: the direct
// parent FOR NO KEY UPDATE when lockParentExclusive (so registrations under
// it serialize and can count its children), every other identity FOR SHARE.
// Any status change to a locked row waits for the transaction, and a row
// whose status changed before the lock was taken is re-read, so a chain that
// is not usable by the time it is locked is ErrParentNotActive. Returns the
// chain, parent first.
func lockUsableChain(ctx context.Context, db bun.IDB, parentID, accountID, projectID string, lockParentExclusive bool) ([]Ancestor, error) {
	chain, err := ancestorChain(ctx, db, parentID, accountID, projectID)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrBrokenAncestorChain) {
		return nil, ErrParentNotActive
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	lock := func(ids []string, mode string) error {
		if len(ids) == 0 {
			return nil
		}
		var locked []string
		if err := db.NewSelect().
			TableExpr("identities").
			Column("id").
			Where("id IN (?)", bun.List(ids)).
			Where("account_id = ?", accountID).
			Where("project_id = ?", projectID).
			Where("status = ?", string(domain.IdentityStatusActive)).
			Where("(expires_at IS NULL OR expires_at > ?)", now).
			OrderExpr("id").
			For(mode).
			Scan(ctx, &locked); err != nil {
			return fmt.Errorf("lock the registration tree above the new identity: %w", err)
		}
		if len(locked) != len(ids) {
			return ErrParentNotActive
		}
		return nil
	}
	rest := make([]string, 0, len(chain))
	for _, a := range chain[1:] {
		rest = append(rest, a.ID)
	}
	parentMode := "SHARE"
	if lockParentExclusive {
		parentMode = "NO KEY UPDATE"
	}
	// The parent first, then the rest: a transaction never asks for a
	// stronger lock on a row it already shares, which could deadlock.
	if err := lock([]string{chain[0].ID}, parentMode); err != nil {
		return nil, err
	}
	if err := lock(rest, "SHARE"); err != nil {
		return nil, err
	}
	return chain, nil
}

// CreateUnderParent inserts identity, whose ParentIdentityID is set, provided
// that the parent and every identity above it are still active and unexpired
// identities in the same account and project, and that the child stays within
// limits: no deeper than limits.MaxDepth, and no more than limits.MaxChildren
// children of the parent that are not deactivated.
//
// The chain is locked in the insert's transaction (the parent FOR NO KEY
// UPDATE, the identities above it FOR SHARE). A deactivation of any of them
// updates its row, so the two serialize: either the deactivation commits
// first and this insert is refused, or it waits for the insert, and the
// cascade, which lists an identity's children only after its deactivation
// has committed, then finds the new child. The parent lock also serializes
// sibling registrations, so the child count cannot be overrun.
//
// Joins the caller's transaction when ctx carries one.
func (r *IdentityRepository) CreateUnderParent(ctx context.Context, identity *domain.Identity, limits TreeLimits) error {
	if identity.ParentIdentityID == "" {
		return errors.New("failed to create identity: CreateUnderParent needs a parent_identity_id")
	}
	insert := func(ctx context.Context, db bun.IDB) error {
		chain, err := lockUsableChain(ctx, db, identity.ParentIdentityID, identity.AccountID, identity.ProjectID, true)
		if err != nil {
			return err
		}
		if limits.MaxDepth > 0 && len(chain) > limits.MaxDepth {
			return fmt.Errorf("%w: the new identity would have %d identities above it; the limit is %d",
				ErrTreeTooDeep, len(chain), limits.MaxDepth)
		}
		if limits.MaxChildren > 0 {
			n, err := db.NewSelect().
				TableExpr("identities").
				Where("account_id = ?", identity.AccountID).
				Where("project_id = ?", identity.ProjectID).
				Where("parent_identity_id = ?", identity.ParentIdentityID).
				Where("status <> ?", string(domain.IdentityStatusDeactivated)).
				Count(ctx)
			if err != nil {
				return fmt.Errorf("count the parent identity's children: %w", err)
			}
			if n >= limits.MaxChildren {
				return fmt.Errorf("%w: it has %d that are not deactivated; the limit is %d",
					ErrTooManyChildren, n, limits.MaxChildren)
			}
		}
		if _, err := db.NewInsert().Model(identity).Exec(ctx); err != nil {
			return fmt.Errorf("failed to create identity: %w", err)
		}
		return nil
	}

	if tx, ok := txFromContext(ctx); ok {
		return insert(ctx, tx)
	}
	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return insert(ctx, tx)
	})
}

// IdentityUpdate qualifies an Update.
type IdentityUpdate struct {
	// PriorStatus is the status the caller read. The row is written only if
	// it still has that status; otherwise Update returns ErrIdentityChanged
	// and writes nothing. Required.
	PriorStatus domain.IdentityStatus
	// MarkCascadePending sets cascade_pending_at in the same UPDATE, for a
	// write that retires the identity. Otherwise the column is left as it is.
	MarkCascadePending bool
	// RequireActiveAncestors locks the identity's ancestor chain (it must
	// have a parent) FOR SHARE in the write's transaction and refuses the
	// write with ErrAncestorNotActive unless every identity above it is
	// active and unexpired. For a write that makes the identity active.
	RequireActiveAncestors bool
	// MaxChildren, with RequireActiveAncestors, locks the parent FOR NO KEY
	// UPDATE instead of FOR SHARE, as a registration under it does, and
	// refuses the write with ErrTooManyChildren when the parent already has
	// that many children that are not deactivated. For a write that brings
	// a deactivated child back. Zero checks nothing.
	MaxChildren int
}

// Update writes every column of identity except cascade_pending_at (which
// only MarkCascadePending, the walk and its cleanup change), provided its
// status is still u.PriorStatus. A whole-row write would otherwise put back a
// status that a concurrent write, such as a deactivation cascade, changed in
// between.
func (r *IdentityRepository) Update(ctx context.Context, identity *domain.Identity, u IdentityUpdate) error {
	if u.PriorStatus == "" {
		return errors.New("failed to update identity: the prior status is required")
	}
	identity.ModifiedBy = middleware.GetCallerName(ctx)
	write := func(ctx context.Context, db bun.IDB) error {
		if u.RequireActiveAncestors {
			if identity.ParentIdentityID == "" {
				return errors.New("failed to update identity: RequireActiveAncestors needs a parent")
			}
			if _, err := lockUsableChain(ctx, db, identity.ParentIdentityID, identity.AccountID, identity.ProjectID, u.MaxChildren > 0); err != nil {
				if errors.Is(err, ErrParentNotActive) {
					return ErrAncestorNotActive
				}
				return err
			}
			if u.MaxChildren > 0 {
				// Under the parent's lock, so this and a concurrent
				// registration or reactivation under the same parent
				// cannot together overrun the limit.
				n, err := db.NewSelect().
					TableExpr("identities").
					Where("account_id = ?", identity.AccountID).
					Where("project_id = ?", identity.ProjectID).
					Where("parent_identity_id = ?", identity.ParentIdentityID).
					Where("status <> ?", string(domain.IdentityStatusDeactivated)).
					Where("id <> ?", identity.ID).
					Count(ctx)
				if err != nil {
					return fmt.Errorf("count the parent identity's children: %w", err)
				}
				if n >= u.MaxChildren {
					return fmt.Errorf("%w: it has %d that are not deactivated; the limit is %d",
						ErrTooManyChildren, n, u.MaxChildren)
				}
			}
		}
		q := db.NewUpdate().Model(identity).ExcludeColumn("cascade_pending_at")
		if u.MarkCascadePending {
			q = q.Set("cascade_pending_at = now()")
		}
		res, err := q.
			Where("id = ? AND account_id = ? AND project_id = ?", identity.ID, identity.AccountID, identity.ProjectID).
			Where("status = ?", string(u.PriorStatus)).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to update identity: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to update identity: %w", err)
		} else if n == 0 {
			return ErrIdentityChanged
		}
		return nil
	}
	if !u.RequireActiveAncestors {
		return write(ctx, dbOrTx(ctx, r.db))
	}
	if tx, ok := txFromContext(ctx); ok {
		return write(ctx, tx)
	}
	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return write(ctx, tx)
	})
}

// ListChildren returns the identities registered by any of parentIDs (their
// direct children) within the given account and project, whatever their
// status, in creation order. An empty parentIDs matches nothing.
func (r *IdentityRepository) ListChildren(ctx context.Context, parentIDs []string, accountID, projectID string) ([]*domain.Identity, error) {
	if len(parentIDs) == 0 {
		return nil, nil
	}
	var identities []*domain.Identity
	if err := dbOrTx(ctx, r.db).NewSelect().Model(&identities).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("parent_identity_id IN (?)", bun.List(parentIDs)).
		OrderExpr("created_at ASC, id ASC").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("list child identities: %w", err)
	}
	return identities, nil
}

// ListChildIDs returns the ids of the identities registered by any of
// parentIDs, whatever their status. An empty parentIDs matches nothing.
func (r *IdentityRepository) ListChildIDs(ctx context.Context, parentIDs []string, accountID, projectID string) ([]string, error) {
	if len(parentIDs) == 0 {
		return nil, nil
	}
	var ids []string
	if err := dbOrTx(ctx, r.db).NewSelect().
		TableExpr("identities").
		Column("id").
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("parent_identity_id IN (?)", bun.List(parentIDs)).
		Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("list child identity ids: %w", err)
	}
	return ids, nil
}

// DeactivateChildren deactivates, in one statement, every identity registered
// by any of parentIDs that is not already deactivated, marks each
// cascade_pending (its own cleanup is still to run), and returns the rows it
// changed. It writes only status, the mark, updated_at and modified_by, and
// only on rows whose status is not deactivated when the statement reaches
// them, so it neither overwrites nor is overwritten by a concurrent write's
// other columns, and two walks never both return the same row.
func (r *IdentityRepository) DeactivateChildren(ctx context.Context, parentIDs []string, accountID, projectID string) ([]*domain.Identity, error) {
	if len(parentIDs) == 0 {
		return nil, nil
	}
	var changed []*domain.Identity
	q := dbOrTx(ctx, r.db).NewUpdate().Model(&changed).
		Set("status = ?", string(domain.IdentityStatusDeactivated)).
		Set("cascade_pending_at = now()").
		Set("updated_at = ?", time.Now())
	if callerID := middleware.GetCallerName(ctx); callerID != "" {
		q = q.Set("modified_by = ?", callerID)
	}
	if _, err := q.
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("parent_identity_id IN (?)", bun.List(parentIDs)).
		Where("status <> ?", string(domain.IdentityStatusDeactivated)).
		Returning("*").
		Exec(ctx, &changed); err != nil {
		return nil, fmt.Errorf("deactivate child identities: %w", err)
	}
	return changed, nil
}

// ClearCascadePending removes the cascade_pending mark from the given
// identities.
func (r *IdentityRepository) ClearCascadePending(ctx context.Context, ids []string, accountID, projectID string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := dbOrTx(ctx, r.db).NewUpdate().
		TableExpr("identities").
		Set("cascade_pending_at = NULL").
		Where("id IN (?)", bun.List(ids)).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("cascade_pending_at IS NOT NULL").
		Exec(ctx); err != nil {
		return fmt.Errorf("clear cascade_pending: %w", err)
	}
	return nil
}

// TouchCascadePending moves the mark on the given identities, where it is
// still set, to now: a resume that failed goes to the back of the queue, so
// one that keeps failing does not hold the oldest-first batch for ever.
func (r *IdentityRepository) TouchCascadePending(ctx context.Context, ids []string, accountID, projectID string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := dbOrTx(ctx, r.db).NewUpdate().
		TableExpr("identities").
		Set("cascade_pending_at = now()").
		Where("id IN (?)", bun.List(ids)).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("cascade_pending_at IS NOT NULL").
		Exec(ctx); err != nil {
		return fmt.Errorf("move cascade_pending: %w", err)
	}
	return nil
}

// MarkUnfinishedRetirements marks cascade_pending up to limit retired
// (deactivated or expired) identities, across every tenant, that are not
// marked but still have a child that is not deactivated: a retirement no walk
// will otherwise reach, such as one written by a release that predates the
// tree (a rollback target, or an old pod during a rollout), which deactivates
// one row and sets no mark. Returns how many it marked. The statement reads
// only identities that have a parent (the partial index on
// parent_identity_id) and their parents by primary key.
func (r *IdentityRepository) MarkUnfinishedRetirements(ctx context.Context, limit int) (int, error) {
	res, err := dbOrTx(ctx, r.db).NewRaw(`
UPDATE identities p SET cascade_pending_at = now()
WHERE p.id IN (
	SELECT DISTINCT c.parent_identity_id
	FROM identities c
	JOIN identities par
	  ON par.id = c.parent_identity_id
	 AND par.account_id = c.account_id
	 AND par.project_id = c.project_id
	WHERE c.parent_identity_id IS NOT NULL
	  AND c.status <> ?
	  AND par.status IN (?, ?)
	  AND par.cascade_pending_at IS NULL
	LIMIT ?
)
AND p.status IN (?, ?)
AND p.cascade_pending_at IS NULL`,
		string(domain.IdentityStatusDeactivated),
		string(domain.IdentityStatusDeactivated), string(domain.IdentityStatusExpired),
		limit,
		string(domain.IdentityStatusDeactivated), string(domain.IdentityStatusExpired),
	).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("mark unfinished retirements: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("mark unfinished retirements: %w", err)
	}
	return int(n), nil
}

// ListCascadePending returns up to limit identities, across every tenant,
// still marked cascade_pending, oldest mark first, through the partial index
// on the mark (migration 072).
func (r *IdentityRepository) ListCascadePending(ctx context.Context, limit int) ([]*domain.Identity, error) {
	var identities []*domain.Identity
	if err := dbOrTx(ctx, r.db).NewSelect().Model(&identities).
		Where("cascade_pending_at IS NOT NULL").
		OrderExpr("cascade_pending_at ASC").
		Limit(limit).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("list identities with a pending cascade: %w", err)
	}
	return identities, nil
}
