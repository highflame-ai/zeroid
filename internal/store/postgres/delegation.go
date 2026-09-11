package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// DelegationRepository walks the credential delegation graph via parent_jti.
//
// Two recursive CTE walkers (WalkUp / WalkDown) and one aggregate
// (ListChains) cover every read pattern the Delegation Explorer needs:
//
//   - WalkUp follows parent_jti links from a starting JTI to the root,
//     answering "who delegated this token to me, and through what chain?"
//   - WalkDown follows reverse parent_jti links (children) from a starting
//     JTI to leaves, answering "what tokens were minted off this one?"
//   - ListChains groups by COALESCE(mission_id, jti) to produce one row per
//     delegation tree active in a time window, ordered by last activity.
//
// All three are tenant-scoped on every join. Both walkers are depth-capped
// and use the SQL-standard CYCLE clause (Postgres 14+) for cycle safety,
// matching the pattern established by revoke_credentials_cascade
// (migrations/007_cascade_revocation.up.sql).
//
// See issue #153.
type DelegationRepository struct {
	db *bun.DB
}

// NewDelegationRepository creates a new DelegationRepository.
func NewDelegationRepository(db *bun.DB) *DelegationRepository {
	return &DelegationRepository{db: db}
}

// ChainSummary is one row of /delegations/chains output — a single
// delegation tree active in the requested time window.
//
// ChainID is COALESCE(mission_id, jti): for credentials issued after the
// mission_id denormalization landed it's the mission_id (= root JTI);
// for legacy pre-denormalization credentials it falls back to grouping
// each row as its own chain. The two cases are indistinguishable to
// callers — both are opaque chain handles.
type ChainSummary struct {
	ChainID         string    `bun:"chain_id"          json:"chain_id"`
	StartedAt       time.Time `bun:"started_at"        json:"started_at"`
	LastActivityAt  time.Time `bun:"last_activity_at"  json:"last_activity_at"`
	CredentialCount int       `bun:"credential_count"  json:"credential_count"`
	MaxDepth        int       `bun:"max_depth"         json:"max_depth"`

	// The identity the chain was issued TO — the root credential's subject.
	//
	// Carried on the summary so a caller does not have to walk /by-jti once
	// per row to find out who a chain belongs to. Studio did exactly that,
	// turning one list request into N+1 against this service, and it is also
	// what forced the agent filter to run client-side over a capped page:
	// without an identity on the row, the server had nothing to filter on.
	//
	// Empty when the root credential predates the identity link or its
	// identity row was deleted (identity_id is ON DELETE SET NULL).
	RootIdentityID   string `bun:"root_identity_id"    json:"root_identity_id,omitempty"`
	RootIdentityName string `bun:"root_identity_name"  json:"root_identity_name,omitempty"`
	RootWimseURI     string `bun:"root_wimse_uri"      json:"root_wimse_uri,omitempty"`
}

// WalkUp returns the credential identified by startJTI plus its ancestors
// reached by following parent_jti links upward, capped at maxDepth hops.
// Results are ordered root → starting credential.
//
// The recursive CTE anchors on startJTI (depth 0) and joins on
// `ic.jti = chain.parent_jti` to climb the chain one hop at a time. The
// CYCLE clause guards against any pathological cycle even though
// parent_jti is acyclic by construction; the hard depth cap is the
// second line of defense.
//
// Tenant scope is enforced both at the anchor and on every recursive
// step. Credentials with parent_jti pointing into a different tenant
// would not be reachable because the recursive step filters on
// `ic.account_id` / `ic.project_id`.
//
// Like WalkDown, this query does NOT constrain by mission_id because
// parent credentials may belong to a different mission when a sub-agent
// starts a new mission_id. The up-walk is single-parent (each credential
// has at most one parent_jti), so there is no fan-out to constrain —
// the structural parent_jti chain is sufficient and tenant scoping keeps
// the walk bounded.
func (r *DelegationRepository) WalkUp(ctx context.Context, startJTI, accountID, projectID string, maxDepth int) ([]*domain.IssuedCredential, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}
	var creds []*domain.IssuedCredential
	db := dbOrTx(ctx, r.db)
	// Order DESC so root (highest depth) appears first.
	const q = `
		WITH RECURSIVE chain(id, jti, parent_jti, depth) AS (
			SELECT id, jti, parent_jti, 0
			FROM issued_credentials
			WHERE jti = ?
			  AND account_id = ?
			  AND project_id = ?
			UNION ALL
			SELECT ic.id, ic.jti, ic.parent_jti, chain.depth + 1
			FROM issued_credentials ic
			JOIN chain ON ic.jti = chain.parent_jti
			WHERE ic.account_id = ?
			  AND ic.project_id = ?
			  AND chain.depth < ?
		) CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
		SELECT ic.*
		FROM issued_credentials ic
		JOIN chain ON ic.id = chain.id
		WHERE NOT chain.is_cycle
		ORDER BY chain.depth DESC, ic.issued_at ASC`
	if err := db.NewRaw(q, startJTI, accountID, projectID, accountID, projectID, maxDepth).Scan(ctx, &creds); err != nil {
		return nil, fmt.Errorf("walk-up delegation chain: %w", err)
	}
	return creds, nil
}

// WalkDown returns the credential identified by startJTI plus its
// descendants reached by following reverse parent_jti links (children),
// capped at maxDepth hops. Results are ordered starting credential →
// leaves (depth ASC, issued_at ASC for ties).
//
// The recursive step joins `ic.parent_jti = chain.jti` to find the
// children of each row in the chain. Same CYCLE + depth-cap safety as
// WalkUp. Same tenant scoping on every join.
//
// Unlike WalkUp, this query does NOT constrain by mission_id because
// child delegations may start new missions (different mission_id from
// their parent). The parent_jti join is structurally unique and
// sufficient to define the tree — mission_id filtering would silently
// prune legitimate subtrees.
func (r *DelegationRepository) WalkDown(ctx context.Context, startJTI, accountID, projectID string, maxDepth int) ([]*domain.IssuedCredential, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}
	var creds []*domain.IssuedCredential
	db := dbOrTx(ctx, r.db)
	const q = `
		WITH RECURSIVE chain(id, jti, depth) AS (
			SELECT id, jti, 0
			FROM issued_credentials
			WHERE jti = ?
			  AND account_id = ?
			  AND project_id = ?
			UNION ALL
			SELECT ic.id, ic.jti, chain.depth + 1
			FROM issued_credentials ic
			JOIN chain ON ic.parent_jti = chain.jti
			WHERE ic.account_id = ?
			  AND ic.project_id = ?
			  AND chain.depth < ?
		) CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
		SELECT ic.*
		FROM issued_credentials ic
		JOIN chain ON ic.id = chain.id
		WHERE NOT chain.is_cycle
		ORDER BY chain.depth ASC, ic.issued_at ASC`
	if err := db.NewRaw(q, startJTI, accountID, projectID, accountID, projectID, maxDepth).Scan(ctx, &creds); err != nil {
		return nil, fmt.Errorf("walk-down delegation chain: %w", err)
	}
	return creds, nil
}

// WalkDownMulti is the batched variant of WalkDown — it seeds the
// recursive CTE with multiple root JTIs at once, avoiding one query per
// root. All roots share the same tenant scope and depth cap. Results are
// ordered depth ASC, issued_at ASC (same as WalkDown).
func (r *DelegationRepository) WalkDownMulti(ctx context.Context, startJTIs []string, accountID, projectID string, maxDepth int) ([]*domain.IssuedCredential, error) {
	if len(startJTIs) == 0 {
		return nil, nil
	}
	if maxDepth < 0 {
		maxDepth = 0
	}
	var creds []*domain.IssuedCredential
	db := dbOrTx(ctx, r.db)
	const q = `
		WITH RECURSIVE chain(id, jti, depth) AS (
			SELECT id, jti, 0
			FROM issued_credentials
			WHERE jti IN (?)
			  AND account_id = ?
			  AND project_id = ?
			UNION ALL
			SELECT ic.id, ic.jti, chain.depth + 1
			FROM issued_credentials ic
			JOIN chain ON ic.parent_jti = chain.jti
			WHERE ic.account_id = ?
			  AND ic.project_id = ?
			  AND chain.depth < ?
		) CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
		SELECT ic.*
		FROM issued_credentials ic
		JOIN chain ON ic.id = chain.id
		WHERE NOT chain.is_cycle
		ORDER BY chain.depth ASC, ic.issued_at ASC`
	if err := db.NewRaw(q, bun.List(startJTIs), accountID, projectID, accountID, projectID, maxDepth).Scan(ctx, &creds); err != nil {
		return nil, fmt.Errorf("walk-down-multi delegation chain: %w", err)
	}
	return creds, nil
}

// ListChains returns one summary row per delegation tree active in the
// [since, until) window, ordered by last activity descending. limit
// caps the result set.
//
// Grouping is COALESCE(mission_id, jti) so credentials denormalized with
// mission_id collapse onto one row per tree, while legacy credentials
// without mission_id each form a one-credential chain. Both cases are
// expected; the result schema is uniform.
//
// The aggregate hits idx_issued_credentials_mission_id for the
// post-denormalization majority. The COALESCE prevents the partial
// index from being used directly in EXPLAIN plans, but tenant-scope
// filtering still narrows the scan to the active tenant's rows.
func (r *DelegationRepository) ListChains(ctx context.Context, accountID, projectID string, since, until time.Time, limit int, rootIdentityID string) ([]*ChainSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows []*ChainSummary
	db := dbOrTx(ctx, r.db)
	// The root credential is found by jti, NOT by picking the lowest
	// delegation_depth inside the window. chain_id is COALESCE(mission_id,
	// jti) and mission_id IS the root jti, so this join reaches the true
	// root even when the root credential was issued before `since` — which
	// is the behaviour the per-row /by-jti walk had, and losing it would
	// silently relabel long-running chains whenever the window moved.
	//
	// The identity join is LEFT: identity_id is ON DELETE SET NULL, and a
	// chain whose identity has been deleted must still be listed. Dropping
	// it would hide exactly the tokens an offboarding review is looking for.
	const q = `
		WITH chains AS (
			SELECT
				COALESCE(mission_id, jti) AS chain_id,
				MIN(issued_at)            AS started_at,
				MAX(issued_at)            AS last_activity_at,
				COUNT(*)::int             AS credential_count,
				MAX(delegation_depth)::int AS max_depth
			FROM issued_credentials
			WHERE account_id = ?
			  AND project_id = ?
			  AND issued_at >= ?
			  AND issued_at <  ?
			GROUP BY COALESCE(mission_id, jti)
		)
		SELECT
			c.chain_id,
			c.started_at,
			c.last_activity_at,
			c.credential_count,
			c.max_depth,
			COALESCE(root.identity_id::text, '') AS root_identity_id,
			COALESCE(i.name, '')                 AS root_identity_name,
			COALESCE(i.wimse_uri, '')            AS root_wimse_uri
		FROM chains c
		LEFT JOIN issued_credentials root
			ON root.jti = c.chain_id
			AND root.account_id = ?
			AND root.project_id = ?
		LEFT JOIN identities i
			ON i.id = root.identity_id
		WHERE (NULLIF(?, '') IS NULL OR root.identity_id = NULLIF(?, '')::uuid)
		ORDER BY c.last_activity_at DESC
		LIMIT ?`
	// The filter is applied BEFORE the limit, which is the whole point: a
	// client filtering a capped page can only ever say "not among these N",
	// never "this agent has none".
	//
	// Compared as uuid, not as text. `identity_id::text = ?` would have cast
	// away the column's type on every row — defeating the index on
	// identity_id — and would have compared canonical lowercase output
	// against whatever case the caller sent, so an upper-case UUID silently
	// matched nothing. NULLIF turns the empty sentinel into NULL before the
	// cast, so "no filter" never reaches ::uuid; the handler's pattern
	// guarantees anything that does reach it parses.
	if err := db.NewRaw(q, accountID, projectID, since, until,
		accountID, projectID, rootIdentityID, rootIdentityID, limit).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list delegation chains: %w", err)
	}
	return rows, nil
}

// IdentityDepth is one row of the identity-depths response — the maximum
// delegation_depth observed across all issued credentials for a given identity.
type IdentityDepth struct {
	IdentityID string `bun:"identity_id" json:"identity_id"`
	MaxDepth   int    `bun:"max_depth"   json:"max_depth"`
}

// MaxDepthByIdentities returns the maximum delegation_depth per identity
// for the given identity IDs within a tenant. Identities with no
// credentials are omitted from the result.
func (r *DelegationRepository) MaxDepthByIdentities(ctx context.Context, accountID, projectID string, identityIDs []string) ([]*IdentityDepth, error) {
	if len(identityIDs) == 0 {
		return nil, nil
	}
	var rows []*IdentityDepth
	db := dbOrTx(ctx, r.db)
	const q = `
		SELECT
			identity_id,
			MAX(delegation_depth)::int AS max_depth
		FROM issued_credentials
		WHERE account_id = ?
		  AND project_id = ?
		  AND identity_id IN (?)
		GROUP BY identity_id`
	if err := db.NewRaw(q, accountID, projectID, bun.List(identityIDs)).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("max depth by identities: %w", err)
	}
	return rows, nil
}
