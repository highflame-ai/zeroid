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
//
// A delegated credential (ParentJTI set) is inserted only while its parent
// and every credential above it are unrevoked: the chain is locked FOR SHARE
// in the insert's transaction and re-read under the lock, and a revoked one
// is ErrRevokedLineage. Every cascade locks the tokens it starts from before
// it walks the tokens below them (revoke_credential_cascade since migration
// 073, the identity and owner cascades since 074, parents first), so the two
// serialize: either the revocation commits first and this insert is refused,
// or the revocation waits for the insert to commit, and its walk then finds
// the new credential and revokes it too.
//
// A delegated credential is also stored as issued after its parent: an
// IssuedAt that is not at least a microsecond later than the parent's (the
// replica that issued the parent had a clock ahead of this one) is moved to
// a microsecond after it. The bulk cascades lock their anchors ordered by
// (delegation_depth, issued_at, id) and rely on that order putting a parent
// first; a parent and child at the same depth (a re-scoping exchange, a CIBA
// grant) are told apart by issued_at alone. The signed token's iat is not
// changed.
func (r *CredentialRepository) Create(ctx context.Context, cred *domain.IssuedCredential) error {
	insert := func(ctx context.Context, db bun.IDB) error {
		if cred.ParentJTI != "" {
			parentIssuedAt, err := lockUnrevokedLineage(ctx, db, cred.ParentJTI)
			if err != nil {
				return err
			}
			if !cred.IssuedAt.IsZero() && cred.IssuedAt.Sub(parentIssuedAt) < time.Microsecond {
				cred.IssuedAt = parentIssuedAt.Add(time.Microsecond)
			}
		}
		if _, err := db.NewInsert().Model(cred).Exec(ctx); err != nil {
			return fmt.Errorf("failed to create credential: %w", err)
		}
		return nil
	}
	if cred.ParentJTI == "" {
		return insert(ctx, dbOrTx(ctx, r.db))
	}
	if tx, ok := txFromContext(ctx); ok {
		return insert(ctx, tx)
	}
	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return insert(ctx, tx)
	})
}

// lockLineageSQL follows parent_jti up from one credential, as
// credentialLineageSQL does, then locks every credential it reached FOR
// SHARE, the root first. The rows are locked in the sorted order (LockRows
// runs above the Sort), so every issuance takes them top-down, and one
// waiting on a row has locked nothing below it. A row updated by a
// transaction that committed while this one waited is returned as it now
// is (READ COMMITTED re-reads a locked row), so is_revoked is current.
const lockLineageSQL = `
WITH RECURSIVE lineage(id, jti, parent_jti, depth) AS (
	SELECT id, jti, parent_jti, 1
	FROM issued_credentials
	WHERE jti = ?
	UNION ALL
	SELECT ic.id, ic.jti, ic.parent_jti, lineage.depth + 1
	FROM issued_credentials ic
	JOIN lineage ON ic.jti = lineage.parent_jti
	WHERE lineage.depth <= ?
) CYCLE jti SET is_cycle TO TRUE DEFAULT FALSE USING cycle_path
SELECT ic.is_revoked, ic.issued_at, lineage.depth, lineage.is_cycle
FROM issued_credentials ic
JOIN lineage ON ic.id = lineage.id
ORDER BY lineage.depth DESC
FOR SHARE OF ic`

// lockUnrevokedLineage locks the credential parentJTI and every credential it
// was delegated from for the rest of db's transaction, returns
// ErrRevokedLineage if any of them is revoked, and otherwise returns the
// parent's issued_at. A chain that loops or is longer than MaxLineageDepth is
// ErrBrokenLineage, and a parent that does not exist is an error: the caller
// read it moments ago.
func lockUnrevokedLineage(ctx context.Context, db bun.IDB, parentJTI string) (time.Time, error) {
	var rows []struct {
		IsRevoked bool      `bun:"is_revoked"`
		IssuedAt  time.Time `bun:"issued_at"`
		Depth     int       `bun:"depth"`
		IsCycle   bool      `bun:"is_cycle"`
	}
	if err := db.NewRaw(lockLineageSQL, parentJTI, MaxLineageDepth).Scan(ctx, &rows); err != nil {
		return time.Time{}, fmt.Errorf("lock the delegation chain above the new credential: %w", err)
	}
	if len(rows) == 0 {
		return time.Time{}, fmt.Errorf("lock the delegation chain above the new credential: parent credential %s does not exist", parentJTI)
	}
	var parentIssuedAt time.Time
	for _, row := range rows {
		if row.IsCycle || row.Depth > MaxLineageDepth {
			return time.Time{}, ErrBrokenLineage
		}
		if row.IsRevoked {
			return time.Time{}, ErrRevokedLineage
		}
		if row.Depth == 1 {
			parentIssuedAt = row.IssuedAt
		}
	}
	return parentIssuedAt, nil
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

// RevokedCredential is the minimal projection of a credential affected by a
// cascade revocation, returned by the revoke functions so the service layer can
// emit one RevocationNotifier event per affected JTI without a follow-up query.
// IdentityID is nullable because delegated descendants may not carry an
// identity_id, and the synthetic external-principal carrier has none.
type RevokedCredential struct {
	JTI        string    `bun:"jti"`
	IdentityID *string   `bun:"identity_id"`
	AccountID  string    `bun:"account_id"`
	ProjectID  string    `bun:"project_id"`
	ExpiresAt  time.Time `bun:"expires_at"`
	RevokedAt  time.Time `bun:"-"`
}

// RevokeAllActiveForIdentity revokes all non-expired, non-revoked credentials for an
// identity and cascades the revocation to every downstream delegated credential in the
// parent_jti chain (RFC 8693 token_exchange descendants), regardless of which identity
// issued those child tokens. Implemented via the revoke_credentials_cascade DB function
// (migration 007, evolved to RETURNS TABLE in migration 029) which executes the full
// subtree update atomically in one statement and returns the affected rows.
//
// Returns the affected credentials (root + descendants), one entry per revoked
// JTI, each stamped with the cascade's revoked_at timestamp. len(result) is the
// total number of credentials revoked.
func (r *CredentialRepository) RevokeAllActiveForIdentity(ctx context.Context, identityID, reason string) ([]RevokedCredential, error) {
	now := time.Now()
	var rows []RevokedCredential
	db := dbOrTx(ctx, r.db)
	if err := db.NewRaw(
		"SELECT jti, identity_id, account_id, project_id, expires_at FROM revoke_credentials_cascade(?, ?, ?)",
		identityID, now, reason,
	).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("failed to cascade-revoke credentials for identity %s: %w", identityID, err)
	}
	for i := range rows {
		rows[i].RevokedAt = now
	}
	return rows, nil
}

// RevokeAllActiveForOwner revokes every non-expired, non-revoked credential
// belonging to an identity owned by ownerUserID within accountID, and cascades
// to every downstream delegated credential in the parent_jti chain. This is the
// primitive for human offboarding: deactivating a person revokes every agent
// that person owns (and their sub-agents) at once. Implemented via the
// revoke_credentials_by_owner DB function (migration 041), which mirrors the
// identity cascade's atomic single-statement update and returned-row semantics.
//
// Scoped by (ownerUserID, accountID) for tenant safety. Returns the affected
// credentials, one entry per revoked JTI, each stamped with the revoked_at
// timestamp; len(result) is the total number revoked.
func (r *CredentialRepository) RevokeAllActiveForOwner(ctx context.Context, ownerUserID, accountID, reason string) ([]RevokedCredential, error) {
	now := time.Now()
	var rows []RevokedCredential
	db := dbOrTx(ctx, r.db)
	if err := db.NewRaw(
		"SELECT jti, identity_id, account_id, project_id, expires_at FROM revoke_credentials_by_owner(?, ?, ?, ?)",
		ownerUserID, accountID, now, reason,
	).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("failed to cascade-revoke credentials for owner %s in account %s: %w", ownerUserID, accountID, err)
	}
	for i := range rows {
		rows[i].RevokedAt = now
	}
	return rows, nil
}

// Revoke marks a credential as revoked and cascades the revocation to every
// downstream delegated credential in the parent_jti chain (RFC 8693 descendants).
// account_id and project_id are enforced on the anchor as tenant-safety guards.
// Implemented via the revoke_credential_cascade DB function (migration 007,
// evolved to RETURNS TABLE in migration 029).
//
// Returns the affected credentials (the token itself + descendants), one entry
// per revoked JTI, each stamped with the cascade's revoked_at timestamp.
// ListActiveLongLivedUserAccessTokenIDs returns the ids of a tenant's active
// authorization_code and refresh_token access tokens whose lifetime exceeds
// maxTTLSeconds. Those grants always mint for a person, so these are the
// long-lived user-subject roots the rfc8693 profile switch revokes (D14).
func (r *CredentialRepository) ListActiveLongLivedUserAccessTokenIDs(ctx context.Context, accountID, projectID string, maxTTLSeconds int) ([]string, error) {
	var ids []string
	err := dbOrTx(ctx, r.db).NewSelect().
		Model((*domain.IssuedCredential)(nil)).
		Column("id").
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Where("grant_type IN (?)", bun.List([]string{string(domain.GrantTypeAuthorizationCode), string(domain.GrantTypeRefreshToken)})).
		Where("ttl_seconds > ?", maxTTLSeconds).
		Where("is_revoked = FALSE").
		Where("expires_at > NOW()").
		Scan(ctx, &ids)
	if err != nil {
		return nil, fmt.Errorf("failed to list long-lived user access tokens: %w", err)
	}
	return ids, nil
}

// RefreshFamilyCredential identifies one active access token issued under a
// refresh-token family, with the tenant scalars the revoke cascade guards on.
type RefreshFamilyCredential struct {
	ID        string `bun:"id"`
	AccountID string `bun:"account_id"`
	ProjectID string `bun:"project_id"`
}

// ListActiveByRefreshFamily returns the active (not revoked, not expired)
// access tokens issued under the given refresh-token family. Backed by the
// partial index idx_issued_credentials_refresh_family_id (migration 055).
func (r *CredentialRepository) ListActiveByRefreshFamily(ctx context.Context, familyID string) ([]RefreshFamilyCredential, error) {
	var rows []RefreshFamilyCredential
	err := dbOrTx(ctx, r.db).NewSelect().
		Model((*domain.IssuedCredential)(nil)).
		Column("id", "account_id", "project_id").
		Where("refresh_family_id = ?", familyID).
		Where("is_revoked = FALSE").
		Where("expires_at > NOW()").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("failed to list access tokens for refresh family: %w", err)
	}
	return rows, nil
}

func (r *CredentialRepository) Revoke(ctx context.Context, id, accountID, projectID, reason string) ([]RevokedCredential, error) {
	now := time.Now()
	var rows []RevokedCredential
	db := dbOrTx(ctx, r.db)
	if err := db.NewRaw(
		"SELECT jti, identity_id, account_id, project_id, expires_at FROM revoke_credential_cascade(?, ?, ?, ?, ?)",
		id, accountID, projectID, now, reason,
	).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("failed to cascade-revoke credential %s: %w", id, err)
	}
	for i := range rows {
		rows[i].RevokedAt = now
	}
	return rows, nil
}
