package integration_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// insertIssuedCredentialRow inserts an issued_credentials row directly via
// testDB so the test can deterministically place rows on either side of the
// cleanup worker's two cutoffs (the expires_at cascade clock and the
// audit_retention_until evidence clock) without minting real tokens whose
// timestamps the service controls. auditRetentionUntil nil produces a NULL
// column — the pre-037 legacy shape.
func insertIssuedCredentialRow(t *testing.T, jti, parentJTI string, expiresAt time.Time, auditRetentionUntil *time.Time) {
	t.Helper()
	row := &domain.IssuedCredential{
		ID:                  uuidV4(t),
		AccountID:           testAccountID,
		ProjectID:           testProjectID,
		JTI:                 jti,
		Subject:             "spiffe://" + testWIMSE + "/" + testAccountID + "/" + testProjectID + "/agent/cleanup-retention",
		ExpiresAt:           expiresAt,
		TTLSeconds:          3600,
		Scopes:              []string{"mcp:read"},
		GrantType:           domain.GrantType("client_credentials"),
		ParentJTI:           parentJTI,
		AuditRetentionUntil: auditRetentionUntil,
	}
	if parentJTI != "" {
		row.DelegationDepth = 1
	}
	_, err := testDB.NewInsert().Model(row).Exec(context.Background())
	require.NoError(t, err, "insert issued_credentials row %s", jti)
}

func issuedCredentialExists(t *testing.T, jti string) bool {
	t.Helper()
	n, err := testDB.NewSelect().
		Model((*domain.IssuedCredential)(nil)).
		Where("jti = ?", jti).
		Count(context.Background())
	require.NoError(t, err)
	return n > 0
}

// TestCleanupRetainsCredentialsWithinAuditRetention proves the two-clock
// prune in CleanupWorker.RunOnce (issue: delegation graph blanks after
// token expiry). A row is deleted only when BOTH clocks have elapsed:
//
//   - expired long ago but audit_retention_until in the future → RETAINED
//     (the evidence clock keeps the delegation graph answerable);
//   - expired long ago and audit_retention_until elapsed → DELETED;
//   - expired long ago with NULL audit_retention_until (pre-037 legacy
//     row) → DELETED under the legacy expires_at-only rule;
//   - audit_retention_until elapsed but expires_at still inside the
//     cascade-walk window (credRetention) → RETAINED, because parent_jti
//     edges may still be needed by cascade revocation;
//   - active, unexpired → never touched.
//
// The test server's cleanup worker runs with credRetention = Token.MaxTTL
// (90 days), so "past the cascade clock" means expires_at < now - 90d.
func TestCleanupRetainsCredentialsWithinAuditRetention(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	future := now.Add(300 * 24 * time.Hour)
	pastHour := now.Add(-time.Hour)
	pastMinute := now.Add(-time.Minute)

	// (1) Past the cascade clock, inside the audit window → RETAIN.
	retainedAudit := uid("cred-retained-audit")
	insertIssuedCredentialRow(t, retainedAudit, "", now.Add(-100*24*time.Hour), &future)

	// (2) Past both clocks → DELETE.
	prunedBoth := uid("cred-pruned-both")
	insertIssuedCredentialRow(t, prunedBoth, "", now.Add(-100*24*time.Hour), &pastHour)

	// (3) Legacy NULL retention, past the cascade clock → DELETE (old rule).
	legacyNull := uid("cred-legacy-null")
	insertIssuedCredentialRow(t, legacyNull, "", now.Add(-100*24*time.Hour), nil)

	// (4) Audit window elapsed but expiry still inside the cascade-walk
	// window → RETAIN. Proves the clocks are ANDed: an aggressive audit
	// clock must never sever parent_jti edges the cascade walk still needs.
	cascadeGuard := uid("cred-cascade-guard")
	insertIssuedCredentialRow(t, cascadeGuard, "", pastHour, &pastMinute)

	// (5) Active credential → RETAIN.
	active := uid("cred-active")
	insertIssuedCredentialRow(t, active, "", now.Add(time.Hour), &future)

	testZeroIDServer.RunCleanupOnce(ctx)

	assert.True(t, issuedCredentialExists(t, retainedAudit), "expired-but-within-retention row must survive the sweep")
	assert.False(t, issuedCredentialExists(t, prunedBoth), "row past both clocks must be pruned")
	assert.False(t, issuedCredentialExists(t, legacyNull), "legacy NULL-retention row must be pruned under the expires_at rule")
	assert.True(t, issuedCredentialExists(t, cascadeGuard), "row inside the cascade-walk window must survive even with audit retention elapsed")
	assert.True(t, issuedCredentialExists(t, active), "active row must never be touched")
}

// TestDelegationGraphSurvivesTokenExpiry proves the product symptom is
// fixed: a delegation chain whose parent token expired long ago still
// resolves through the graph CTEs (WalkUp from the live child reaches the
// expired root; WalkDown from the expired root reaches the child) after a
// cleanup pass, because the expired row is retained by its evidence clock.
func TestDelegationGraphSurvivesTokenExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	future := now.Add(300 * 24 * time.Hour)

	// Root expired well past the cascade clock (90d) but within audit
	// retention; child is still live and points at it via parent_jti.
	rootJTI := uid("cred-graph-root")
	childJTI := uid("cred-graph-child")
	insertIssuedCredentialRow(t, rootJTI, "", now.Add(-100*24*time.Hour), &future)
	insertIssuedCredentialRow(t, childJTI, rootJTI, now.Add(time.Hour), &future)

	testZeroIDServer.RunCleanupOnce(ctx)

	repo := postgres.NewDelegationRepository(testDB)

	up, err := repo.WalkUp(ctx, childJTI, testAccountID, testProjectID, 10)
	require.NoError(t, err)
	upJTIs := make([]string, 0, len(up))
	for _, c := range up {
		upJTIs = append(upJTIs, c.JTI)
	}
	assert.Contains(t, upJTIs, rootJTI, "walk-up from the live child must still reach the expired root")
	assert.Contains(t, upJTIs, childJTI)

	down, err := repo.WalkDown(ctx, rootJTI, testAccountID, testProjectID, 10)
	require.NoError(t, err)
	downJTIs := make([]string, 0, len(down))
	for _, c := range down {
		downJTIs = append(downJTIs, c.JTI)
	}
	assert.Contains(t, downJTIs, childJTI, "walk-down from the expired root must still reach the live child")
}

// TestRotateRejectsExpiredCredential pins the guard that keeps audit
// retention from widening the rotation surface: rows now outlive expiry by
// ~400 days, and RotateCredential's revoke half is a silent no-op on an
// expired row (the cascade anchor requires expires_at > revoked_at) — so
// without the guard, "rotate" would mint a live token off a long-dead
// credential. An expired credential must be rejected, left unrevoked, and
// no replacement minted.
func TestRotateRejectsExpiredCredential(t *testing.T) {
	ctx := context.Background()

	policyID := delegationPolicy(t, uid("rotate-expired-policy"), []string{"mcp:read"})
	identityID, jti, _ := issueRootCredential(t, policyID, "rotate-expired", []string{"mcp:read"})

	var cred domain.IssuedCredential
	require.NoError(t, testDB.NewSelect().Model(&cred).Where("jti = ?", jti).Scan(ctx))

	// Age the credential past expiry directly — the API cannot mint an
	// already-expired token.
	_, err := testDB.NewUpdate().
		Model((*domain.IssuedCredential)(nil)).
		Set("expires_at = ?", time.Now().Add(-time.Hour)).
		Where("id = ?", cred.ID).
		Exec(ctx)
	require.NoError(t, err)

	resp := post(t, adminPath("/credentials/"+cred.ID+"/rotate"), nil, adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	// 409 Conflict, not 5xx: rotating a dead credential is a terminal-state
	// client mistake, not a server fault (it must not fire 5xx alerting).
	assert.Equal(t, http.StatusConflict, resp.StatusCode,
		"rotating an expired credential must return 409, not resurrect it or 500")

	// The expired row must be untouched: not retro-revoked, and no
	// replacement credential minted for the identity.
	require.NoError(t, testDB.NewSelect().Model(&cred).Where("id = ?", cred.ID).Scan(ctx))
	assert.False(t, cred.IsRevoked, "failed rotation must not retro-revoke the expired row")

	n, err := testDB.NewSelect().
		Model((*domain.IssuedCredential)(nil)).
		Where("identity_id = ?", identityID).
		Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "failed rotation must not mint a replacement credential")
}

// TestIssuedCredentialStampedWithAuditRetention proves the write path: a
// credential minted through the real issuance flow carries a non-NULL
// audit_retention_until strictly beyond its expires_at, so every new row
// participates in the two-clock model without backfill.
func TestIssuedCredentialStampedWithAuditRetention(t *testing.T) {
	policyID := delegationPolicy(t, uid("cleanup-retention-policy"), []string{"mcp:read"})
	_, jti, _ := issueRootCredential(t, policyID, "cleanup-retention", []string{"mcp:read"})

	var cred domain.IssuedCredential
	err := testDB.NewSelect().
		Model(&cred).
		Where("jti = ?", jti).
		Scan(context.Background())
	require.NoError(t, err)

	require.NotNil(t, cred.AuditRetentionUntil, "issuance must stamp the evidence clock")
	assert.True(t, cred.AuditRetentionUntil.After(cred.ExpiresAt),
		"audit_retention_until (%s) must be beyond expires_at (%s)", cred.AuditRetentionUntil, cred.ExpiresAt)
}
