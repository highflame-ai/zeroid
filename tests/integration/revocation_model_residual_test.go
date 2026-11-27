package integration_test

// A deadlock the lock-order model (verify/tla, check head-residual-deadlock)
// finds on rows stored by this release, and that runCascade's retry is there
// to absorb: a token stored while a cascade's first statement waits is locked
// by its second statement, after rows that come later in the order, while a
// second cascade that saw the new token already holds it.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// mrCred stores one credential at the given delegation depth through the
// issuance chokepoint's repository call. identityID may be "".
func mrCred(ctx context.Context, tn hrdTenant, parentJTI, identityID string, depth int) (string, error) {
	jti := uuid.NewString()
	cred := &domain.IssuedCredential{
		ID: uuid.NewString(), AccountID: tn.account, ProjectID: tn.project,
		JTI: jti, Subject: "lock-model", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), TTLSeconds: 3600,
		Scopes: []string{}, GrantType: domain.GrantTypeTokenExchange, ParentJTI: parentJTI, DelegationDepth: depth,
	}
	if identityID != "" {
		cred.IdentityID = &identityID
	}
	return jti, postgres.NewCredentialRepository(testDB).Create(ctx, cred)
}

// mrRetries returns runCascade's log lines for a cascade aborted as a deadlock
// victim and run again.
func mrRetries(t *testing.T, sl *serverLog) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range sl.find(t, "cascade revocation aborted by the database; running it again", nil) {
		if e, _ := line["error"].(string); strings.Contains(e, "40P01") {
			out = append(out, line)
		}
	}
	return out
}

// TestCascadeRetryAbsorbsDeadlockOnTokenStoredDuringFirstStatement: X's token
// A → B (no identity, depth 1) → S (Y's, depth 2), and an exchange of A storing
// C for Y at depth 1, so C sorts before S.
//
//  1. The exchange locks A FOR SHARE and inserts C; a test transaction holds S
//     FOR SHARE.
//  2. X's cascade starts: its first statement's snapshot has A, B, S. It waits
//     for A.
//  3. The exchange commits. X's first statement locks A and B and waits for S.
//  4. Y's cascade starts: its snapshot has C. It locks C and waits for S.
//  5. S is released. X takes S, and its second statement (new snapshot, now
//     with C) waits for C, which Y holds; Y waits for S, which X holds.
//
// PostgreSQL aborts one of the two, and runCascade runs it again. Both must
// return without error and leave nothing live below a revoked token.
func TestCascadeRetryAbsorbsDeadlockOnTokenStoredDuringFirstStatement(t *testing.T) {
	const trials = 3
	sl := captureServerLog(t)
	deadlocked := 0
	for trial := 0; trial < trials; trial++ {
		ctx := context.Background()
		tn := newTenant(t, "")
		policyID := tn.policy(t, []string{"data:read"})
		identX, identY := rlIdentity(t, tn, policyID), rlIdentity(t, tn, policyID)
		aJTI, err := mrCred(ctx, tn, "", identX, 0)
		require.NoError(t, err)
		bJTI, err := mrCred(ctx, tn, aJTI, "", 1)
		require.NoError(t, err)
		sJTI, err := mrCred(ctx, tn, bJTI, identY, 2)
		require.NoError(t, err)

		exch, err := testDB.BeginTx(ctx, nil)
		require.NoError(t, err)
		cJTI, err := mrCred(postgres.WithTx(ctx, exch), tn, aJTI, identY, 1)
		require.NoError(t, err)
		hold, err := testDB.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = hold.ExecContext(ctx, `SELECT 1 FROM issued_credentials WHERE jti = ? FOR SHARE`, sJTI)
		require.NoError(t, err)

		before := len(mrRetries(t, sl))
		repo := postgres.NewCredentialRepository(testDB)
		errs := make(chan error, 2)
		go func() {
			_, err := repo.RevokeAllActiveForIdentity(ctx, identX, "lock_model_test")
			errs <- err
		}()
		loWaitForWaiters(t, "revoke_credentials_cascade", 1)
		require.NoError(t, exch.Commit())
		time.Sleep(100 * time.Millisecond) // X's first statement moves on to S
		go func() {
			_, err := repo.RevokeAllActiveForIdentity(ctx, identY, "lock_model_test")
			errs <- err
		}()
		loWaitForWaiters(t, "revoke_credentials_cascade", 2)
		require.NoError(t, hold.Commit())

		for i := 0; i < 2; i++ {
			assert.NoError(t, <-errs, "runCascade MUST absorb the deadlock by running the aborted cascade again")
		}
		if len(mrRetries(t, sl)) > before {
			deadlocked++
		}
		for _, jti := range []string{aJTI, bJTI, sJTI, cJTI} {
			assert.True(t, rlRowRevoked(t, jti), "every token of X's and Y's trees MUST be revoked")
		}
		assert.Empty(t, rlLiveBelowRevoked(t, tn))
	}
	t.Logf("%d of %d trials deadlocked and were run again", deadlocked, trials)
	assert.Positive(t, deadlocked, "the interleaving MUST reach the deadlock, or this test checks nothing")
}
