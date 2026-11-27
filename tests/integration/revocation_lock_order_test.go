package integration_test

// The bulk cascades (every token of an identity, every token of an owner's
// identities) against a delegated issuance below one of those tokens. The
// issuance locks the tokens above its new one FOR SHARE, root first; a bulk
// cascade that does not lock its anchors first can take a token below the
// root before the root, so the two deadlock, and its walk can miss a token
// whose issuance it waited for.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// loBulkCascades are the two bulk cascades, each revoking every token of the
// tenant's identity identityID (register gives every identity the same
// owner).
var loBulkCascades = map[string]func(ctx context.Context, tn hrdTenant, identityID string) ([]postgres.RevokedCredential, error){
	"identity": func(ctx context.Context, _ hrdTenant, identityID string) ([]postgres.RevokedCredential, error) {
		return postgres.NewCredentialRepository(testDB).RevokeAllActiveForIdentity(ctx, identityID, "lock_order_test")
	},
	"owner": func(ctx context.Context, tn hrdTenant, _ string) ([]postgres.RevokedCredential, error) {
		return postgres.NewCredentialRepository(testDB).RevokeAllActiveForOwner(ctx, "user-test-owner", tn.account, "lock_order_test")
	},
}

// loCred stores one credential through the issuance chokepoint's repository
// call and returns its jti. identityID may be "".
func loCred(ctx context.Context, tn hrdTenant, parentJTI, identityID string) (string, error) {
	return loCredIssuedAt(ctx, tn, parentJTI, identityID, time.Time{})
}

// loCredIssuedAt is loCred with the issuance time the issuing replica's clock
// read. The zero time leaves issued_at to the database's default.
func loCredIssuedAt(ctx context.Context, tn hrdTenant, parentJTI, identityID string, issuedAt time.Time) (string, error) {
	jti := uuid.NewString()
	cred := &domain.IssuedCredential{
		ID: uuid.NewString(), AccountID: tn.account, ProjectID: tn.project,
		JTI: jti, Subject: "lock-order", IssuedAt: issuedAt, ExpiresAt: time.Now().Add(time.Hour), TTLSeconds: 3600,
		Scopes: []string{}, GrantType: domain.GrantTypeTokenExchange, ParentJTI: parentJTI,
	}
	if identityID != "" {
		cred.IdentityID = &identityID
	}
	return jti, postgres.NewCredentialRepository(testDB).Create(ctx, cred)
}

// loChain registers an identity and stores root (issued to it) → mid (issued
// to no identity) → fanOut leaves below mid. Returns the identity and mid.
func loChain(t *testing.T, tn hrdTenant, policyID string, fanOut int) (identityID, midJTI string) {
	t.Helper()
	ctx := context.Background()
	wimse := tn.register(t, uid("lock-order"), policyID, "", []string{"data:read"})
	require.NoError(t, testDB.NewRaw(`SELECT id FROM identities WHERE wimse_uri = ?`, wimse).Scan(ctx, &identityID))
	rootJTI, err := loCred(ctx, tn, "", identityID)
	require.NoError(t, err)
	midJTI, err = loCred(ctx, tn, rootJTI, "")
	require.NoError(t, err)
	_, err = testDB.ExecContext(ctx, `
		INSERT INTO issued_credentials (id, account_id, project_id, jti, subject, expires_at, parent_jti, grant_type)
		SELECT gen_random_uuid(), ?, ?, gen_random_uuid()::text, 'lock-order', NOW() + interval '1 hour', ?, 'token_exchange'
		FROM generate_series(1, ?)`, tn.account, tn.project, midJTI, fanOut)
	require.NoError(t, err)
	return identityID, midJTI
}

// TestBulkCascadeRevokesTokenStoredWhileItWaited holds a delegated issuance's
// transaction open after its INSERT, runs a bulk cascade over the chain's
// root, waits until the cascade waits for that transaction, and commits it.
// The cascade must revoke the new token and report it (one revocation event
// per reported jti), not leave it live below the revoked root.
func TestBulkCascadeRevokesTokenStoredWhileItWaited(t *testing.T) {
	for name, cascade := range loBulkCascades {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			tn := newTenant(t, "")
			policyID := tn.policy(t, []string{"data:read"})
			identityID, midJTI := loChain(t, tn, policyID, 0)

			tx, err := testDB.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer tx.Rollback() //nolint:errcheck
			childJTI, err := loCred(postgres.WithTx(ctx, tx), tn, midJTI, "")
			require.NoError(t, err)

			type result struct {
				rows []postgres.RevokedCredential
				err  error
			}
			done := make(chan result, 1)
			go func() {
				rows, err := cascade(ctx, tn, identityID)
				done <- result{rows, err}
			}()
			t.Logf("cascade waits for the issuance: %.200s",
				rlWaitForLockWait(t, "revoke_credentials_", []string{"transactionid", "tuple"}, done))
			require.NoError(t, tx.Commit())

			r := <-done
			require.NoError(t, r.err)
			assert.True(t, rlRowRevoked(t, childJTI),
				"a token stored while the cascade waited for it MUST be revoked with the root")
			assert.True(t, slices.ContainsFunc(r.rows, func(c postgres.RevokedCredential) bool { return c.JTI == childJTI }),
				"and reported, so a revocation event is sent for it")
			assert.Empty(t, rlLiveBelowRevoked(t, tn))
		})
	}
}

// TestBulkCascadeDoesNotDeadlockWithDelegatedIssuance runs a bulk cascade
// over root → mid → 1500 leaves while delegated issuances below mid run in a
// loop. A cascade that takes mid before root deadlocks with an issuance that
// holds root and waits for mid; PostgreSQL then aborts one of them, which
// fails the exchange with a 500 or the revocation.
func TestBulkCascadeDoesNotDeadlockWithDelegatedIssuance(t *testing.T) {
	for name, cascade := range loBulkCascades {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var failures []string
			var live []string
			const trials = 25
			for i := range trials {
				// A tenant per trial, so the owner cascade walks this
				// trial's tree only.
				tn := newTenant(t, "")
				identityID, midJTI := loChain(t, tn, tn.policy(t, []string{"data:read"}), 1500)

				var mu sync.Mutex
				fail := func(what string, err error) {
					mu.Lock()
					failures = append(failures, what+": "+err.Error())
					mu.Unlock()
				}
				stop := make(chan struct{})
				var wg sync.WaitGroup
				for range 2 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for {
							select {
							case <-stop:
								return
							default:
							}
							if _, err := loCred(ctx, tn, midJTI, ""); err != nil {
								if !errors.Is(err, postgres.ErrRevokedLineage) {
									fail("issuance", err)
								}
								return
							}
						}
					}()
				}
				time.Sleep(2 * time.Millisecond)
				if _, err := cascade(ctx, tn, identityID); err != nil {
					fail("cascade", err)
				}
				close(stop)
				wg.Wait()
				live = append(live, rlLiveBelowRevoked(t, tn)...)
				if len(failures) > 0 {
					t.Logf("trial %d: %s", i, strings.Join(failures, "; "))
					break
				}
			}
			assert.Empty(t, failures, "a bulk cascade and a delegated issuance below it MUST NOT deadlock")
			assert.Empty(t, live, "and no token is left live below a revoked one")
		})
	}
}

// TestBulkCascadeLocksParentAnchorFirstUnderClockSkew covers a parent and
// child anchor that the cascade's ordering key cannot tell apart by depth: a
// re-scoping exchange (or a CIBA grant) issues the child to the same identity
// at the same delegation_depth. The child was stored by a replica whose clock
// is a second behind the one that stored the parent, so its issue time is the
// earlier one. An issuance below the child, holding the parent and waiting
// for the child, MUST NOT deadlock with a cascade that took the child first
// and waits for the parent.
//
// The test holds the parent locked so that the issuance queues on it first,
// starts the cascade, waits until it too waits, and then releases the parent.
func TestBulkCascadeLocksParentAnchorFirstUnderClockSkew(t *testing.T) {
	for name, cascade := range loBulkCascades {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			tn := newTenant(t, "")
			wimse := tn.register(t, uid("lock-order-skew"), tn.policy(t, []string{"data:read"}), "", []string{"data:read"})
			var identityID string
			require.NoError(t, testDB.NewRaw(`SELECT id FROM identities WHERE wimse_uri = ?`, wimse).Scan(ctx, &identityID))
			parentJTI, err := loCred(ctx, tn, "", identityID)
			require.NoError(t, err)
			var parentIssuedAt time.Time
			require.NoError(t, testDB.NewRaw(`SELECT issued_at FROM issued_credentials WHERE jti = ?`, parentJTI).
				Scan(ctx, &parentIssuedAt))
			childJTI, err := loCredIssuedAt(ctx, tn, parentJTI, identityID, parentIssuedAt.Add(-time.Second))
			require.NoError(t, err)

			hold, err := testDB.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer hold.Rollback() //nolint:errcheck
			_, err = hold.ExecContext(ctx, `SELECT 1 FROM issued_credentials WHERE jti = ? FOR NO KEY UPDATE`, parentJTI)
			require.NoError(t, err)

			issued := make(chan error, 1)
			go func() {
				_, err := loCred(ctx, tn, childJTI, "")
				issued <- err
			}()
			rlWaitForLockWait(t, "FOR SHARE OF ic", []string{"transactionid", "tuple"}, issued)

			type result struct {
				rows []postgres.RevokedCredential
				err  error
			}
			done := make(chan result, 1)
			go func() {
				rows, err := cascade(ctx, tn, identityID)
				done <- result{rows, err}
			}()
			rlWaitForLockWait(t, "revoke_credentials_", []string{"transactionid", "tuple"}, done)
			require.NoError(t, hold.Commit())

			issueErr := <-issued
			r := <-done
			assert.NoError(t, r.err, "the cascade MUST NOT deadlock with the issuance")
			if issueErr != nil {
				assert.ErrorIs(t, issueErr, postgres.ErrRevokedLineage,
					"the issuance is refused because the cascade won, not aborted")
			}
			assert.True(t, rlRowRevoked(t, childJTI))
			assert.Empty(t, rlLiveBelowRevoked(t, tn), "and no token is left live below a revoked one")
		})
	}
}

// TestOverlappingCascadesDoNotDeadlock revokes, at the same moment, an
// orchestrator's identity and the identity of a sub-agent it delegated to
// (root R of X → M of Y → 3000 leaves), and the same with the sub-agent's
// single token M revoked through RFC 7009's cascade. The second cascade locks
// M before its walk. A first cascade whose walk locks a leaf before it
// reaches M then deadlocks with it, and PostgreSQL aborts one of the two.
//
// Each cascade runs in a transaction of the test's, where it is not retried,
// so the test sees every abort: the walks must lock parents first and never
// deadlock, not merely recover.
func TestOverlappingCascadesDoNotDeadlock(t *testing.T) {
	repo := postgres.NewCredentialRepository(testDB)
	second := map[string]func(ctx context.Context, tn hrdTenant, yID, midID string) error{
		"identity": func(ctx context.Context, _ hrdTenant, yID, _ string) error {
			_, err := repo.RevokeAllActiveForIdentity(ctx, yID, "overlap_test")
			return err
		},
		"single": func(ctx context.Context, tn hrdTenant, _, midID string) error {
			_, err := repo.Revoke(ctx, midID, tn.account, tn.project, "overlap_test")
			return err
		},
	}
	inTx := func(fn func(ctx context.Context) error) error {
		return testDB.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
			return fn(postgres.WithTx(ctx, tx))
		})
	}
	for name, revokeSecond := range second {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			const trials = 20
			var failures []string
			for i := range trials {
				tn := newTenant(t, "")
				policyID := tn.policy(t, []string{"data:read"})
				xID, yID := rlIdentity(t, tn, policyID), rlIdentity(t, tn, policyID)
				_, rootJTI := rlCred(t, tn, "", xID, "overlap")
				// The leaves are stored before M, so a walk that reads the
				// table in storage order, as the identity cascade's UPDATE
				// does on a table this small, reaches them before M. On a
				// large table its plan reads the walked ids out of a hash,
				// which reaches the same order by chance.
				midJTI := uuid.NewString()
				_, err := testDB.ExecContext(ctx, `
					INSERT INTO issued_credentials (id, account_id, project_id, jti, subject, expires_at, parent_jti, delegation_depth, grant_type)
					SELECT gen_random_uuid(), ?, ?, gen_random_uuid()::text, 'overlap', NOW() + interval '1 hour', ?, 2, 'token_exchange'
					FROM generate_series(1, 3000)`, tn.account, tn.project, midJTI)
				require.NoError(t, err)
				midID := rlCredJTI(t, tn, midJTI, rootJTI, yID, "overlap")

				start := make(chan struct{})
				errs := make([]error, 2)
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					errs[0] = inTx(func(ctx context.Context) error {
						_, err := repo.RevokeAllActiveForIdentity(ctx, xID, "overlap_test")
						return err
					})
				}()
				go func() {
					defer wg.Done()
					<-start
					errs[1] = inTx(func(ctx context.Context) error { return revokeSecond(ctx, tn, yID, midID) })
				}()
				close(start)
				wg.Wait()
				for j, err := range errs {
					if err != nil {
						failures = append(failures, fmt.Sprintf("trial %d cascade %d: %v", i, j, err))
					}
				}
				var live int
				require.NoError(t, testDB.NewRaw(`
					SELECT count(*) FROM issued_credentials
					WHERE account_id = ? AND project_id = ? AND NOT is_revoked`, tn.account, tn.project).Scan(ctx, &live))
				if live != 0 {
					failures = append(failures, fmt.Sprintf("trial %d: %d tokens left live", i, live))
				}
				if len(failures) > 0 {
					break
				}
			}
			assert.Empty(t, failures, "two cascades over overlapping trees MUST NOT deadlock")
		})
	}
}

// TestCrossDelegatedCascadesDoNotDeadlock revokes two trees at once whose
// tokens are each inside the other's walk, in two shapes:
//
//   - "mutual": two agents that delegate to each other. X's root R1 → M1 of Y,
//     and Y's root R2 → M2 of X. X's cascade walks R1, M1 and M2; Y's walks
//     R2, M2 and M1.
//   - "returns": a chain that comes back to the agent it started from. R of X
//     → M of Y → K of X, raced against RFC 7009's cascade of M.
//
// A cascade that locks only its own tokens before it walks takes M2 (or K)
// in its first statement, while the other cascade holds M1 (or M) and its
// walk then wants M2 (or K). Each waits for the other, every time.
//
// A transaction holds the shared tokens FOR SHARE, as an issuance below them
// would, until both cascades wait on it, so both start from the same point.
// Each cascade runs in a transaction of the test's, where it is not retried.
func TestCrossDelegatedCascadesDoNotDeadlock(t *testing.T) {
	repo := postgres.NewCredentialRepository(testDB)
	inTx := func(fn func(ctx context.Context) error) error {
		return testDB.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
			return fn(postgres.WithTx(ctx, tx))
		})
	}
	identityCascade := func(identityID string) func(ctx context.Context) error {
		return func(ctx context.Context) error {
			_, err := repo.RevokeAllActiveForIdentity(ctx, identityID, "cross_delegation_test")
			return err
		}
	}
	leaves := func(tn hrdTenant, parentJTI string) {
		_, err := testDB.ExecContext(context.Background(), `
			INSERT INTO issued_credentials (id, account_id, project_id, jti, subject, expires_at, parent_jti, grant_type)
			SELECT gen_random_uuid(), ?, ?, gen_random_uuid()::text, 'cross', NOW() + interval '1 hour', ?, 'token_exchange'
			FROM generate_series(1, 50)`, tn.account, tn.project, parentJTI)
		require.NoError(t, err)
	}
	// Each shape builds its tree and returns the tokens to hold and the two
	// cascades to race.
	shapes := map[string]func(tn hrdTenant, policyID string) (held []string, a, b func(ctx context.Context) error){
		"mutual": func(tn hrdTenant, policyID string) ([]string, func(ctx context.Context) error, func(ctx context.Context) error) {
			xID, yID := rlIdentity(t, tn, policyID), rlIdentity(t, tn, policyID)
			_, r1 := rlCred(t, tn, "", xID, "cross")
			_, r2 := rlCred(t, tn, "", yID, "cross")
			_, m1 := rlCred(t, tn, r1, yID, "cross")
			_, m2 := rlCred(t, tn, r2, xID, "cross")
			leaves(tn, m1)
			leaves(tn, m2)
			return []string{m1, m2}, identityCascade(xID), identityCascade(yID)
		},
		"returns": func(tn hrdTenant, policyID string) ([]string, func(ctx context.Context) error, func(ctx context.Context) error) {
			xID, yID := rlIdentity(t, tn, policyID), rlIdentity(t, tn, policyID)
			_, r := rlCred(t, tn, "", xID, "cross")
			mID, m := rlCred(t, tn, r, yID, "cross")
			_, k := rlCred(t, tn, m, xID, "cross")
			leaves(tn, k)
			return []string{m, k}, identityCascade(xID), func(ctx context.Context) error {
				_, err := repo.Revoke(ctx, mID, tn.account, tn.project, "cross_delegation_test")
				return err
			}
		},
	}
	for name, build := range shapes {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			const trials = 5
			var failures []string
			for i := range trials {
				tn := newTenant(t, "")
				held, a, b := build(tn, tn.policy(t, []string{"data:read"}))

				hold, err := testDB.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer hold.Rollback() //nolint:errcheck
				_, err = hold.ExecContext(ctx, `SELECT 1 FROM issued_credentials WHERE jti IN (?) FOR SHARE`, bun.List(held))
				require.NoError(t, err)

				errs := make([]error, 2)
				var wg sync.WaitGroup
				for j, fn := range []func(ctx context.Context) error{a, b} {
					wg.Add(1)
					go func() {
						defer wg.Done()
						errs[j] = inTx(fn)
					}()
				}
				loWaitForWaiters(t, "revoke_credential", 2)
				require.NoError(t, hold.Commit())
				wg.Wait()

				for j, err := range errs {
					if err != nil {
						failures = append(failures, fmt.Sprintf("trial %d cascade %d: %v", i, j, err))
					}
				}
				var live int
				require.NoError(t, testDB.NewRaw(`
					SELECT count(*) FROM issued_credentials
					WHERE account_id = ? AND project_id = ? AND NOT is_revoked`, tn.account, tn.project).Scan(ctx, &live))
				if live != 0 {
					failures = append(failures, fmt.Sprintf("trial %d: %d tokens left live", i, live))
				}
				if len(failures) > 0 {
					break
				}
			}
			assert.Empty(t, failures, "two cascades whose trees each reach into the other's MUST NOT deadlock")
		})
	}
}

// loWaitForWaiters polls until n backends whose current query contains
// queryLike wait on a lock, and fails the test after 15 seconds.
func loWaitForWaiters(t *testing.T, queryLike string, n int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		require.NoError(t, testDB.NewRaw(`
			SELECT count(DISTINCT l.pid) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
			WHERE NOT l.granted AND a.query LIKE ? AND a.pid <> pg_backend_pid()`,
			"%"+queryLike+"%").Scan(context.Background(), &waiting))
		if waiting >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("fewer than %d queries like %q waited on a lock within 15s", n, queryLike)
}

// TestDelegatedIssuedAtMovedAfterParentKeepsSignedIat runs a real token
// exchange below a token stored by a replica whose clock was five seconds
// ahead of this one. The child's stored issued_at is moved to a microsecond
// after its parent's, so the cascades lock the parent first. The token itself
// does not change: introspection answers the signed iat, not the stored
// value.
func TestDelegatedIssuedAtMovedAfterParentKeepsSignedIat(t *testing.T) {
	ctx := context.Background()
	tn := newTenant(t, "")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)
	root, _ := tn.workloadRoot(t, policyID, scopes)
	rootJTI := rlJTI(t, root)
	_, err := testDB.ExecContext(ctx,
		`UPDATE issued_credentials SET issued_at = issued_at + interval '5 seconds' WHERE jti = ?`, rootJTI)
	require.NoError(t, err)

	status, body := rlExchange(t, rlNewActor(t, tn, policyID, scopes), scopes, root)
	require.Equal(t, http.StatusOK, status, "%v", body)
	child := body["access_token"].(string)
	childJTI := rlJTI(t, child)

	var rows []struct {
		JTI      string    `bun:"jti"`
		IssuedAt time.Time `bun:"issued_at"`
	}
	require.NoError(t, testDB.NewRaw(`SELECT jti, issued_at FROM issued_credentials WHERE jti IN (?, ?)`,
		rootJTI, childJTI).Scan(ctx, &rows))
	require.Len(t, rows, 2)
	stored := map[string]time.Time{}
	for _, r := range rows {
		stored[r.JTI] = r.IssuedAt
	}
	assert.Equal(t, stored[rootJTI].Add(time.Microsecond), stored[childJTI],
		"the child is stored as issued a microsecond after its parent")

	parsed, err := jwt.ParseInsecure([]byte(child))
	require.NoError(t, err)
	signedIat, ok := parsed.IssuedAt()
	require.True(t, ok)
	assert.Less(t, signedIat.Unix(), stored[childJTI].Unix()-3, "the signed iat is this replica's clock")
	assert.Equal(t, float64(signedIat.Unix()), introspect(t, child)["iat"],
		"introspection answers the token's own iat")
}
