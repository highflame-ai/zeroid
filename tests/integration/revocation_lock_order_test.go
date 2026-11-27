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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
