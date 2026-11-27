package integration_test

// Helpers for the tests that a token delegated from a revoked token is never
// usable, whether it was issued while the revocation ran or was left behind
// by an older release that let the two interleave. The tests themselves live
// in the compliance file for the spec each one asserts.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

// rlActor is an identity with a registered key, so it can present actor
// tokens on a token exchange.
type rlActor struct {
	key   *ecdsa.PrivateKey
	wimse string
}

func rlNewActor(t *testing.T, tn hrdTenant, policyID string, scopes []string) rlActor {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wimse := tn.register(t, uid("rl-actor"), policyID, ecPublicKeyPEM(t, key), scopes)
	return rlActor{key: key, wimse: wimse}
}

// rlExchange exchanges subject for a token issued to actor and returns the
// HTTP status and body.
func rlExchange(t *testing.T, actor rlActor, scopes []string, subject string) (int, map[string]any) {
	t.Helper()
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": subject,
		"actor_token":   buildAssertion(t, actor.key, actor.wimse),
		"scope":         scopesToString(scopes),
	}, nil)
	return resp.StatusCode, decode(t, resp)
}

// rlRevoke revokes token through RFC 7009.
func rlRevoke(t *testing.T, token string) {
	t.Helper()
	resp := post(t, "/oauth2/token/revoke", map[string]any{"token": token}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
}

func rlJTI(t *testing.T, token string) string {
	t.Helper()
	return decodeJWTUnsafe(t, token)["jti"].(string)
}

// rlRowRevoked reads is_revoked from the stored row, not from introspection:
// introspection also refuses a token below a revoked one, so it cannot tell
// whether the cascade reached the row.
func rlRowRevoked(t *testing.T, jti string) bool {
	t.Helper()
	var revoked bool
	require.NoError(t, testDB.NewRaw(`SELECT is_revoked FROM issued_credentials WHERE jti = ?`, jti).
		Scan(context.Background(), &revoked))
	return revoked
}

// rlRevokeRowOnly marks one stored credential revoked without the cascade,
// which is the state an exchange that interleaved with a revocation used to
// leave behind: the parent revoked, the child issued after the walk and live.
func rlRevokeRowOnly(t *testing.T, jti string) {
	t.Helper()
	_, err := testDB.ExecContext(context.Background(), `
		UPDATE issued_credentials
		SET is_revoked = TRUE, revoked_at = NOW(), revoke_reason = 'test_row_only'
		WHERE jti = ?`, jti)
	require.NoError(t, err)
}

// rlLiveBelowRevokedSQL lists, in one tenant, the unrevoked, unexpired
// credentials that have a revoked credential anywhere above them in the
// parent_jti chain. The store must never hold one.
const rlLiveBelowRevokedSQL = `
WITH RECURSIVE anc(child_jti, ancestor_jti, hops) AS (
	SELECT c.jti, c.parent_jti, 1
	FROM issued_credentials c
	WHERE c.account_id = ? AND c.project_id = ?
	  AND c.is_revoked = FALSE AND c.expires_at > NOW()
	  AND c.parent_jti IS NOT NULL
	UNION ALL
	SELECT anc.child_jti, p.parent_jti, anc.hops + 1
	FROM anc JOIN issued_credentials p ON p.jti = anc.ancestor_jti
	WHERE p.parent_jti IS NOT NULL AND anc.hops < 100
)
SELECT DISTINCT anc.child_jti
FROM anc JOIN issued_credentials p ON p.jti = anc.ancestor_jti
WHERE p.is_revoked = TRUE`

func rlLiveBelowRevoked(t *testing.T, tn hrdTenant) []string {
	t.Helper()
	var jtis []string
	require.NoError(t, testDB.NewRaw(rlLiveBelowRevokedSQL, tn.account, tn.project).Scan(context.Background(), &jtis))
	return jtis
}

// rlWaitForLockWait polls until a backend whose current query contains
// queryLike waits on a lock of one of the given lock types, and returns that
// query. It fails the test if done fires first (the request finished without
// waiting) or nothing waits within 15 seconds.
func rlWaitForLockWait[T any](t *testing.T, queryLike string, lockTypes []string, done <-chan T) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var q []string
		require.NoError(t, testDB.NewRaw(`
			SELECT a.query FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
			WHERE NOT l.granted AND l.locktype IN (?) AND a.query LIKE ?
			  AND a.pid <> pg_backend_pid()`,
			bun.In(lockTypes), "%"+queryLike+"%").Scan(context.Background(), &q))
		if len(q) > 0 {
			return q[0]
		}
		select {
		case r := <-done:
			t.Fatalf("finished without waiting on a %v lock: %v", lockTypes, r)
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("no query like %q waited on a %v lock within 15s", queryLike, lockTypes)
	return ""
}

// rlRevokedParent is a delegation chain root → child → grandchild in a tenant
// of its own, in which only the root's row is revoked: the state the store
// is left in when an exchange interleaves with the root's revocation.
type rlRevokedParent struct {
	tn                      hrdTenant
	policyID                string
	scopes                  []string
	root, child, grandchild string
}

func rlRevokedParentFixture(t *testing.T) rlRevokedParent {
	t.Helper()
	f := rlRevokedParent{tn: newTenant(t, ""), scopes: []string{"data:read"}}
	f.policyID = f.tn.policy(t, f.scopes)
	f.root, _ = f.tn.workloadRoot(t, f.policyID, f.scopes)

	status, body := rlExchange(t, rlNewActor(t, f.tn, f.policyID, f.scopes), f.scopes, f.root)
	require.Equal(t, http.StatusOK, status, "root → child: %v", body)
	f.child = body["access_token"].(string)
	status, body = rlExchange(t, rlNewActor(t, f.tn, f.policyID, f.scopes), f.scopes, f.child)
	require.Equal(t, http.StatusOK, status, "child → grandchild: %v", body)
	f.grandchild = body["access_token"].(string)

	rlRevokeRowOnly(t, rlJTI(t, f.root))
	require.False(t, rlRowRevoked(t, rlJTI(t, f.child)))
	require.False(t, rlRowRevoked(t, rlJTI(t, f.grandchild)))
	return f
}
