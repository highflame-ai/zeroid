package integration_test

// The registration tree's guards on tokens and writes (docs/identity-tree.md):
// a token that speaks for or acts as a stopped identity is neither issued nor
// reported active; a child is held to its parent's own policy and the key it
// presented; a calling identity writes only to its children and never raises
// a status; and the cleanup worker finishes retirements an older release
// wrote, rotating past marks that keep failing.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exchangeTree runs an NHI token exchange of subjectToken by the actor whose
// key is actorKey and returns the status and body.
func exchangeTree(t *testing.T, subjectToken string, actorKey *ecdsa.PrivateKey, actorURI string) (int, map[string]any) {
	t.Helper()
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": subjectToken,
		"actor_token":   buildAssertion(t, actorKey, actorURI),
		"scope":         "data:read",
	}, nil)
	return resp.StatusCode, decode(t, resp)
}

// exchangeActor registers, as an admin, an identity outside any tree that
// may act in a token exchange, and returns it with its key.
func exchangeActor(t *testing.T, tn treeTenant, policyID string) (treeIdentity, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	actor := mustTreeIdentity(t, tn.headers(), map[string]any{
		"credential_policy_id": policyID, "public_key_pem": ecPublicKeyPEM(t, key),
		"allowed_scopes": []string{"data:read", "data:write"},
	})
	return actor, key
}

// TestIdentityTree_StoppedTreeDelegatesNothing: while an identity above it is
// suspended, a token that speaks for a child is not exchanged, whichever
// actor presents it and however many hops it is from the child's own token,
// and introspection reports it inactive. Reactivating the root lifts both.
func TestIdentityTree_StoppedTreeDelegatesNothing(t *testing.T) {
	tn := newTreeTenant()
	pol := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-x"), "allowed_grant_types": []string{"api_key", "client_credentials", "token_exchange"},
		"allowed_scopes": []string{"data:read", "data:write"}, "max_ttl_seconds": 3600, "max_delegation_depth": 5,
	}, tn.headers())
	root, _ := mustTreeAgent(t, tn.headers(), map[string]any{"created_by": "owner-alice", "credential_policy_id": pol, "allowed_scopes": []string{"data:read", "data:write"}})
	_, childKey := mustTreeAgent(t, tn.as(root.ID), map[string]any{})
	childToken := mustAPIKeyToken(t, childKey)
	actorA, keyA := exchangeActor(t, tn, pol)
	actorB, keyB := exchangeActor(t, tn, pol)

	// One hop, before the stop: the actor now holds a token delegated from
	// the child's.
	status, body := exchangeTree(t, childToken, keyA, actorA.WIMSEURI)
	require.Equal(t, http.StatusOK, status, "%v", body)
	hopToken := body["access_token"].(string)

	status, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+root.ID), map[string]any{"status": "suspended"}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)

	status, body = exchangeTree(t, childToken, keyB, actorB.WIMSEURI)
	assert.Equal(t, http.StatusBadRequest, status, "the child's own token, under a suspended root: %v", body)
	assert.NotContains(t, body, "access_token")
	status, body = exchangeTree(t, hopToken, keyB, actorB.WIMSEURI)
	assert.Equal(t, http.StatusBadRequest, status, "a token one hop from the child's: %v", body)
	assert.NotContains(t, body, "access_token")
	assert.Equal(t, false, introspect(t, childToken)["active"], "the child's token is inactive while the tree is stopped")
	assert.Equal(t, false, introspect(t, hopToken)["active"], "so is one delegated from it")

	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+root.ID), map[string]any{"status": "active"}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	assert.Equal(t, true, introspect(t, childToken)["active"], "suspension pauses the tree; it revokes nothing below it")
	status, body = exchangeTree(t, hopToken, keyB, actorB.WIMSEURI)
	assert.Equal(t, http.StatusOK, status, "the tree is running again: %v", body)
}

// TestIdentityTree_ChildHeldToIdentityAndKeyPolicy: a child registered
// through an API key whose policy is wider than its parent identity's own
// (the identity was narrowed after the key was made) inherits the narrower,
// and naming the key's wider policy is refused, as it is without the key.
func TestIdentityTree_ChildHeldToIdentityAndKeyPolicy(t *testing.T) {
	tn := newTreeTenant()
	wide := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-kwide"), "allowed_grant_types": []string{"api_key", "client_credentials", "token_exchange"},
		"allowed_scopes": []string{"data:read", "data:write"}, "max_ttl_seconds": 86400, "max_delegation_depth": 3,
	}, tn.headers())
	narrow := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-knarrow"), "allowed_grant_types": []string{"api_key"},
		"allowed_scopes": []string{"data:read", "data:write"}, "max_ttl_seconds": 300, "max_delegation_depth": 1,
	}, tn.headers())
	parent, _ := mustTreeAgent(t, tn.headers(), map[string]any{"created_by": "owner-alice", "credential_policy_id": wide})
	keyID := apiKeyIDOf(t, parent.ID)
	status, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+parent.ID), map[string]any{"credential_policy_id": narrow}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)

	viaKey := tn.as(parent.ID)
	viaKey[testCallerAPIKeyIDHeader] = keyID
	child := mustTreeIdentity(t, viaKey, map[string]any{})
	assert.Equal(t, narrow, child.CredentialPolicyID, "the child inherits the narrower of the identity's and the key's policies")

	status, raw = postTreeIdentity(t, viaKey, map[string]any{"credential_policy_id": wide})
	assert.Equal(t, http.StatusBadRequest, status, "naming the key's wider policy: %s", raw)
	assert.Contains(t, treeDetail(t, raw), "exceeds the parent identity's credential policy")
	status, raw = postTreeIdentity(t, tn.as(parent.ID), map[string]any{"credential_policy_id": wide})
	assert.Equal(t, http.StatusBadRequest, status, "naming it without the key: %s", raw)

	// The same bound holds on a change made through the key.
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+child.ID), map[string]any{"credential_policy_id": wide}, viaKey)
	assert.Equal(t, http.StatusBadRequest, status, "moving the child onto the key's wider policy: %s", raw)
	assert.Equal(t, narrow, getTreeIdentity(t, tn, child.ID).CredentialPolicyID)
}

// TestIdentityTree_CallerWritesOnlyLowerItsChildren: a request authenticated
// as an identity changes only the identities it registered, may lower their
// status but never raise it (so it cannot undo an admin's stop), never
// changes an identity_type, and never writes to itself, even while
// suspended.
func TestIdentityTree_CallerWritesOnlyLowerItsChildren(t *testing.T) {
	tn := newTreeTenant()
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": "owner-alice"})
	child := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{})
	grandchild := mustTreeIdentity(t, tn.as(child.ID), map[string]any{})
	other := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": "owner-alice"})
	patch := func(headers map[string]string, id string, body map[string]any) (int, []byte) {
		t.Helper()
		return treeRequest(t, http.MethodPatch, adminPath("/identities/"+id), body, headers)
	}
	byParent := tn.as(parent.ID)

	for _, st := range []string{"suspended", "deactivated"} {
		status, raw := patch(tn.headers(), child.ID, map[string]any{"status": st})
		require.Equal(t, http.StatusOK, status, "%s", raw)
		status, raw = patch(byParent, child.ID, map[string]any{"status": "active"})
		assert.Equal(t, http.StatusForbidden, status, "the parent reactivating a child an admin %s: %s", st, raw)
		assert.Equal(t, http.StatusForbidden, func() int {
			s, _ := treeRequest(t, http.MethodPost, adminPath("/agents/registry/"+child.ID+"/activate"), nil, byParent)
			return s
		}(), "nor through the agent registry")
		assert.Equal(t, st, getTreeIdentity(t, tn, child.ID).Status)
		if st == "suspended" {
			status, raw = patch(tn.headers(), child.ID, map[string]any{"status": "active"})
			require.Equal(t, http.StatusOK, status, "an admin reactivates it: %s", raw)
		}
	}

	second := mustTreeIdentity(t, byParent, map[string]any{})
	status, raw := patch(byParent, second.ID, map[string]any{"identity_type": "service"})
	assert.Equal(t, http.StatusForbidden, status, "changing a child's identity_type: %s", raw)
	status, raw = patch(byParent, second.ID, map[string]any{"name": "renamed"})
	assert.Equal(t, http.StatusOK, status, "renaming its own child: %s", raw)
	status, raw = patch(byParent, second.ID, map[string]any{"status": "suspended"})
	assert.Equal(t, http.StatusOK, status, "suspending its own child: %s", raw)

	for name, id := range map[string]string{"itself": parent.ID, "a grandchild": grandchild.ID, "an identity an admin registered": other.ID} {
		status, raw = patch(byParent, id, map[string]any{"name": "renamed"})
		assert.Equal(t, http.StatusForbidden, status, "renaming %s: %s", name, raw)
		status, raw = treeRequest(t, http.MethodDelete, adminPath("/identities/"+id), nil, byParent)
		assert.Equal(t, http.StatusForbidden, status, "deleting %s: %s", name, raw)
		status, raw = treeRequest(t, http.MethodPost, adminPath("/agents/registry/"+id+"/rotate-key"), nil, byParent)
		assert.Equal(t, http.StatusForbidden, status, "rotating the key of %s: %s", name, raw)
	}
	assert.Equal(t, "active", getTreeIdentity(t, tn, other.ID).Status)

	// A suspended caller cannot set itself active.
	status, raw = patch(tn.headers(), parent.ID, map[string]any{"status": "suspended"})
	require.Equal(t, http.StatusOK, status, "%s", raw)
	status, raw = patch(byParent, parent.ID, map[string]any{"status": "active"})
	assert.Equal(t, http.StatusForbidden, status, "a suspended caller reactivating itself: %s", raw)
	assert.Equal(t, "suspended", getTreeIdentity(t, tn, parent.ID).Status)

	status, raw = treeRequest(t, http.MethodPost, adminPath("/identities/offboard-by-owner"), map[string]any{"owner_user_id": "owner-alice"}, tn.as(other.ID))
	assert.Equal(t, http.StatusForbidden, status, "an identity offboarding an owner: %s", raw)
	status, raw = treeRequest(t, http.MethodPost, adminPath("/identities/discovered/release-source"), map[string]any{"origin": "okta", "source_id": uid("src")}, tn.as(other.ID))
	assert.Equal(t, http.StatusForbidden, status, "an identity maintaining discovery sources: %s", raw)
}

// TestIdentityTree_CallerOnlyBringsExpiryForward: a calling identity can
// bring a child's stored expiry forward, but cannot move it later or clear it.
// So it cannot revive a child whose expiry has passed before the sweep ran, or
// push back an expiry the deployer brought forward. An admin still can.
func TestIdentityTree_CallerOnlyBringsExpiryForward(t *testing.T) {
	tn := newTreeTenant()
	parent, _ := mustTreeAgent(t, tn.headers(), map[string]any{"created_by": "owner-alice"})
	byParent := tn.as(parent.ID)
	patch := func(headers map[string]string, id string, expiresAt string) (int, []byte) {
		t.Helper()
		return treeRequest(t, http.MethodPatch, adminPath("/identities/"+id), map[string]any{"expires_at": expiresAt}, headers)
	}
	in := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }

	// The child's expiry has passed and the sweep has not run.
	child, childKey := mustTreeAgent(t, byParent, map[string]any{})
	_, err := testDB.ExecContext(t.Context(), "UPDATE identities SET expires_at = now() - interval '1 minute' WHERE id = ?", child.ID)
	require.NoError(t, err)
	code, _ := apiKeyToken(t, childKey, "")
	require.NotEqual(t, http.StatusOK, code, "an expired child is refused an api_key grant")
	status, raw := patch(byParent, child.ID, in(24*time.Hour))
	assert.Equal(t, http.StatusForbidden, status, "the parent reviving an expired child: %s", raw)
	code, _ = apiKeyToken(t, childKey, "")
	assert.NotEqual(t, http.StatusOK, code, "the child stays refused")

	// A stored future expiry cannot be pushed back or cleared, only brought forward.
	second, _ := mustTreeAgent(t, byParent, map[string]any{})
	status, raw = patch(tn.headers(), second.ID, in(2*time.Hour))
	require.Equal(t, http.StatusOK, status, "an admin sets the expiry: %s", raw)
	status, raw = patch(byParent, second.ID, in(48*time.Hour))
	assert.Equal(t, http.StatusForbidden, status, "pushing a future expiry back: %s", raw)
	status, raw = patch(byParent, second.ID, "")
	assert.Equal(t, http.StatusForbidden, status, "clearing a stored expiry: %s", raw)
	status, raw = patch(byParent, second.ID, in(time.Hour))
	assert.Equal(t, http.StatusOK, status, "bringing the expiry forward: %s", raw)

	// With none stored, any date within the bound is allowed.
	third, _ := mustTreeAgent(t, byParent, map[string]any{})
	status, raw = patch(byParent, third.ID, in(72*time.Hour))
	assert.Equal(t, http.StatusOK, status, "setting an expiry where none is stored: %s", raw)

	// The deployer's own write is not held to this.
	status, raw = patch(tn.headers(), second.ID, in(96*time.Hour))
	assert.Equal(t, http.StatusOK, status, "an unmarked write moving the expiry later: %s", raw)
}

// TestIdentityTree_ReactivationHeldToChildLimit: bringing a deactivated
// child back is refused when its parent already has max_children children
// that are not deactivated.
func TestIdentityTree_ReactivationHeldToChildLimit(t *testing.T) {
	tn := newTreeTenant()
	wide := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": "owner-limits"})
	first := mustTreeIdentity(t, tn.as(wide.ID), map[string]any{})
	bulkTreeChildren(t, tn, wide.ID, "owner-limits", 999)
	status, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+first.ID), map[string]any{"status": "deactivated"}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	mustTreeIdentity(t, tn.as(wide.ID), map[string]any{})

	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+first.ID), map[string]any{"status": "active"}, tn.headers())
	assert.Equal(t, http.StatusConflict, status, "reactivating the 1001st child: %s", raw)
	assert.Contains(t, treeDetail(t, raw), "as many children as allowed")
	assert.Equal(t, "deactivated", getTreeIdentity(t, tn, first.ID).Status)
	n, err := testDB.NewSelect().TableExpr("identities").Where("parent_identity_id = ?", wide.ID).
		Where("status <> 'deactivated'").Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1000, n)
}

// TestIdentityTree_WorkerFinishesUnmarkedRetirement: a retirement written
// by a release that predates the tree (status deactivated, no mark, children
// untouched) is found and walked by the cleanup worker.
func TestIdentityTree_WorkerFinishesUnmarkedRetirement(t *testing.T) {
	for _, status := range []string{"deactivated", "expired"} {
		t.Run(status, func(t *testing.T) {
			tn := newTreeTenant()
			owner := uid("owner-old")
			root := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": owner})
			mid := mustTreeIdentity(t, tn.as(root.ID), map[string]any{})
			bulkTreeChildren(t, tn, mid.ID, owner, 5)
			setInDB(t, "identities", mid.ID, "status = ?", status)
			require.Equal(t, 6, activeTreeCount(t, tn))

			testZeroIDServer.RunCleanupOnce(context.Background())
			assert.Equal(t, 1, activeTreeCount(t, tn), "only the root stays active")
			assert.False(t, cascadePending(t, mid.ID))
		})
	}
}

// TestIdentityTree_FailingResumeRotates: a pending cascade whose resume fails
// moves to the back of the queue, so it cannot keep newer marks out of the
// worker's oldest-first batch, and stays marked for the next pass.
func TestIdentityTree_FailingResumeRotates(t *testing.T) {
	ctx := context.Background()
	tn := newTreeTenant()
	owner := uid("owner-rot")
	stuck := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": owner})
	poisoned := treeChildRow(tn, stuck.ID)
	poisoned.OwnerUserID = owner
	_, err := testDB.NewInsert().Model(poisoned).Exec(ctx)
	require.NoError(t, err)

	// Any write that deactivates the poisoned child fails, so the walk below
	// stuck fails on every attempt.
	fn, trig := uid("tree_poison_fn"), uid("tree_poison_trg")
	_, err = testDB.ExecContext(ctx, fmt.Sprintf(`CREATE FUNCTION %q() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF NEW.id = '%s' AND NEW.status = 'deactivated' THEN
		RAISE EXCEPTION 'poisoned';
	END IF;
	RETURN NEW;
END $$`, fn, poisoned.ID))
	require.NoError(t, err)
	_, err = testDB.ExecContext(ctx, fmt.Sprintf(`CREATE TRIGGER %q BEFORE UPDATE ON identities FOR EACH ROW EXECUTE FUNCTION %q()`, trig, fn))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %q ON identities`, trig))
		_, _ = testDB.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %q()`, fn))
	})

	old := time.Now().Add(-48 * time.Hour)
	setInDB(t, "identities", stuck.ID, "status = 'deactivated', cascade_pending_at = ?", old)

	testZeroIDServer.RunCleanupOnce(ctx)
	var mark time.Time
	require.NoError(t, testDB.NewSelect().TableExpr("identities").Column("cascade_pending_at").
		Where("id = ?", stuck.ID).Scan(ctx, &mark))
	assert.True(t, mark.After(time.Now().Add(-time.Hour)), "the failed resume moved its mark to now (got %s)", mark)
	assert.Equal(t, "active", getTreeIdentity(t, tn, poisoned.ID).Status)
}

// TestIdentityTree_CascadeMarkIndexed: the worker's list of pending
// cascades reads a partial index on the mark.
func TestIdentityTree_CascadeMarkIndexed(t *testing.T) {
	var def string
	require.NoError(t, testDB.NewSelect().TableExpr("pg_indexes").Column("indexdef").
		Where("indexname = 'idx_identities_cascade_pending'").Scan(context.Background(), &def))
	assert.Contains(t, def, "WHERE (cascade_pending_at IS NOT NULL)")
}
