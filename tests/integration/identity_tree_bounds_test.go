package integration_test

// The registration tree's bounds (docs/identity-tree.md): a child is held to
// its parent's full credential policy, to the token and API key its parent
// presented, and to every ancestor's lifetime; a stopped tree issues no
// token; and the deactivation walk survives being cut short.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// treeExpiry is the part of an identity these tests read for its lifetime.
type treeExpiry struct {
	ExpiresAt *time.Time `json:"expires_at"`
}

func treeExpiresAt(t *testing.T, tn treeTenant, id string) *time.Time {
	t.Helper()
	status, raw := treeRequest(t, http.MethodGet, adminPath("/identities/"+id), nil, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	var out treeExpiry
	require.NoError(t, json.Unmarshal(raw, &out))
	return out.ExpiresAt
}

// apiKeyIDOf returns the id of the identity's active API key.
func apiKeyIDOf(t *testing.T, identityID string) string {
	t.Helper()
	var id string
	require.NoError(t, testDB.NewSelect().TableExpr("service_keys").Column("id").
		Where("identity_id = ?", identityID).Where("state = 'active'").Limit(1).Scan(context.Background(), &id))
	return id
}

func setInDB(t *testing.T, table, id, set string, args ...any) {
	t.Helper()
	_, err := testDB.NewUpdate().TableExpr(table).Set(set, args...).Where("id = ?", id).Exec(context.Background())
	require.NoError(t, err)
}

// TestIdentityTree_NamedPolicyFullSubset: a child may not name a credential
// policy with its parent's scopes but wider grant types, lifetime or
// delegation depth, on registration or on update, and nothing registers
// under a parent whose own policy is inactive or expired.
func TestIdentityTree_NamedPolicyFullSubset(t *testing.T) {
	tn := newTreeTenant()
	parentPolicy := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-pp"), "allowed_grant_types": []string{"api_key"}, "allowed_scopes": []string{"data:read"},
		"max_ttl_seconds": 300,
	}, tn.headers())
	wider := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-wide-axes"), "allowed_grant_types": []string{"api_key", "client_credentials", "token_exchange"},
		"allowed_scopes": []string{"data:read"}, "max_ttl_seconds": 86400, "max_delegation_depth": 3,
	}, tn.headers())
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"credential_policy_id": parentPolicy})

	status, raw := postTreeIdentity(t, tn.as(parent.ID), map[string]any{"credential_policy_id": wider})
	assert.Equal(t, http.StatusBadRequest, status, "same scopes, wider axes: %s", raw)
	assert.Contains(t, treeDetail(t, raw), "exceeds the parent identity's credential policy")

	child := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{})
	require.Equal(t, parentPolicy, child.CredentialPolicyID)
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+child.ID), map[string]any{"credential_policy_id": wider}, tn.headers())
	assert.Equal(t, http.StatusBadRequest, status, "an update is held to the full policy too: %s", raw)
	assert.Equal(t, parentPolicy, getTreeIdentity(t, tn, child.ID).CredentialPolicyID)

	setInDB(t, "credential_policies", parentPolicy, "is_active = false")
	status, raw = postTreeIdentity(t, tn.as(parent.ID), map[string]any{})
	assert.Equal(t, http.StatusForbidden, status, "a parent on an inactive policy: %s", raw)
	setInDB(t, "credential_policies", parentPolicy, "is_active = true, expires_at = ?", time.Now().Add(-time.Minute))
	status, raw = postTreeIdentity(t, tn.as(parent.ID), map[string]any{})
	assert.Equal(t, http.StatusForbidden, status, "a parent on an expired policy: %s", raw)
}

// TestIdentityTree_BoundByPresentedCredential: a child is held to the scopes
// of the token its parent presented (none when it holds none), to the
// expiry of the API key that token came from, and to every ancestor's expiry,
// and no reserved scope passes to it.
func TestIdentityTree_BoundByPresentedCredential(t *testing.T) {
	tn := newTreeTenant()
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"allowed_scopes": []string{"data:read", "data:write"}})

	narrow := tn.asWith(parent.ID, "data:read")
	status, raw := postTreeIdentity(t, narrow, map[string]any{"allowed_scopes": []string{"data:write"}})
	assert.Equal(t, http.StatusBadRequest, status, "a scope the token does not hold: %s", raw)
	assert.Contains(t, treeDetail(t, raw), "data:write")
	assert.Equal(t, []string{"data:read"}, mustTreeIdentity(t, narrow, map[string]any{}).AllowedScopes,
		"a child naming none takes what the parent and its token both hold")
	status, raw = postTreeIdentity(t, tn.asWith(parent.ID), map[string]any{})
	assert.Equal(t, http.StatusBadRequest, status, "a token with no scopes lets the child hold none: %s", raw)

	reserved := tn.asWith(parent.ID, "data:read", testReservedPrefix+"admin")
	open := mustTreeIdentity(t, tn.headers(), map[string]any{})
	reservedOpen := tn.asWith(open.ID, "data:read", testReservedPrefix+"admin")
	assert.Equal(t, []string{"data:read"}, mustTreeIdentity(t, reservedOpen, map[string]any{}).AllowedScopes,
		"a reserved scope on the token does not pass down")
	status, raw = postTreeIdentity(t, reserved, map[string]any{"allowed_scopes": []string{testReservedPrefix + "admin"}})
	assert.Equal(t, http.StatusBadRequest, status, "naming a reserved scope: %s", raw)

	// The presented API key: the child cannot outlive it, and a key that is
	// not the caller's own is refused.
	agent, _ := mustTreeAgent(t, tn.headers(), map[string]any{"created_by": "owner-alice"})
	keyID := apiKeyIDOf(t, agent.ID)
	keyExpiry := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	setInDB(t, "service_keys", keyID, "expires_at = ?", keyExpiry)
	viaKey := tn.as(agent.ID)
	viaKey[testCallerAPIKeyIDHeader] = keyID
	child := mustTreeIdentity(t, viaKey, map[string]any{})
	got := treeExpiresAt(t, tn, child.ID)
	require.NotNil(t, got, "a child naming no expiry takes the key's")
	assert.WithinDuration(t, keyExpiry, *got, time.Second)
	status, raw = postTreeIdentity(t, viaKey, map[string]any{"expires_at": keyExpiry.Add(time.Hour).Format(time.RFC3339)})
	assert.Equal(t, http.StatusBadRequest, status, "outliving the key: %s", raw)
	other, _ := mustTreeAgent(t, tn.headers(), map[string]any{"created_by": "owner-alice"})
	notMine := tn.as(agent.ID)
	notMine[testCallerAPIKeyIDHeader] = apiKeyIDOf(t, other.ID)
	status, raw = postTreeIdentity(t, notMine, map[string]any{})
	assert.Equal(t, http.StatusForbidden, status, "another identity's key: %s", raw)

	// Every ancestor's expiry: a grandchild cannot outlive the grandparent.
	rootExpiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	root := mustTreeIdentity(t, tn.headers(), map[string]any{"expires_at": rootExpiry.Format(time.RFC3339)})
	mid := mustTreeIdentity(t, tn.as(root.ID), map[string]any{})
	status, raw = postTreeIdentity(t, tn.as(mid.ID), map[string]any{"expires_at": rootExpiry.Add(time.Hour).Format(time.RFC3339)})
	assert.Equal(t, http.StatusBadRequest, status, "outliving the grandparent: %s", raw)
	leaf := mustTreeIdentity(t, tn.as(mid.ID), map[string]any{})
	assert.WithinDuration(t, rootExpiry, *treeExpiresAt(t, tn, leaf.ID), time.Second)
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+leaf.ID), map[string]any{"expires_at": ""}, tn.headers())
	assert.Equal(t, http.StatusBadRequest, status, "clearing a capped expiry: %s", raw)
}

// TestIdentityTree_ActivationNeedsActiveAncestors: a child cannot be
// reactivated while an identity above it is not active, and IsRegisteredBy
// answers false for a parent that is not active.
func TestIdentityTree_ActivationNeedsActiveAncestors(t *testing.T) {
	tn := newTreeTenant()
	chain, _ := treeChain(t, tn)
	ctx := context.Background()

	status, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+chain[2].ID), map[string]any{"status": "suspended"}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+chain[1].ID), map[string]any{"status": "suspended"}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+chain[2].ID), map[string]any{"status": "active"}, tn.headers())
	assert.Equal(t, http.StatusConflict, status, "reactivating below a suspended parent: %s", raw)
	assert.Equal(t, "suspended", getTreeIdentity(t, tn, chain[2].ID).Status)

	ok, err := testZeroIDServer.IsRegisteredBy(ctx, chain[2].ID, zeroid.CallerIdentity{IdentityID: chain[1].ID}, tn.account, tn.project)
	require.NoError(t, err)
	assert.False(t, ok, "a suspended parent")
	ok, err = testZeroIDServer.IsRegisteredBy(ctx, chain[1].ID, zeroid.CallerIdentity{IdentityID: chain[0].ID}, tn.account, tn.project)
	require.NoError(t, err)
	assert.True(t, ok, "an active parent")
	stampExpiredInDB(t, chain[0].ID)
	ok, err = testZeroIDServer.IsRegisteredBy(ctx, chain[1].ID, zeroid.CallerIdentity{IdentityID: chain[0].ID}, tn.account, tn.project)
	require.NoError(t, err)
	assert.False(t, ok, "an expired parent")

	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+chain[1].ID), map[string]any{"status": "active"}, tn.headers())
	assert.Equal(t, http.StatusConflict, status, "reactivating below an expired parent: %s", raw)
}

// TestIdentityTree_StoppedTreeIssuesNothing: while any identity above it is
// suspended, deactivated or expired, an identity receives no token, even when
// its own row is still active (the walk has not reached it).
func TestIdentityTree_StoppedTreeIssuesNothing(t *testing.T) {
	stop := map[string]func(t *testing.T, tn treeTenant, id string){
		"suspended": func(t *testing.T, tn treeTenant, id string) {
			status, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+id), map[string]any{"status": "suspended"}, tn.headers())
			require.Equal(t, http.StatusOK, status, "%s", raw)
		},
		"deactivated, walk not run": func(t *testing.T, _ treeTenant, id string) {
			setInDB(t, "identities", id, "status = 'deactivated'")
		},
		"expired, not swept": func(t *testing.T, _ treeTenant, id string) {
			stampExpiredInDB(t, id)
		},
	}
	for name, fn := range stop {
		t.Run(name, func(t *testing.T) {
			tn := newTreeTenant()
			chain, keys := treeChain(t, tn)
			mustAPIKeyToken(t, keys[3])
			fn(t, tn, chain[1].ID)
			for i := 2; i < len(chain); i++ {
				require.Equal(t, "active", getTreeIdentity(t, tn, chain[i].ID).Status)
				code, body := apiKeyToken(t, keys[i], "")
				assert.Equal(t, http.StatusBadRequest, code, "level %d below a %s identity: %v", i, name, body)
			}
			mustAPIKeyToken(t, keys[0])
		})
	}
}

// TestIdentityTree_ChildOwnerOnlyByTrustedPath: a child's owner changes only
// in a context marked WithTrustedOwnerWrite, and never from a request
// authenticated as an identity.
func TestIdentityTree_ChildOwnerOnlyByTrustedPath(t *testing.T) {
	tn := newTreeTenant()
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": "owner-alice"})
	child := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{})
	patch := func(headers map[string]string, id, owner string) int {
		t.Helper()
		status, _ := treeRequest(t, http.MethodPatch, adminPath("/identities/"+id), map[string]any{"owner_user_id": owner}, headers)
		return status
	}

	assert.Equal(t, http.StatusForbidden, patch(tn.headers(), child.ID, "owner-mallory"), "an untrusted admin write")
	byParent := tn.as(parent.ID)
	byParent[testTrustedOwnerWriteHeader] = "1"
	assert.Equal(t, http.StatusForbidden, patch(byParent, child.ID, "owner-mallory"), "an identity, even marked trusted")
	assert.Equal(t, http.StatusForbidden, patch(tn.as(parent.ID), parent.ID, "owner-mallory"), "an identity changing its own owner")
	assert.Equal(t, "owner-alice", getTreeIdentity(t, tn, child.ID).OwnerUserID)

	trusted := tn.headers()
	trusted[testTrustedOwnerWriteHeader] = "1"
	assert.Equal(t, http.StatusOK, patch(trusted, child.ID, "owner-bob"), "the trusted path")
	assert.Equal(t, "owner-bob", getTreeIdentity(t, tn, child.ID).OwnerUserID)
	assert.Equal(t, http.StatusOK, patch(tn.headers(), child.ID, "owner-bob"), "naming the current owner is no change")
}

// TestIdentityTree_AttestationCappedAtParent: a verified attestation cannot
// lift a child above its parent's trust level, whatever level the submitter
// claimed.
func TestIdentityTree_AttestationCappedAtParent(t *testing.T) {
	testZeroIDServer.SetAttestationPermissive(true)
	t.Cleanup(func() { testZeroIDServer.SetAttestationPermissive(false) })
	tn := newTreeTenant()
	pol := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-attest"), "max_ttl_seconds": 3600, "allowed_grant_types": []string{"client_credentials", "api_key"},
	}, tn.headers())
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"trust_level": "verified_third_party", "credential_policy_id": pol})
	child := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{})
	require.Equal(t, "unverified", child.TrustLevel)

	bogusToken := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FueXRoaW5nIn0.AAAAAAAA"
	subResp := doRequest(t, http.MethodPost, adminPath("/attestation/submit"), map[string]any{
		"identity_id": child.ID, "level": "hardware", "proof_type": "oidc_token", "proof_value": bogusToken,
	}, tn.headers())
	require.Equal(t, http.StatusCreated, subResp.StatusCode)
	attID := decode(t, subResp)["id"].(string)
	resp := doRequest(t, http.MethodPost, adminPath("/attestation/verify"), map[string]any{"attestation_id": attID}, tn.headers())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
	assert.Equal(t, "verified_third_party", getTreeIdentity(t, tn, child.ID).TrustLevel, "raised only to the parent's level")
}

// TestIdentityTree_UpdateCannotRestoreStatus: a whole-row update that read the
// identity before a deactivation committed is refused rather than writing
// the old status back.
func TestIdentityTree_UpdateCannotRestoreStatus(t *testing.T) {
	ctx := context.Background()
	tn := newTreeTenant()
	id := mustTreeIdentity(t, tn.headers(), map[string]any{})
	repo := postgres.NewIdentityRepository(testDB)
	stale, err := repo.GetByID(ctx, id.ID, tn.account, tn.project)
	require.NoError(t, err)

	setInDB(t, "identities", id.ID, "status = 'deactivated'")
	stale.Name = "renamed"
	err = repo.Update(ctx, stale, postgres.IdentityUpdate{PriorStatus: stale.Status})
	require.ErrorIs(t, err, postgres.ErrIdentityChanged)
	assert.Equal(t, "deactivated", getTreeIdentity(t, tn, id.ID).Status)
}

// TestIdentityTree_Limits: registration refuses a child deeper than the
// depth limit or beyond the children limit, with 409.
func TestIdentityTree_Limits(t *testing.T) {
	tn := newTreeTenant()
	root := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": "owner-limits"})

	last := root
	for depth := 1; depth <= 8; depth++ {
		last = mustTreeIdentity(t, tn.as(last.ID), map[string]any{})
	}
	status, raw := postTreeIdentity(t, tn.as(last.ID), map[string]any{})
	assert.Equal(t, http.StatusConflict, status, "depth 9: %s", raw)
	assert.Contains(t, treeDetail(t, raw), "deeper than allowed")

	wide := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": "owner-limits"})
	bulkTreeChildren(t, tn, wide.ID, "owner-limits", 1000)
	status, raw = postTreeIdentity(t, tn.as(wide.ID), map[string]any{})
	assert.Equal(t, http.StatusConflict, status, "child 1001: %s", raw)
	assert.Contains(t, treeDetail(t, raw), "as many children as allowed")
	// Deactivated children do not count.
	_, err := testDB.NewUpdate().TableExpr("identities").Set("status = 'deactivated'").
		Where("id = (SELECT id FROM identities WHERE parent_identity_id = ? LIMIT 1)", wide.ID).
		Exec(context.Background())
	require.NoError(t, err)
	mustTreeIdentity(t, tn.as(wide.ID), map[string]any{})
}

// bulkTreeChildren inserts n active children of parentID directly.
func bulkTreeChildren(t *testing.T, tn treeTenant, parentID, owner string, n int) {
	t.Helper()
	rows := make([]*domain.Identity, 0, n)
	for range n {
		r := treeChildRow(tn, parentID)
		r.OwnerUserID = owner
		rows = append(rows, r)
	}
	_, err := testDB.NewInsert().Model(&rows).Exec(context.Background())
	require.NoError(t, err)
}

func activeTreeCount(t *testing.T, tn treeTenant) int {
	t.Helper()
	n, err := testDB.NewSelect().TableExpr("identities").
		Where("account_id = ?", tn.account).Where("project_id = ?", tn.project).
		Where("status = 'active'").Count(context.Background())
	require.NoError(t, err)
	return n
}

func cascadePending(t *testing.T, id string) bool {
	t.Helper()
	var marked bool
	require.NoError(t, testDB.NewSelect().TableExpr("identities").ColumnExpr("cascade_pending_at IS NOT NULL").
		Where("id = ?", id).Scan(context.Background(), &marked))
	return marked
}

// TestIdentityTree_CascadeResumes: a deactivation whose walk was cut short
// stays marked, and the cleanup worker, a repeated DELETE, and a repeated
// offboarding each finish it; reactivation waits for it.
func TestIdentityTree_CascadeResumes(t *testing.T) {
	// interrupted retires root as a crash after the retiring UPDATE would
	// leave it: deactivated and marked, children untouched.
	interrupted := func(t *testing.T, owner string) (treeTenant, treeIdentity) {
		tn := newTreeTenant()
		root := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": owner})
		bulkTreeChildren(t, tn, root.ID, owner, 50)
		setInDB(t, "identities", root.ID, "status = 'deactivated', cascade_pending_at = now()")
		require.Equal(t, 50, activeTreeCount(t, tn))
		return tn, root
	}

	t.Run("cleanup worker", func(t *testing.T) {
		tn, root := interrupted(t, uid("owner-sweep"))
		testZeroIDServer.RunCleanupOnce(context.Background())
		assert.Zero(t, activeTreeCount(t, tn))
		assert.False(t, cascadePending(t, root.ID), "the mark is cleared once the walk finishes")
	})
	t.Run("repeated delete", func(t *testing.T) {
		tn, root := interrupted(t, uid("owner-del"))
		status, raw := treeRequest(t, http.MethodPost, adminPath("/agents/registry/"+root.ID+"/activate"), nil, tn.headers())
		assert.Equal(t, http.StatusConflict, status, "reactivation waits for the walk: %s", raw)
		status, raw = treeRequest(t, http.MethodDelete, adminPath("/identities/"+root.ID), nil, tn.headers())
		require.Equal(t, http.StatusOK, status, "%s", raw)
		assert.Zero(t, activeTreeCount(t, tn))
		assert.False(t, cascadePending(t, root.ID))
	})
	t.Run("repeated offboarding", func(t *testing.T) {
		owner := uid("owner-off")
		tn, root := interrupted(t, owner)
		status, raw := treeRequest(t, http.MethodPost, adminPath("/identities/offboard-by-owner"), map[string]any{"owner_user_id": owner}, tn.headers())
		require.Equal(t, http.StatusOK, status, "%s", raw)
		assert.Zero(t, activeTreeCount(t, tn))
		assert.False(t, cascadePending(t, root.ID))
	})
	t.Run("canceled sweep", func(t *testing.T) {
		tn := newTreeTenant()
		owner := uid("owner-cancel")
		root := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": owner})
		bulkTreeChildren(t, tn, root.ID, owner, 20)
		stampExpiredInDB(t, root.ID)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		testZeroIDServer.RunCleanupOnce(ctx)
		testZeroIDServer.RunCleanupOnce(context.Background())
		assert.Zero(t, activeTreeCount(t, tn), "the next pass finishes what a canceled one left")
		assert.False(t, cascadePending(t, root.ID))
	})
}

// TestIdentityTree_PatchResendingUnchanged: re-sending a child's unchanged
// allowed_scopes or credential_policy_id after its parent was narrowed is
// not an escalation and is accepted; widening still is refused.
func TestIdentityTree_PatchResendingUnchanged(t *testing.T) {
	tn := newTreeTenant()
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"allowed_scopes": []string{"data:read", "data:write"}})
	child := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{})
	status, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+parent.ID), map[string]any{"allowed_scopes": []string{"data:read"}}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)

	for _, body := range []map[string]any{
		{"name": "renamed", "allowed_scopes": []string{"data:read", "data:write"}},
		{"name": "renamed", "credential_policy_id": child.CredentialPolicyID},
		{"allowed_scopes": []string{"data:write"}},
	} {
		status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+child.ID), body, tn.headers())
		assert.Equal(t, http.StatusOK, status, "%v: %s", body, raw)
	}
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+child.ID), map[string]any{"allowed_scopes": []string{"data:read", "data:write"}}, tn.headers())
	assert.Equal(t, http.StatusBadRequest, status, "widening again past the narrowed parent: %s", raw)
}

// TestIdentityTree_OffboardChainOnce: offboarding the owner of a deep chain,
// whose every identity the owner holds, walks it once rather than once per
// identity.
func TestIdentityTree_OffboardChainOnce(t *testing.T) {
	tn := newTreeTenant()
	owner := uid("owner-chain")
	root := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": owner})
	parent := root.ID
	rows := make([]*domain.Identity, 0, 200)
	for range 200 {
		r := treeChildRow(tn, parent)
		r.OwnerUserID = owner
		rows = append(rows, r)
		parent = r.ID
	}
	_, err := testDB.NewInsert().Model(&rows).Exec(context.Background())
	require.NoError(t, err)

	start := time.Now()
	status, raw := treeRequest(t, http.MethodPost, adminPath("/identities/offboard-by-owner"), map[string]any{"owner_user_id": owner}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	assert.Zero(t, activeTreeCount(t, tn))
	t.Logf("offboarding a 200-deep chain took %v", time.Since(start))
}
