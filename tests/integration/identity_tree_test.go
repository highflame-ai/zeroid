package integration_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// The registration tree (docs/identity-tree.md): an identity registered by a
// request the embedder authenticated as another identity is that identity's
// child. The test AdminAuth middleware marks the caller from the
// X-Test-Caller-* headers, standing in for the embedder's own authentication.

// treeTenant is a fresh account and project, so each test owns its
// identities, policies and tenant default policy.
type treeTenant struct {
	account, project string
}

func newTreeTenant() treeTenant {
	return treeTenant{account: uid("acct-tree"), project: uid("proj-tree")}
}

func (tn treeTenant) headers() map[string]string {
	return map[string]string{"X-Account-ID": tn.account, "X-Project-ID": tn.project}
}

// as returns headers for a request authenticated as the identity with id.
func (tn treeTenant) as(id string) map[string]string {
	h := tn.headers()
	h[testCallerIdentityIDHeader] = id
	return h
}

// treeIdentity is the part of an identity these tests read back.
type treeIdentity struct {
	ID                 string   `json:"id"`
	WIMSEURI           string   `json:"wimse_uri"`
	Status             string   `json:"status"`
	OwnerUserID        string   `json:"owner_user_id"`
	CreatedBy          string   `json:"created_by"`
	ParentIdentityID   string   `json:"parent_identity_id"`
	CredentialPolicyID string   `json:"credential_policy_id"`
	AllowedScopes      []string `json:"allowed_scopes"`
}

// treeRequest sends a JSON request and returns the status and raw body.
func treeRequest(t *testing.T, method, path string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	resp, err := doRaw(t, method, path, body, headers)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

// postTreeIdentity calls POST /identities and returns the status and body.
func postTreeIdentity(t *testing.T, headers map[string]string, body map[string]any) (int, []byte) {
	t.Helper()
	if _, ok := body["external_id"]; !ok {
		body["external_id"] = uid("tree-id")
	}
	if _, ok := body["owner_user_id"]; !ok {
		body["owner_user_id"] = "owner-request"
	}
	return treeRequest(t, http.MethodPost, adminPath("/identities"), body, headers)
}

// mustTreeIdentity registers an identity and returns it.
func mustTreeIdentity(t *testing.T, headers map[string]string, body map[string]any) treeIdentity {
	t.Helper()
	status, raw := postTreeIdentity(t, headers, body)
	require.Equal(t, http.StatusCreated, status, "POST /identities: %s", raw)
	var out treeIdentity
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// mustTreeAgent registers an agent (identity + API key) and returns both.
func mustTreeAgent(t *testing.T, headers map[string]string, body map[string]any) (treeIdentity, string) {
	t.Helper()
	ext := uid("tree-agent")
	body["external_id"] = ext
	body["name"] = ext
	status, raw := treeRequest(t, http.MethodPost, adminPath("/agents/register"), body, headers)
	require.Equal(t, http.StatusCreated, status, "POST /agents/register: %s", raw)
	var out struct {
		Identity treeIdentity `json:"identity"`
		APIKey   string       `json:"api_key"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	require.NotEmpty(t, out.APIKey)
	return out.Identity, out.APIKey
}

// getTreeIdentity reads an identity through GET /identities/{id}.
func getTreeIdentity(t *testing.T, tn treeTenant, id string) treeIdentity {
	t.Helper()
	status, raw := treeRequest(t, http.MethodGet, adminPath("/identities/"+id), nil, tn.headers())
	require.Equal(t, http.StatusOK, status, "GET /identities/%s: %s", id, raw)
	var out treeIdentity
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// apiKeyToken redeems an API key; scope is optional.
func apiKeyToken(t *testing.T, apiKey, scope string) (int, map[string]any) {
	t.Helper()
	body := map[string]any{"grant_type": "api_key", "api_key": apiKey}
	if scope != "" {
		body["scope"] = scope
	}
	resp := post(t, "/oauth2/token", body, nil)
	return resp.StatusCode, decode(t, resp)
}

// mustAPIKeyToken redeems an API key and returns the access token.
func mustAPIKeyToken(t *testing.T, apiKey string) string {
	t.Helper()
	status, body := apiKeyToken(t, apiKey, "")
	require.Equal(t, http.StatusOK, status, "api_key grant: %v", body)
	return body["access_token"].(string)
}

// treeList lists identities on path (an /identities or /agents/registry
// list) and returns the ids it found.
func treeList(t *testing.T, path, key string, tn treeTenant) (int, []string) {
	t.Helper()
	status, raw := treeRequest(t, http.MethodGet, path, nil, tn.headers())
	if status != http.StatusOK {
		return status, nil
	}
	var page map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &page))
	var items []treeIdentity
	require.NoError(t, json.Unmarshal(page[key], &items))
	var ids []string
	for _, i := range items {
		ids = append(ids, i.ID)
	}
	return status, ids
}

// TestIdentityTree_ParentFromAuthenticatedCaller verifies that an identity
// registered by a request the embedder authenticated as another identity
// records that identity as its parent, by id or by WIMSE URI, on both
// registration routes, and that the reads return it.
func TestIdentityTree_ParentFromAuthenticatedCaller(t *testing.T) {
	tn := newTreeTenant()
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": "owner-alice"})
	assert.Empty(t, parent.ParentIdentityID, "an identity an admin registers has no parent")

	child := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{})
	assert.Equal(t, parent.ID, child.ParentIdentityID)
	assert.Equal(t, parent.ID, getTreeIdentity(t, tn, child.ID).ParentIdentityID, "GET /identities/{id} returns parent_identity_id")

	byURI := tn.headers()
	byURI[testCallerWIMSEHeader] = parent.WIMSEURI
	assert.Equal(t, parent.ID, mustTreeIdentity(t, byURI, map[string]any{}).ParentIdentityID,
		"the caller may be named by its WIMSE URI")

	agent, _ := mustTreeAgent(t, tn.as(parent.ID), map[string]any{})
	assert.Equal(t, parent.ID, agent.ParentIdentityID, "POST /agents/register records the parent too")
	status, raw := treeRequest(t, http.MethodGet, adminPath("/agents/registry/"+agent.ID), nil, tn.headers())
	require.Equal(t, http.StatusOK, status)
	var registry treeIdentity
	require.NoError(t, json.Unmarshal(raw, &registry))
	assert.Equal(t, parent.ID, registry.ParentIdentityID, "the agent registry returns parent_identity_id")
}

// TestIdentityTree_BodyCannotNameParent verifies that the parent comes only
// from the authenticated caller: a body field, opaque labels or metadata, or
// a client-set header cannot name one, and cannot override the caller.
func TestIdentityTree_BodyCannotNameParent(t *testing.T) {
	tn := newTreeTenant()
	p := mustTreeIdentity(t, tn.headers(), map[string]any{})
	q := mustTreeIdentity(t, tn.headers(), map[string]any{})

	// A top-level field is not part of either registration schema.
	ext := uid("tree-body-parent")
	status, raw := postTreeIdentity(t, tn.headers(), map[string]any{"external_id": ext, "parent_identity_id": p.ID})
	assert.Equal(t, http.StatusUnprocessableEntity, status, "body parent_identity_id: %s", raw)
	status, _ = treeRequest(t, http.MethodPost, adminPath("/agents/register"),
		map[string]any{"name": ext, "external_id": ext, "parent_identity_id": p.ID}, tn.headers())
	assert.Equal(t, http.StatusUnprocessableEntity, status)
	_, ids := treeList(t, adminPath("/identities?search="+ext), "identities", tn)
	assert.Empty(t, ids, "a refused request registers nothing")

	// Labels and metadata are opaque: they are stored, and name no parent.
	naming := map[string]any{"parent_identity_id": p.ID}
	assert.Empty(t, mustTreeIdentity(t, tn.headers(), map[string]any{"labels": naming}).ParentIdentityID)
	viaMetadata, _ := mustTreeAgent(t, tn.headers(), map[string]any{"metadata": naming, "created_by": "owner-alice"})
	assert.Empty(t, viaMetadata.ParentIdentityID)

	// Headers a client sets are not authentication.
	headers := tn.headers()
	headers["X-User-ID"] = p.WIMSEURI
	headers["X-Parent-Identity-ID"] = p.ID
	assert.Empty(t, mustTreeIdentity(t, headers, map[string]any{}).ParentIdentityID)

	// The authenticated caller wins over anything the body says.
	assert.Equal(t, q.ID, mustTreeIdentity(t, tn.as(q.ID), map[string]any{"labels": naming}).ParentIdentityID)
	child, _ := mustTreeAgent(t, tn.as(q.ID), map[string]any{"metadata": naming})
	assert.Equal(t, q.ID, child.ParentIdentityID)
}

// TestIdentityTree_CrossTenantParentRefused verifies that a caller identity
// from another project or account cannot register identities in this one.
func TestIdentityTree_CrossTenantParentRefused(t *testing.T) {
	home := newTreeTenant()
	parent := mustTreeIdentity(t, home.headers(), map[string]any{})

	otherProject := treeTenant{account: home.account, project: uid("proj-tree-other")}
	otherAccount := treeTenant{account: uid("acct-tree-other"), project: home.project}
	for name, tn := range map[string]treeTenant{"other project": otherProject, "other account": otherAccount} {
		t.Run(name, func(t *testing.T) {
			status, raw := postTreeIdentity(t, tn.as(parent.ID), map[string]any{})
			assert.Equal(t, http.StatusForbidden, status, "by id: %s", raw)

			byURI := tn.headers()
			byURI[testCallerWIMSEHeader] = parent.WIMSEURI
			status, raw = postTreeIdentity(t, byURI, map[string]any{})
			assert.Equal(t, http.StatusForbidden, status, "by WIMSE URI: %s", raw)

			status, _ = treeRequest(t, http.MethodPost, adminPath("/agents/register"),
				map[string]any{"name": "x", "external_id": uid("tree-x")}, tn.as(parent.ID))
			assert.Equal(t, http.StatusForbidden, status, "agent registration")

			_, ids := treeList(t, adminPath("/identities"), "identities", tn)
			assert.Empty(t, ids, "nothing is registered in the other tenant")
		})
	}
}

// TestIdentityTree_InactiveParentRefused verifies that only an active,
// unexpired identity can register children, and that a caller reference
// naming no identity, or two different ones, is refused rather than ignored.
func TestIdentityTree_InactiveParentRefused(t *testing.T) {
	tn := newTreeTenant()

	for _, status := range []string{"suspended", "deactivated"} {
		parent := mustTreeIdentity(t, tn.headers(), map[string]any{})
		code, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+parent.ID), map[string]any{"status": status}, tn.headers())
		require.Equal(t, http.StatusOK, code, "%s", raw)
		code, raw = postTreeIdentity(t, tn.as(parent.ID), map[string]any{})
		assert.Equal(t, http.StatusForbidden, code, "a %s parent: %s", status, raw)
	}

	expired := mustTreeIdentity(t, tn.headers(), map[string]any{})
	stampExpiredInDB(t, expired.ID)
	code, raw := postTreeIdentity(t, tn.as(expired.ID), map[string]any{})
	assert.Equal(t, http.StatusForbidden, code, "an expired parent: %s", raw)

	code, _ = postTreeIdentity(t, tn.as("6f1d1c8e-2f4a-4b8e-9d3c-0a1b2c3d4e5f"), map[string]any{})
	assert.Equal(t, http.StatusForbidden, code, "an id that names no identity")
	code, _ = postTreeIdentity(t, tn.as("not-a-uuid"), map[string]any{})
	assert.Equal(t, http.StatusForbidden, code, "an id that is not an identity id")

	a := mustTreeIdentity(t, tn.headers(), map[string]any{})
	b := mustTreeIdentity(t, tn.headers(), map[string]any{})
	mismatched := tn.as(a.ID)
	mismatched[testCallerWIMSEHeader] = b.WIMSEURI
	code, _ = postTreeIdentity(t, mismatched, map[string]any{})
	assert.Equal(t, http.StatusForbidden, code, "an id and a WIMSE URI naming different identities")
}

// TestIdentityTree_OwnerAndCreatedByInherited verifies that a child takes its
// parent's owner whatever the request says, that created_by names the parent,
// and that a child agent's bootstrap API key names the owner too.
func TestIdentityTree_OwnerAndCreatedByInherited(t *testing.T) {
	tn := newTreeTenant()
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"owner_user_id": "owner-alice"})

	child := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{"owner_user_id": "owner-mallory"})
	assert.Equal(t, "owner-alice", child.OwnerUserID, "the parent's owner, not the body's")
	assert.Equal(t, parent.WIMSEURI, child.CreatedBy, "created_by names the parent identity")

	headers := tn.as(parent.ID)
	headers["X-User-ID"] = "user-mallory"
	agent, key := mustTreeAgent(t, headers, map[string]any{"created_by": "owner-mallory"})
	assert.Equal(t, "owner-alice", agent.OwnerUserID)
	assert.Equal(t, parent.WIMSEURI, agent.CreatedBy)

	status, body := apiKeyToken(t, key, "")
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, "owner-alice", body["user_id"], "the bootstrap key's creator is the inherited owner")
}

// TestIdentityTree_ScopeCeiling verifies that a child can hold no scope its
// parent does not, on registration and on update, and that the refusal names
// the scope.
func TestIdentityTree_ScopeCeiling(t *testing.T) {
	tn := newTreeTenant()
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"allowed_scopes": []string{"data:read", "data:write"}})
	grants := []string{"api_key", "client_credentials", "jwt_bearer", "token_exchange"}

	status, raw := postTreeIdentity(t, tn.as(parent.ID), map[string]any{"allowed_scopes": []string{"data:read", "admin:all"}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(raw), `admin:all`, "the refusal names the scope")

	wider := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-wider"), "allowed_grant_types": grants, "allowed_scopes": []string{"data:read", "billing:write"},
	}, tn.headers())
	status, raw = postTreeIdentity(t, tn.as(parent.ID), map[string]any{"credential_policy_id": wider})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(raw), `billing:write`, "the refusal names the policy's scope")

	narrower := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-narrower"), "allowed_grant_types": grants, "allowed_scopes": []string{"data:read"},
	}, tn.headers())
	child := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{"credential_policy_id": narrower})
	assert.Equal(t, narrower, child.CredentialPolicyID)
	assert.ElementsMatch(t, []string{"data:read", "data:write"}, child.AllowedScopes, "allowed_scopes left empty is the parent's")

	child = mustTreeIdentity(t, tn.as(parent.ID), map[string]any{"allowed_scopes": []string{"data:read"}})
	assert.Equal(t, []string{"data:read"}, child.AllowedScopes)

	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+child.ID),
		map[string]any{"allowed_scopes": []string{"data:read", "admin:all"}}, tn.headers())
	assert.Equal(t, http.StatusBadRequest, status, "an update is held to the parent too")
	assert.Contains(t, string(raw), `admin:all`)
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+child.ID),
		map[string]any{"allowed_scopes": []string{}}, tn.headers())
	assert.Equal(t, http.StatusBadRequest, status, "clearing the only ceiling would free the child: %s", raw)
	assert.Equal(t, []string{"data:read"}, getTreeIdentity(t, tn, child.ID).AllowedScopes, "a refused update changes nothing")

	open := mustTreeIdentity(t, tn.headers(), map[string]any{})
	anything := mustTreeIdentity(t, tn.as(open.ID), map[string]any{"allowed_scopes": []string{"admin:all"}})
	assert.Equal(t, []string{"admin:all"}, anything.AllowedScopes, "nothing exceeds a parent with no ceiling")
}

// TestIdentityTree_EmptyCeilingPolicyRefused verifies that a child of a
// restricted parent cannot be placed on a policy that places no scope ceiling,
// which would let it request any scope.
func TestIdentityTree_EmptyCeilingPolicyRefused(t *testing.T) {
	tn := newTreeTenant()
	empty := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-empty"), "allowed_grant_types": []string{"api_key"},
	}, tn.headers())

	restricted := mustTreeIdentity(t, tn.headers(), map[string]any{"allowed_scopes": []string{"data:read"}})
	status, raw := postTreeIdentity(t, tn.as(restricted.ID), map[string]any{
		"credential_policy_id": empty, "allowed_scopes": []string{"data:read"},
	})
	assert.Equal(t, http.StatusBadRequest, status, "%s", raw)
	assert.Contains(t, string(raw), "places no scope ceiling")

	open := mustTreeIdentity(t, tn.headers(), map[string]any{})
	child := mustTreeIdentity(t, tn.as(open.ID), map[string]any{"credential_policy_id": empty})
	assert.Equal(t, empty, child.CredentialPolicyID, "a parent with no ceiling may place its child on one too")
}

// TestIdentityTree_InheritsParentPolicy verifies that a child that names no
// credential policy gets its parent's, not the tenant default, and that the
// child can then mint nothing its parent could not: the escape an empty
// default policy would otherwise open.
func TestIdentityTree_InheritsParentPolicy(t *testing.T) {
	tn := newTreeTenant()
	restricted := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-restricted"), "allowed_grant_types": []string{"api_key"}, "allowed_scopes": []string{"data:read"},
	}, tn.headers())
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"credential_policy_id": restricted})

	child, key := mustTreeAgent(t, tn.as(parent.ID), map[string]any{})
	assert.Equal(t, restricted, child.CredentialPolicyID, "the parent's policy, not the tenant default")

	status, body := apiKeyToken(t, key, "billing:write")
	assert.Equal(t, http.StatusBadRequest, status, "%v", body)
	assert.Equal(t, "invalid_scope", body["error"])
	status, body = apiKeyToken(t, key, "data:read")
	assert.Equal(t, http.StatusOK, status, "%v", body)

	// Resetting the child's policy returns it to its parent's.
	status, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+child.ID),
		map[string]any{"credential_policy_id": ""}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	assert.Equal(t, restricted, getTreeIdentity(t, tn, child.ID).CredentialPolicyID)

	// A parent bounded only by its own allowed_scopes, on the tenant default
	// policy (no ceiling): the child takes the allowed_scopes too.
	rowOnly := mustTreeIdentity(t, tn.headers(), map[string]any{"allowed_scopes": []string{"data:read"}})
	rowChild, rowKey := mustTreeAgent(t, tn.as(rowOnly.ID), map[string]any{})
	stored := getTreeIdentity(t, tn, rowChild.ID)
	assert.Equal(t, rowOnly.CredentialPolicyID, stored.CredentialPolicyID)
	assert.Equal(t, []string{"data:read"}, stored.AllowedScopes)
	status, body = apiKeyToken(t, rowKey, "billing:write")
	assert.Equal(t, http.StatusBadRequest, status, "%v", body)
	assert.Equal(t, "invalid_scope", body["error"])
}

// treeChain registers a root agent and three generations below it, each
// registered by the one above, and returns them root first with their keys.
func treeChain(t *testing.T, tn treeTenant) ([]treeIdentity, []string) {
	t.Helper()
	root, rootKey := mustTreeAgent(t, tn.headers(), map[string]any{"created_by": "owner-alice"})
	ids, keys := []treeIdentity{root}, []string{rootKey}
	for range 3 {
		next, key := mustTreeAgent(t, tn.as(ids[len(ids)-1].ID), map[string]any{})
		ids, keys = append(ids, next), append(keys, key)
	}
	return ids, keys
}

// TestIdentityTree_DeactivationCascades verifies that deactivating an identity
// deactivates every identity below it, three levels down, with the same API
// key and token revocation a direct deactivation performs, and leaves
// identities outside the subtree alone.
func TestIdentityTree_DeactivationCascades(t *testing.T) {
	tn := newTreeTenant()
	chain, keys := treeChain(t, tn)
	unrelated, unrelatedKey := mustTreeAgent(t, tn.headers(), map[string]any{"created_by": "owner-alice"})

	tokens := make([]string, len(chain))
	for i, key := range keys {
		tokens[i] = mustAPIKeyToken(t, key)
	}
	unrelatedToken := mustAPIKeyToken(t, unrelatedKey)

	status, raw := treeRequest(t, http.MethodDelete, adminPath("/identities/"+chain[0].ID), nil, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)

	for i, node := range chain {
		assert.Equal(t, "deactivated", getTreeIdentity(t, tn, node.ID).Status, "level %d", i)
		assert.False(t, introspect(t, tokens[i])["active"].(bool), "level %d's token is revoked", i)
		code, body := apiKeyToken(t, keys[i], "")
		assert.Equal(t, http.StatusBadRequest, code, "level %d's API key no longer mints: %v", i, body)
	}
	for i := 1; i < len(chain); i++ {
		events := revocationCapture.forJTI(jtiOf(t, tokens[i]))
		require.Len(t, events, 1, "level %d's token fires one revocation event", i)
		assert.Equal(t, "parent_deactivated", events[0].Reason, "level %d", i)
	}

	assert.Equal(t, "active", getTreeIdentity(t, tn, unrelated.ID).Status, "an identity outside the subtree is untouched")
	assert.True(t, introspect(t, unrelatedToken)["active"].(bool))
}

// TestIdentityTree_DeactivationCascadesOnEveryPath verifies the cascade on the
// other ways an identity is retired: the agent deactivate route, a status
// update, the expire route and the expiry sweep.
func TestIdentityTree_DeactivationCascadesOnEveryPath(t *testing.T) {
	retire := map[string]func(t *testing.T, tn treeTenant, id string){
		"agent deactivate route": func(t *testing.T, tn treeTenant, id string) {
			status, raw := treeRequest(t, http.MethodPost, adminPath("/agents/registry/"+id+"/deactivate"), nil, tn.headers())
			require.Equal(t, http.StatusOK, status, "%s", raw)
		},
		"agent delete route": func(t *testing.T, tn treeTenant, id string) {
			status, raw := treeRequest(t, http.MethodDelete, adminPath("/agents/registry/"+id), nil, tn.headers())
			require.Equal(t, http.StatusOK, status, "%s", raw)
		},
		"status update": func(t *testing.T, tn treeTenant, id string) {
			status, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+id), map[string]any{"status": "deactivated"}, tn.headers())
			require.Equal(t, http.StatusOK, status, "%s", raw)
		},
		"expire route": func(t *testing.T, tn treeTenant, id string) {
			status, raw := treeRequest(t, http.MethodPost, adminPath("/identities/"+id+"/expire"), nil, tn.headers())
			require.Equal(t, http.StatusOK, status, "%s", raw)
		},
		"expiry sweep": func(t *testing.T, _ treeTenant, id string) {
			stampExpiredInDB(t, id)
			testZeroIDServer.RunCleanupOnce(context.Background())
		},
	}
	for name, fn := range retire {
		t.Run(name, func(t *testing.T) {
			tn := newTreeTenant()
			chain, _ := treeChain(t, tn)
			fn(t, tn, chain[0].ID)
			for i, node := range chain[1:] {
				assert.Equal(t, "deactivated", getTreeIdentity(t, tn, node.ID).Status, "level %d", i+1)
			}
		})
	}
}

// TestIdentityTree_ReactivationDoesNotCascade verifies that reactivating an
// identity leaves the identities below it deactivated.
func TestIdentityTree_ReactivationDoesNotCascade(t *testing.T) {
	tn := newTreeTenant()
	chain, keys := treeChain(t, tn)

	status, raw := treeRequest(t, http.MethodDelete, adminPath("/identities/"+chain[0].ID), nil, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	status, raw = treeRequest(t, http.MethodPost, adminPath("/agents/registry/"+chain[0].ID+"/activate"), nil, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)

	assert.Equal(t, "active", getTreeIdentity(t, tn, chain[0].ID).Status)
	for i, node := range chain[1:] {
		assert.Equal(t, "deactivated", getTreeIdentity(t, tn, node.ID).Status, "level %d stays deactivated", i+1)
		code, body := apiKeyToken(t, keys[i+1], "")
		assert.Equal(t, http.StatusBadRequest, code, "level %d still cannot mint: %v", i+1, body)
	}
}

// TestIdentityTree_CascadeReachesThroughDeactivated verifies that the walk
// does not stop at an identity that is already deactivated: an identity
// reactivated below it is still reached from further up.
func TestIdentityTree_CascadeReachesThroughDeactivated(t *testing.T) {
	tn := newTreeTenant()
	chain, _ := treeChain(t, tn)

	status, raw := treeRequest(t, http.MethodDelete, adminPath("/identities/"+chain[1].ID), nil, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	require.Equal(t, "deactivated", getTreeIdentity(t, tn, chain[3].ID).Status)
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+chain[3].ID), map[string]any{"status": "active"}, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)

	status, raw = treeRequest(t, http.MethodDelete, adminPath("/identities/"+chain[0].ID), nil, tn.headers())
	require.Equal(t, http.StatusOK, status, "%s", raw)
	assert.Equal(t, "deactivated", getTreeIdentity(t, tn, chain[3].ID).Status)
}

// TestIdentityTree_ListByParent verifies listing an identity's children on
// both list routes, and that the filter must be an identity id.
func TestIdentityTree_ListByParent(t *testing.T) {
	tn := newTreeTenant()
	chain, _ := treeChain(t, tn)
	sibling, _ := mustTreeAgent(t, tn.as(chain[0].ID), map[string]any{})

	q := "?parent_identity_id=" + url.QueryEscape(chain[0].ID)
	status, ids := treeList(t, adminPath("/identities"+q), "identities", tn)
	require.Equal(t, http.StatusOK, status)
	assert.ElementsMatch(t, []string{chain[1].ID, sibling.ID}, ids, "direct children only")
	status, ids = treeList(t, adminPath("/agents/registry"+q), "agents", tn)
	require.Equal(t, http.StatusOK, status)
	assert.ElementsMatch(t, []string{chain[1].ID, sibling.ID}, ids)

	status, _ = treeList(t, adminPath("/identities?parent_identity_id=not-a-uuid"), "identities", tn)
	assert.Equal(t, http.StatusBadRequest, status)
	status, _ = treeList(t, adminPath("/agents/registry?parent_identity_id=not-a-uuid"), "agents", tn)
	assert.Equal(t, http.StatusBadRequest, status)
}

// TestIdentityTree_IsRegisteredBy verifies the embedder helper: true only for
// the direct parent, named by id or WIMSE URI, in the identity's own tenant.
func TestIdentityTree_IsRegisteredBy(t *testing.T) {
	tn := newTreeTenant()
	chain, _ := treeChain(t, tn)
	root, child, grandchild := chain[0], chain[1], chain[2]
	ctx := context.Background()

	check := func(id string, by zeroid.CallerIdentity, account, project string) bool {
		t.Helper()
		ok, err := testZeroIDServer.IsRegisteredBy(ctx, id, by, account, project)
		require.NoError(t, err)
		return ok
	}

	assert.True(t, check(child.ID, zeroid.CallerIdentity{IdentityID: root.ID}, tn.account, tn.project))
	assert.True(t, check(child.ID, zeroid.CallerIdentity{WIMSEURI: root.WIMSEURI}, tn.account, tn.project))
	assert.True(t, check(child.ID, zeroid.CallerIdentity{IdentityID: root.ID, WIMSEURI: root.WIMSEURI}, tn.account, tn.project))

	assert.False(t, check(grandchild.ID, zeroid.CallerIdentity{IdentityID: root.ID}, tn.account, tn.project), "a grandparent did not register it")
	assert.False(t, check(root.ID, zeroid.CallerIdentity{IdentityID: child.ID}, tn.account, tn.project), "the edge has a direction")
	assert.False(t, check(root.ID, zeroid.CallerIdentity{IdentityID: root.ID}, tn.account, tn.project), "an identity with no parent")
	assert.False(t, check(child.ID, zeroid.CallerIdentity{IdentityID: root.ID, WIMSEURI: grandchild.WIMSEURI}, tn.account, tn.project), "an id and a URI naming different identities")
	assert.False(t, check(child.ID, zeroid.CallerIdentity{}, tn.account, tn.project), "an empty reference")
	assert.False(t, check(child.ID, zeroid.CallerIdentity{IdentityID: root.ID}, tn.account, uid("proj-tree-other")), "another tenant")
	assert.False(t, check("not-a-uuid", zeroid.CallerIdentity{IdentityID: root.ID}, tn.account, tn.project))
}

// treeChildRow is an identity row registered under parentID, for driving the
// store directly.
func treeChildRow(tn treeTenant, parentID string) *domain.Identity {
	ext := uid("tree-race")
	return &domain.Identity{
		ID:               uuid.NewString(),
		AccountID:        tn.account,
		ProjectID:        tn.project,
		ExternalID:       ext,
		Name:             ext,
		WIMSEURI:         "spiffe://" + testWIMSE + "/" + tn.account + "/" + tn.project + "/agent/" + ext,
		IdentityType:     domain.IdentityTypeAgent,
		TrustLevel:       domain.TrustLevelUnverified,
		Status:           domain.IdentityStatusActive,
		Origin:           domain.OriginNative,
		OwnerUserID:      "owner-alice",
		ParentIdentityID: parentID,
		AllowedScopes:    []string{},
		Capabilities:     []byte("[]"),
		Labels:           []byte("{}"),
		Metadata:         []byte("{}"),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// waitBlockedBy waits until another session is waiting on a lock held by the
// session with the given backend pid.
func waitBlockedBy(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		require.NoError(t, testDB.NewRaw("SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))", pid).
			Scan(context.Background(), &waiting))
		if waiting > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no session waited on the held lock")
}

// TestIdentityTree_RegistrationRacingDeactivation pins the parent-row lock
// that keeps a child from slipping in below a parent being deactivated. The
// two writes serialize on the parent row: a registration that waits on a
// deactivation is refused once it commits, and a deactivation that waits on a
// registration commits after the child exists, so the cascade, which lists
// children only after the parent's deactivation, finds it.
func TestIdentityTree_RegistrationRacingDeactivation(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewIdentityRepository(testDB)

	hold := func(t *testing.T) (bun.Tx, int) {
		t.Helper()
		tx, err := testDB.BeginTx(ctx, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback() })
		var pid int
		require.NoError(t, tx.NewRaw("SELECT pg_backend_pid()").Scan(ctx, &pid))
		return tx, pid
	}
	await := func(t *testing.T, done <-chan error) error {
		t.Helper()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("the waiting write did not finish after the lock was released")
			return nil
		}
	}

	t.Run("a registration waiting on a deactivation is refused", func(t *testing.T) {
		tn := newTreeTenant()
		parent := mustTreeIdentity(t, tn.headers(), map[string]any{})

		tx, pid := hold(t)
		_, err := tx.NewUpdate().TableExpr("identities").
			Set("status = ?", "deactivated").Where("id = ?", parent.ID).Exec(ctx)
		require.NoError(t, err)

		done := make(chan error, 1)
		go func() { done <- repo.CreateUnderParent(ctx, treeChildRow(tn, parent.ID)) }()
		waitBlockedBy(t, pid)
		require.NoError(t, tx.Commit())

		require.ErrorIs(t, await(t, done), postgres.ErrParentNotActive)
		children, err := repo.ListChildren(ctx, []string{parent.ID}, tn.account, tn.project)
		require.NoError(t, err)
		assert.Empty(t, children)
	})

	t.Run("a deactivation waiting on a registration then finds the child", func(t *testing.T) {
		tn := newTreeTenant()
		parent := mustTreeIdentity(t, tn.headers(), map[string]any{})

		tx, pid := hold(t)
		child := treeChildRow(tn, parent.ID)
		require.NoError(t, repo.CreateUnderParent(postgres.WithTx(ctx, tx), child))

		done := make(chan error, 1)
		go func() {
			_, err := testDB.NewUpdate().TableExpr("identities").
				Set("status = ?", "deactivated").Where("id = ?", parent.ID).Exec(ctx)
			done <- err
		}()
		waitBlockedBy(t, pid)
		require.NoError(t, tx.Commit())

		require.NoError(t, await(t, done))
		children, err := repo.ListChildren(ctx, []string{parent.ID}, tn.account, tn.project)
		require.NoError(t, err)
		require.Len(t, children, 1)
		assert.Equal(t, child.ID, children[0].ID)
	})
}
