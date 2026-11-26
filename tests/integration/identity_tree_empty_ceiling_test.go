package integration_test

// A child's empty allowed_scopes (docs/identity-tree.md, docs/scope-ceilings.md):
// on an identity registered by another identity, an empty list means the
// identity holds no scope, never that it is unrestricted. So a caller whose
// token holds no scope can register children, and they receive no scope on
// any grant, carry none on an API key, gain none by delegation, and are
// narrowed, not widened, by clearing the list. An identity with no parent is
// unchanged: its empty list places no restriction.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// emptyCeilingGrants are the grant types the tests here need a policy to allow.
var emptyCeilingGrants = []string{"api_key", "jwt_bearer", "token_exchange"}

// emptyCeilingPolicy creates a policy that lists data:read and data:write,
// which a child left unrestricted by an empty list would be issued by
// default.
func emptyCeilingPolicy(t *testing.T, tn treeTenant) string {
	t.Helper()
	return createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-empty-ceiling"), "allowed_grant_types": emptyCeilingGrants,
		"allowed_scopes": []string{"data:read", "data:write"}, "max_ttl_seconds": 3600, "max_delegation_depth": 5,
	}, tn.headers())
}

// requireTokenNoScopes asserts a token response issued a token carrying no scope.
func requireTokenNoScopes(t *testing.T, status int, body map[string]any) {
	t.Helper()
	require.Equal(t, http.StatusOK, status, "an omitted request is answered: %v", body)
	assert.Empty(t, body["scope"], "the response names no scope")
	claims := decodeJWTPayload(t, body["access_token"].(string))
	assert.NotContains(t, claims, "scopes", "the token carries no scope")
}

// requireTokenRefused asserts a token request was refused over its scopes.
func requireTokenRefused(t *testing.T, status int, body map[string]any, what string) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, status, "%s: %v", what, body)
	assert.Equal(t, "invalid_scope", body["error"], "%s", what)
	assert.NotContains(t, body, "access_token", "%s", what)
}

// jwtBearerToken redeems a self-signed assertion; scope is optional.
func jwtBearerToken(t *testing.T, key *ecdsa.PrivateKey, wimseURI, scope string) (int, map[string]any) {
	t.Helper()
	body := map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":  buildAssertion(t, key, wimseURI),
	}
	if scope != "" {
		body["scope"] = scope
	}
	resp := post(t, "/oauth2/token", body, nil)
	return resp.StatusCode, decode(t, resp)
}

// TestIdentityTree_ScopelessCallerRegistersChild: a caller whose token holds
// no scope registers a child (201) whose allowed_scopes is empty. The child
// is issued no scope it requests, and nothing on a request that names none,
// although the parent's policy, which the child inherits, lists scopes. Shadow
// answers exactly as off and records nothing: issuance already makes the
// change the stricter rules would.
func TestIdentityTree_ScopelessCallerRegistersChild(t *testing.T) {
	for _, mode := range []zeroid.ScopeRulesMode{zeroid.ScopeRulesModeOff, zeroid.ScopeRulesModeShadow} {
		t.Run(string(mode), func(t *testing.T) {
			setScopeRules(t, mode)
			records := captureScopeRules(t)
			tn := newTreeTenant()
			pol := emptyCeilingPolicy(t, tn)
			parent := mustTreeIdentity(t, tn.headers(), map[string]any{
				"credential_policy_id": pol, "allowed_scopes": []string{"data:read", "data:write"},
			})

			child, key := mustTreeAgent(t, tn.asWith(parent.ID), map[string]any{})
			assert.Equal(t, parent.ID, child.ParentIdentityID)
			assert.Empty(t, child.AllowedScopes, "a token that holds no scope gives the child none")
			assert.Equal(t, pol, child.CredentialPolicyID, "the child inherits the parent's policy, which lists scopes")
			assert.Empty(t, getTreeIdentity(t, tn, child.ID).AllowedScopes)

			status, body := apiKeyToken(t, key, "data:read")
			requireTokenRefused(t, status, body, "api_key: a scope the inherited policy lists")
			status, body = apiKeyToken(t, key, "admin:all")
			requireTokenRefused(t, status, body, "api_key: a scope nothing lists")
			status, body = apiKeyToken(t, key, "")
			requireTokenNoScopes(t, status, body)

			// The same on the jwt-bearer grant.
			signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			signed := mustTreeIdentity(t, tn.asWith(parent.ID), map[string]any{"public_key_pem": ecPublicKeyPEM(t, signer)})
			assert.Empty(t, signed.AllowedScopes)
			status, body = jwtBearerToken(t, signer, signed.WIMSEURI, "data:read")
			requireTokenRefused(t, status, body, "jwt_bearer: a scope the inherited policy lists")
			status, body = jwtBearerToken(t, signer, signed.WIMSEURI, "")
			requireTokenNoScopes(t, status, body)

			// The child's own scopeless key registers a grandchild in turn.
			childID := child.ID
			grandchild := mustTreeIdentity(t, tn.asWith(childID), map[string]any{})
			assert.Equal(t, childID, grandchild.ParentIdentityID)
			assert.Empty(t, grandchild.AllowedScopes)
			status, raw := postTreeIdentity(t, tn.asWith(childID, "data:read"), map[string]any{"allowed_scopes": []string{"data:read"}})
			assert.Equal(t, http.StatusBadRequest, status, "a parent that lists no scope lets its child list none: %s", raw)

			assert.Empty(t, records.lines(t), "no stricter rule changes what issuance already decided")
			assert.Empty(t, records.counts(t))
		})
	}
}

// TestIdentityTree_ScopelessChildUnderEnforce: with token.scope_rules=enforce
// a child whose own list is empty is read as listing nothing. A scope it
// requests is refused invalid_scope naming its registration as the ceiling
// that must list it, though the policy it inherits lists the scope, and a
// request that names none is issued a token with no scopes claim.
func TestIdentityTree_ScopelessChildUnderEnforce(t *testing.T) {
	setScopeRules(t, zeroid.ScopeRulesModeEnforce)
	tn := newTreeTenant()
	pol := emptyCeilingPolicy(t, tn)
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{
		"credential_policy_id": pol, "allowed_scopes": []string{"data:read", "data:write"},
	})
	child, key := mustTreeAgent(t, tn.asWith(parent.ID), map[string]any{})
	require.Empty(t, child.AllowedScopes)

	const refusal = "scope %s is not granted: the identity's allowed_scopes must list it"
	status, body := apiKeyToken(t, key, "data:read")
	requireTokenRefused(t, status, body, "api_key: a scope the inherited policy lists")
	assert.Equal(t, fmt.Sprintf(refusal, "data:read"), body["error_description"])
	status, body = apiKeyToken(t, key, "")
	requireTokenNoScopes(t, status, body)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signed := mustTreeIdentity(t, tn.asWith(parent.ID), map[string]any{"public_key_pem": ecPublicKeyPEM(t, signer)})
	status, body = jwtBearerToken(t, signer, signed.WIMSEURI, "data:write")
	requireTokenRefused(t, status, body, "jwt_bearer: a scope the inherited policy lists")
	assert.Equal(t, fmt.Sprintf(refusal, "data:write"), body["error_description"])
	status, body = jwtBearerToken(t, signer, signed.WIMSEURI, "")
	requireTokenNoScopes(t, status, body)
}

// TestIdentityTree_ChildKeyScopesWithinItsList: a key for a child carries
// only scopes the child lists, so a child that lists none gets keys with
// none. A key for an identity with no parent is created as before.
func TestIdentityTree_ChildKeyScopesWithinItsList(t *testing.T) {
	tn := newTreeTenant()
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"allowed_scopes": []string{"data:read", "data:write"}})
	createKey := func(identityID string, scopes ...string) (int, []byte) {
		body := map[string]any{"name": uid("tree-key"), "identity_id": identityID}
		if len(scopes) > 0 {
			body["scopes"] = scopes
		}
		return treeRequest(t, http.MethodPost, adminPath("/api-keys"), body, tn.headers())
	}

	none := mustTreeIdentity(t, tn.asWith(parent.ID), map[string]any{})
	status, raw := createKey(none.ID, "data:read")
	assert.Equal(t, http.StatusBadRequest, status, "a key with a scope for a child that lists none: %s", raw)
	assert.Contains(t, string(raw), "data:read")
	status, raw = createKey(none.ID)
	assert.Equal(t, http.StatusCreated, status, "a key with no scope: %s", raw)

	listed := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{"allowed_scopes": []string{"data:read"}})
	status, raw = createKey(listed.ID, "data:write")
	assert.Equal(t, http.StatusBadRequest, status, "a scope the child does not list: %s", raw)
	status, raw = createKey(listed.ID, "data:read")
	assert.Equal(t, http.StatusCreated, status, "a scope the child lists: %s", raw)

	status, raw = createKey(parent.ID, "admin:all")
	assert.Equal(t, http.StatusCreated, status, "an identity with no parent: unchanged, checked at issuance only: %s", raw)
}

// TestIdentityTree_ChildWithNoScopeGainsNoneByDelegation: a token exchange
// gives a child that lists no scope nothing, as the subject (its token holds
// none) or as the actor (its own list admits none), and the refusal names
// the actor's registration.
func TestIdentityTree_ChildWithNoScopeGainsNoneByDelegation(t *testing.T) {
	tn := newTreeTenant()
	pol := emptyCeilingPolicy(t, tn)
	parent, parentKey := mustTreeAgent(t, tn.headers(), map[string]any{
		"created_by": "owner-alice", "credential_policy_id": pol, "allowed_scopes": []string{"data:read", "data:write"},
	})
	parentToken := mustAPIKeyToken(t, parentKey)

	_, childKey := mustTreeAgent(t, tn.asWith(parent.ID), map[string]any{})
	childToken := mustAPIKeyToken(t, childKey)
	actor, actorKey := exchangeActor(t, tn, pol)
	status, body := exchangeTree(t, childToken, actorKey, actor.WIMSEURI)
	requireTokenRefused(t, status, body, "the child's token as the subject")

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	childActor := mustTreeIdentity(t, tn.asWith(parent.ID), map[string]any{"public_key_pem": ecPublicKeyPEM(t, signer)})
	status, body = exchangeTree(t, parentToken, signer, childActor.WIMSEURI)
	requireTokenRefused(t, status, body, "the child as the actor")
	assert.Contains(t, body["error_description"], "the actor identity is not registered for [data:read]")
}

// TestIdentityTree_RootEmptyListUnrestricted: an identity with no parent and
// an empty allowed_scopes, on a policy that lists nothing, is unrestricted as
// before.
func TestIdentityTree_RootEmptyListUnrestricted(t *testing.T) {
	setScopeRules(t, zeroid.ScopeRulesModeOff)
	tn := newTreeTenant()
	open := createRichCredentialPolicy(t, map[string]any{
		"name": uid("tree-open"), "allowed_grant_types": emptyCeilingGrants, "max_ttl_seconds": 3600,
	}, tn.headers())
	root, key := mustTreeAgent(t, tn.headers(), map[string]any{"created_by": "owner-alice", "credential_policy_id": open})
	require.Empty(t, root.ParentIdentityID)
	require.Empty(t, root.AllowedScopes)

	status, body := apiKeyToken(t, key, "anything:at-all")
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, "anything:at-all", body["scope"], "an empty list on an identity with no parent places no restriction")
}

// TestIdentityTree_ClearingChildListNarrows: setting a child's allowed_scopes
// to empty narrows it to no scope, whoever makes the change (an admin, or the
// parent itself), and the child is then issued none. A calling identity still
// cannot widen it again beyond its token.
func TestIdentityTree_ClearingChildListNarrows(t *testing.T) {
	tn := newTreeTenant()
	pol := emptyCeilingPolicy(t, tn)
	parent := mustTreeIdentity(t, tn.headers(), map[string]any{"credential_policy_id": pol})
	child, key := mustTreeAgent(t, tn.as(parent.ID), map[string]any{"allowed_scopes": []string{"data:read"}})
	status, body := apiKeyToken(t, key, "data:read")
	require.Equal(t, http.StatusOK, status, "before: %v", body)

	status, raw := treeRequest(t, http.MethodPatch, adminPath("/identities/"+child.ID), map[string]any{"allowed_scopes": []string{}}, tn.headers())
	require.Equal(t, http.StatusOK, status, "an admin clearing the list: %s", raw)
	assert.Empty(t, getTreeIdentity(t, tn, child.ID).AllowedScopes)
	status, body = apiKeyToken(t, key, "data:read")
	requireTokenRefused(t, status, body, "a scope the cleared list used to hold")
	status, body = apiKeyToken(t, key, "")
	requireTokenNoScopes(t, status, body)

	other := mustTreeIdentity(t, tn.as(parent.ID), map[string]any{"allowed_scopes": []string{"data:read"}})
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+other.ID), map[string]any{"allowed_scopes": []string{}}, tn.asWith(parent.ID))
	require.Equal(t, http.StatusOK, status, "the parent, with a scopeless token, clearing its child's list: %s", raw)
	assert.Empty(t, getTreeIdentity(t, tn, other.ID).AllowedScopes)
	status, raw = treeRequest(t, http.MethodPatch, adminPath("/identities/"+other.ID), map[string]any{"allowed_scopes": []string{"data:read"}}, tn.asWith(parent.ID))
	assert.Equal(t, http.StatusBadRequest, status, "widening it again beyond the caller's token: %s", raw)
	assert.Empty(t, getTreeIdentity(t, tn, other.ID).AllowedScopes, "a refused update changes nothing")
}
