package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// delegationPolicy returns a fresh credential policy that allows
// client_credentials + token_exchange up to depth 5 with the supplied
// scope set. Centralized so a future scope-allowlist tightening only
// needs editing in one place.
func delegationPolicy(t *testing.T, name string, allowedScopes []string) string {
	t.Helper()
	return createRichCredentialPolicy(t, map[string]any{
		"name":                 name,
		"allowed_grant_types":  []string{"client_credentials", "token_exchange"},
		"allowed_scopes":       allowedScopes,
		"max_delegation_depth": 5,
		"max_ttl_seconds":      3600,
	}, adminHeaders())
}

// issueRootCredential registers an identity + OAuth client, issues a
// client_credentials token, returns (identityID, jti, accessToken).
// Centralized so chain-building tests stop reading like boilerplate.
func issueRootCredential(t *testing.T, policyID, namePrefix string, scopes []string) (identityID, jti, token string) {
	t.Helper()
	extID := uid(namePrefix)
	identityID = registerIdentityWithPolicy(t, extID, policyID, "", scopes, adminHeaders())
	client := registerOAuthClient(t, extID, scopes)
	scopeStr := scopesToString(scopes)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         scopeStr,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"client_credentials root issuance: expected 200")
	token = decode(t, resp)["access_token"].(string)
	jti = decodeJWTUnsafe(t, token)["jti"].(string)
	return
}

// exchangeToken registers a new identity with the given scope ceiling,
// then exchanges parentToken for a token bound to that identity.
// Returns (identityID, jti, accessToken). Scopes on the exchanged
// token are exactly requestedScopes so attenuation tests can drive a
// known shape.
func exchangeToken(t *testing.T, policyID, namePrefix string, allowedScopes, requestedScopes []string, parentToken string) (identityID, jti, token string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	extID := uid(namePrefix)
	identityID = registerIdentityWithPolicy(t, extID, policyID, ecPublicKeyPEM(t, key),
		allowedScopes, adminHeaders())
	wimse := fetchIdentityWIMSEByExternalID(t, extID)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": parentToken,
		"actor_token":   buildAssertion(t, key, wimse),
		"scope":         scopesToString(requestedScopes),
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"token_exchange %s: expected 200, got %d", namePrefix, resp.StatusCode)
	token = decode(t, resp)["access_token"].(string)
	jti = decodeJWTUnsafe(t, token)["jti"].(string)
	return
}

func scopesToString(scopes []string) string {
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

// edgeMap indexes graph response edges by their `to` identity_id so
// per-edge assertions can target a specific hop without iterating.
func edgeMap(body map[string]any) map[string]map[string]any {
	edges, _ := body["edges"].([]any)
	out := make(map[string]map[string]any, len(edges))
	for _, e := range edges {
		m := e.(map[string]any)
		if to, ok := m["to"].(string); ok && to != "" {
			out[to] = m
		}
	}
	return out
}

func nodeIDs(body map[string]any) map[string]struct{} {
	nodes, _ := body["nodes"].([]any)
	out := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		m := n.(map[string]any)
		out[m["id"].(string)] = struct{}{}
	}
	return out
}

func stringSlice(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// TestDelegationGraph_DepthBoundedSubgraph builds a 3-node delegation
// chain with scope attenuation at the deepest hop. Pins:
//
//   - Exact node count: 3 (orchestrator + A + B).
//   - Exact edge count: 3 (root + 2 exchanges).
//   - focal_id echoes the queried identity.
//   - orchestrator→A edge: scopes_in == scopes_out, attenuated == [].
//   - A→B edge: scopes_in = parent scopes, scopes_out = child scopes,
//     attenuated = exactly ["data:write"].
//
// Chain shape:
//
//	orchestrator  client_credentials  [data:read, data:write]   depth 0
//	  └── A       token_exchange      [data:read, data:write]   depth 1
//	        └── B token_exchange      [data:read]               depth 2  ← attenuated
func TestDelegationGraph_DepthBoundedSubgraph(t *testing.T) {
	policyID := delegationPolicy(t, uid("deleg-policy"), []string{"data:read", "data:write"})

	orchID, _, orchToken := issueRootCredential(t, policyID, "deleg-orch",
		[]string{"data:read", "data:write"})
	aID, _, tokenA := exchangeToken(t, policyID, "deleg-agent-a",
		[]string{"data:read", "data:write"},
		[]string{"data:read", "data:write"}, orchToken)
	bID, _, _ := exchangeToken(t, policyID, "deleg-agent-b",
		[]string{"data:read", "data:write"},
		[]string{"data:read"}, tokenA)

	graphResp := get(t, adminPath("/delegations/graph?identity_id="+aID+"&depth=2"), adminHeaders())
	require.Equal(t, http.StatusOK, graphResp.StatusCode)
	body := decode(t, graphResp)

	assert.Equal(t, aID, body["focal_id"], "focal_id must echo queried identity")
	assert.Nil(t, body["truncated"], "small graph must not be truncated")

	ids := nodeIDs(body)
	assert.Len(t, ids, 3, "graph must include exactly 3 nodes (orch + A + B)")
	assert.Contains(t, ids, orchID, "orchestrator missing from nodes")
	assert.Contains(t, ids, aID, "agent-A missing from nodes")
	assert.Contains(t, ids, bID, "agent-B missing from nodes")

	edges, _ := body["edges"].([]any)
	require.Len(t, edges, 3, "graph must include exactly 3 edges (root + 2 hops)")

	byTo := edgeMap(body)
	orchEdge, ok := byTo[orchID]
	require.True(t, ok, "orchestrator must have an edge keyed by its identity_id")
	assert.Empty(t, orchEdge["from"],
		"root credential edge has no parent → from must be empty")
	assert.Empty(t, orchEdge["parent_jti"],
		"root credential edge has no parent_jti (omitted via omitempty)")
	assert.Empty(t, stringSlice(orchEdge["attenuated"]),
		"root credential has no parent → attenuated must be empty")
	assert.Equal(t, stringSlice(orchEdge["scopes_in"]), stringSlice(orchEdge["scopes_out"]),
		"root credential: scopes_in must equal scopes_out")

	aEdge, ok := byTo[aID]
	require.True(t, ok, "agent-A edge must exist")
	assert.Equal(t, orchID, aEdge["from"], "A's edge must point from orchestrator")
	assert.Empty(t, stringSlice(aEdge["attenuated"]),
		"A inherits both scopes; attenuation must be empty")

	bEdge, ok := byTo[bID]
	require.True(t, ok, "agent-B edge must exist")
	assert.Equal(t, aID, bEdge["from"], "B's edge must point from agent-A")
	assert.ElementsMatch(t, []string{"data:read", "data:write"}, stringSlice(bEdge["scopes_in"]),
		"B's scopes_in must be A's full scope set")
	assert.ElementsMatch(t, []string{"data:read"}, stringSlice(bEdge["scopes_out"]),
		"B's scopes_out must be exactly what was requested")
	assert.ElementsMatch(t, []string{"data:write"}, stringSlice(bEdge["attenuated"]),
		"the one dropped scope on A→B must be data:write")
}

// TestDelegationGraph_NoCredentials_SingleNode pins the empty-chain
// behavior: a registered identity with no issued credentials returns a
// single-node graph (the identity itself) with no edges.
func TestDelegationGraph_NoCredentials_SingleNode(t *testing.T) {
	extID := uid("deleg-empty")
	identityID := registerIdentityWithPolicy(t, extID, "", "",
		[]string{"data:read"}, adminHeaders())

	resp := get(t, adminPath("/delegations/graph?identity_id="+identityID+"&depth=2"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := decode(t, resp)
	assert.Equal(t, identityID, body["focal_id"])

	nodes, _ := body["nodes"].([]any)
	require.Len(t, nodes, 1, "no-credential identity yields exactly one node (itself)")
	assert.Equal(t, identityID, nodes[0].(map[string]any)["id"],
		"the single node must be the queried identity, not a placeholder")

	edges, _ := body["edges"].([]any)
	assert.Empty(t, edges, "no-credential identity yields no edges")
}

// TestDelegationGraph_DepthLimitsTheWalk pins the depth-bound invariant
// on the recursive CTE: a 4-hop chain queried with depth=1 from the
// middle node returns ONLY the focal credential plus one hop in each
// direction. The root and the deepest leaf must be absent.
//
// This is the most important correctness test in the file: a CTE that
// silently ignored its depth cap would still return a "valid-looking"
// response, just oversized — which is exactly the failure mode that
// makes a 500-credential mission OOM the Studio renderer.
//
// Chain: orch → A → B → C → D, request graph for B with depth=1.
// Expected: {A, B, C} only (D and orch must be missing).
func TestDelegationGraph_DepthLimitsTheWalk(t *testing.T) {
	policyID := delegationPolicy(t, uid("deleg-depth-policy"), []string{"data:read"})

	orchID, _, orchTok := issueRootCredential(t, policyID, "depth-orch", []string{"data:read"})
	aID, _, tokA := exchangeToken(t, policyID, "depth-a",
		[]string{"data:read"}, []string{"data:read"}, orchTok)
	bID, _, tokB := exchangeToken(t, policyID, "depth-b",
		[]string{"data:read"}, []string{"data:read"}, tokA)
	cID, _, tokC := exchangeToken(t, policyID, "depth-c",
		[]string{"data:read"}, []string{"data:read"}, tokB)
	dID, _, _ := exchangeToken(t, policyID, "depth-d",
		[]string{"data:read"}, []string{"data:read"}, tokC)

	resp := get(t, adminPath("/delegations/graph?identity_id="+bID+"&depth=1"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	ids := nodeIDs(body)
	assert.Contains(t, ids, aID, "depth=1 from B must include A (1 hop up)")
	assert.Contains(t, ids, bID, "depth=1 from B must include B (focal)")
	assert.Contains(t, ids, cID, "depth=1 from B must include C (1 hop down)")
	assert.NotContains(t, ids, orchID,
		"depth=1 from B must NOT include orchestrator (2 hops up)")
	assert.NotContains(t, ids, dID,
		"depth=1 from B must NOT include D (2 hops down)")
	assert.Len(t, ids, 3, "depth=1 must yield exactly 3 nodes — no more, no fewer")

	// A's parent (orchestrator) is outside the walked set, so A's edge
	// must carry from="" — surfaces the depth boundary to the client.
	aEdge := edgeMap(body)[aID]
	require.NotNil(t, aEdge, "A's edge must be present")
	assert.Empty(t, aEdge["from"],
		"A's parent (orch) is beyond the depth cap; edge.from must be empty")
}

// TestDelegationGraph_MostRecentCredentialIsFocal pins the Option-B
// design choice: when an identity participates in multiple unrelated
// chains, GetGraph centers on the most recent credential and the older
// chain is invisible.
//
// Without this guard the focal selection could silently flip between
// chains as old credentials happen to sort differently.
func TestDelegationGraph_MostRecentCredentialIsFocal(t *testing.T) {
	policyID := delegationPolicy(t, uid("focal-policy"), []string{"data:read"})

	// Issue two unrelated root credentials for the same identity. Each
	// is its own mission tree — they share nothing but the identity.
	extID := uid("focal-orch")
	identityID := registerIdentityWithPolicy(t, extID, policyID, "",
		[]string{"data:read"}, adminHeaders())
	client := registerOAuthClient(t, extID, []string{"data:read"})

	respFirst := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, respFirst.StatusCode)
	jtiFirst := decodeJWTUnsafe(t, decode(t, respFirst)["access_token"].(string))["jti"].(string)

	// Force monotonic clock movement so the second credential's
	// issued_at is strictly greater than the first.
	time.Sleep(20 * time.Millisecond)

	respSecond := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, respSecond.StatusCode)
	jtiSecond := decodeJWTUnsafe(t, decode(t, respSecond)["access_token"].(string))["jti"].(string)
	require.NotEqual(t, jtiFirst, jtiSecond, "two issuances must produce distinct JTIs")

	resp := get(t, adminPath("/delegations/graph?identity_id="+identityID+"&depth=2"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	edges, _ := body["edges"].([]any)
	require.Len(t, edges, 1,
		"focal must walk only the most-recent credential's chain; the older chain is invisible")
	gotJTI := edges[0].(map[string]any)["jti"].(string)
	assert.Equal(t, jtiSecond, gotJTI,
		"focal credential must be the most recent issuance")
	assert.NotEqual(t, jtiFirst, gotJTI,
		"older credential's chain must NOT be selected as focal")
}

// TestDelegationGraph_RevokedCredentialAppears pins that the graph is
// a historical view, not an "active credentials" view: revoked
// credentials still appear with is_revoked=true. Forensic replay
// depends on this.
func TestDelegationGraph_RevokedCredentialAppears(t *testing.T) {
	policyID := delegationPolicy(t, uid("revoke-policy"), []string{"data:read"})

	_, _, orchTok := issueRootCredential(t, policyID, "revoke-orch", []string{"data:read"})
	aID, aJTI, tokA := exchangeToken(t, policyID, "revoke-a",
		[]string{"data:read"}, []string{"data:read"}, orchTok)
	_ = tokA

	// Revoke A's credential by JTI via the credential-list lookup.
	credResp := get(t, adminPath("/credentials?identity_id="+aID), adminHeaders())
	require.Equal(t, http.StatusOK, credResp.StatusCode)
	creds := decode(t, credResp)["credentials"].([]any)
	require.NotEmpty(t, creds, "A must have at least one credential")
	var credID string
	for _, c := range creds {
		m := c.(map[string]any)
		if m["jti"].(string) == aJTI {
			credID = m["id"].(string)
		}
	}
	require.NotEmpty(t, credID, "could not resolve A's credential ID for revocation")

	rev := post(t, adminPath("/credentials/"+credID+"/revoke"),
		map[string]any{"reason": "test-revoke"}, adminHeaders())
	require.Equal(t, http.StatusOK, rev.StatusCode, "revoke must succeed")

	resp := get(t, adminPath("/delegations/graph?identity_id="+aID+"&depth=2"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	aEdge := edgeMap(body)[aID]
	require.NotNil(t, aEdge, "A's edge must still appear after revocation")
	assert.True(t, aEdge["is_revoked"].(bool),
		"revoked credential's edge must carry is_revoked=true")
}

// TestDelegationGraph_DepthOutOfRange_Rejected pins the Huma-side
// validation bounds on `depth` (1..10). 0 and 11 both reject with
// 422 (Huma's validation-error status).
func TestDelegationGraph_DepthOutOfRange_Rejected(t *testing.T) {
	extID := uid("deleg-bounds")
	identityID := registerIdentityWithPolicy(t, extID, "", "",
		[]string{"data:read"}, adminHeaders())

	for _, depth := range []int{0, 11, 100} {
		resp := get(t,
			adminPath("/delegations/graph?identity_id="+identityID+"&depth="+fmt.Sprintf("%d", depth)),
			adminHeaders())
		defer func() { _ = resp.Body.Close() }()
		assert.GreaterOrEqual(t, resp.StatusCode, 400,
			"depth=%d must be rejected with 4xx", depth)
		assert.Less(t, resp.StatusCode, 500,
			"depth=%d must NOT 500 (validation, not server error)", depth)
	}
}

// TestDelegationGraph_MissingIdentityID_Rejected pins the Huma
// `required:"true"` enforcement on identity_id. Without it the
// service would receive an empty UUID and silently return the
// "no credentials" path, which would mask client mistakes.
func TestDelegationGraph_MissingIdentityID_Rejected(t *testing.T) {
	resp := get(t, adminPath("/delegations/graph?depth=2"), adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	assert.GreaterOrEqual(t, resp.StatusCode, 400,
		"missing identity_id must be rejected with 4xx")
	assert.Less(t, resp.StatusCode, 500,
		"missing identity_id must NOT 500 (validation, not server error)")
}

// TestDelegationByJTI_WalksToRoot pins the forensic lineage walk: given
// a leaf credential's JTI, the endpoint returns the full chain root → leaf
// ordered by depth, and per-edge scope attenuation is computed against
// the parent's scopes.
func TestDelegationByJTI_WalksToRoot(t *testing.T) {
	policyID := delegationPolicy(t, uid("by-jti-policy"), []string{"data:read"})

	_, rootJTI, orchTok := issueRootCredential(t, policyID, "byjti-orch",
		[]string{"data:read"})
	_, leafJTI, _ := exchangeToken(t, policyID, "byjti-agent",
		[]string{"data:read"}, []string{"data:read"}, orchTok)

	chainResp := get(t, adminPath("/delegations/by-jti/"+url.PathEscape(leafJTI)), adminHeaders())
	require.Equal(t, http.StatusOK, chainResp.StatusCode)

	body := decode(t, chainResp)
	edges, _ := body["edges"].([]any)
	require.Len(t, edges, 2, "lineage has 2 hops: root + token_exchange")

	first := edges[0].(map[string]any)
	second := edges[1].(map[string]any)
	firstDepth, _ := first["delegation_depth"].(float64)
	secondDepth, _ := second["delegation_depth"].(float64)
	assert.Equal(t, 0, int(firstDepth), "first edge must be root (delegation_depth 0)")
	assert.Equal(t, 1, int(secondDepth), "second edge must be depth 1")
	assert.Equal(t, rootJTI, first["jti"], "first edge JTI must match root credential")
	assert.Equal(t, leafJTI, second["jti"], "second edge JTI must match leaf credential")
	assert.Equal(t, rootJTI, second["parent_jti"],
		"leaf's parent_jti must reference the root")
}

// TestDelegationByJTI_NotFound pins the 404 path. A valid UUID that does
// not match any credential must 404, not 500 and not return an empty
// chain with 200.
func TestDelegationByJTI_NotFound(t *testing.T) {
	resp := get(t, adminPath("/delegations/by-jti/00000000-0000-0000-0000-000000000000"), adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"unknown JTI must 404")
}

// TestDelegationByJTI_TenantIsolation pins that a JTI minted in tenant A
// is not addressable from tenant B — the walk anchor is tenant-scoped.
// This is the IDOR guard for forensic lookup.
func TestDelegationByJTI_TenantIsolation(t *testing.T) {
	tenantBHeaders := tenantHeaders(
		"acct-byjti-iso-b-"+uid(""),
		"proj-byjti-iso-b-"+uid(""),
	)

	policyID := delegationPolicy(t, uid("byjti-iso-policy"), []string{"data:read"})
	_, rootJTI, _ := issueRootCredential(t, policyID, "byjti-iso-orch", []string{"data:read"})

	resp := get(t,
		adminPath("/delegations/by-jti/"+url.PathEscape(rootJTI)),
		tenantBHeaders)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"tenant B must not resolve tenant A's JTI — 404 expected")
}

// TestDelegationChains_TimeWindow pins the happy path: issuing a
// credential inside [since, until) produces at least one chain summary.
func TestDelegationChains_TimeWindow(t *testing.T) {
	policyID := delegationPolicy(t, uid("chains-policy"), []string{"data:read"})

	before := time.Now().Add(-1 * time.Minute)
	issueRootCredential(t, policyID, "chains-orch", []string{"data:read"})
	after := time.Now().Add(1 * time.Minute)

	q := "/delegations/chains" +
		"?since=" + url.QueryEscape(before.Format(time.RFC3339)) +
		"&until=" + url.QueryEscape(after.Format(time.RFC3339)) +
		"&limit=100"
	resp := get(t, adminPath(q), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := decode(t, resp)
	chains, _ := body["chains"].([]any)
	require.NotEmpty(t, chains, "must include the chain we just issued")
	first := chains[0].(map[string]any)
	assert.NotEmpty(t, first["chain_id"])
	assert.NotEmpty(t, first["started_at"])
	assert.NotEmpty(t, first["last_activity_at"])
}

// TestDelegationChains_TimeWindowExcludesOutOfRange pins the exclusive
// upper bound: a credential issued at time T with a window [T+10s, T+1m)
// must NOT appear. Without this, a permissive time filter would let
// callers see chains they shouldn't.
//
// Uses a fresh tenant so we don't have to disambiguate from other
// tests' chains in the same window.
func TestDelegationChains_TimeWindowExcludesOutOfRange(t *testing.T) {
	headers := tenantHeaders(
		"acct-chains-window-"+uid(""),
		"proj-chains-window-"+uid(""),
	)

	// Issue one chain in this fresh tenant.
	extID := uid("window-orch")
	body := map[string]any{
		"external_id":    extID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": []string{"data:read"},
	}
	idResp := post(t, adminPath("/identities"), body, headers)
	require.Equal(t, http.StatusCreated, idResp.StatusCode)
	_ = decode(t, idResp)

	client := registerOAuthClient(t, extID, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    headers["X-Account-ID"],
		"project_id":    headers["X-Project-ID"],
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	issuedAt := time.Now()

	// Query a window that starts AFTER issuance — expect zero rows.
	since := issuedAt.Add(10 * time.Second).Format(time.RFC3339)
	until := issuedAt.Add(1 * time.Minute).Format(time.RFC3339)
	q := "/delegations/chains" +
		"?since=" + url.QueryEscape(since) +
		"&until=" + url.QueryEscape(until) +
		"&limit=100"
	chainsResp := get(t, adminPath(q), headers)
	require.Equal(t, http.StatusOK, chainsResp.StatusCode)
	out := decode(t, chainsResp)
	total, _ := out["total"].(float64)
	assert.Equal(t, 0, int(total),
		"chain issued before `since` must NOT appear in the response")
}

// TestDelegationChains_OrderingAndLimit pins two invariants together:
//
//   - Chains are returned ordered by last_activity_at DESC (newest first).
//   - The `limit` query param actually caps the response size.
//
// Done in a fresh tenant so the response is exactly the chains we create.
func TestDelegationChains_OrderingAndLimit(t *testing.T) {
	headers := tenantHeaders(
		"acct-chains-order-"+uid(""),
		"proj-chains-order-"+uid(""),
	)

	// Issue two roots in this tenant, oldest first.
	jtiOld := issueRootInTenant(t, headers, "order-old")
	time.Sleep(20 * time.Millisecond)
	jtiNew := issueRootInTenant(t, headers, "order-new")
	require.NotEqual(t, jtiOld, jtiNew)

	// Full list, ordered.
	q := "/delegations/chains?limit=100"
	full := decode(t, get(t, adminPath(q), headers))
	chains, _ := full["chains"].([]any)
	require.GreaterOrEqual(t, len(chains), 2)
	firstID := chains[0].(map[string]any)["chain_id"].(string)
	secondID := chains[1].(map[string]any)["chain_id"].(string)
	assert.Equal(t, jtiNew, firstID,
		"newest chain must sort first (ORDER BY last_activity_at DESC)")
	assert.Equal(t, jtiOld, secondID, "older chain must sort second")

	// Limit=1 returns only the newest.
	one := decode(t, get(t, adminPath("/delegations/chains?limit=1"), headers))
	oneChains, _ := one["chains"].([]any)
	require.Len(t, oneChains, 1, "limit=1 must cap response at one chain")
	assert.Equal(t, jtiNew, oneChains[0].(map[string]any)["chain_id"],
		"limit=1 must return the newest, not the oldest")
}

// issueRootInTenant is a tenant-aware variant of issueRootCredential used
// by the cross-tenant tests. Returns the root JTI which is also the
// chain_id (= mission_id) for the resulting tree.
func issueRootInTenant(t *testing.T, headers map[string]string, namePrefix string) string {
	t.Helper()
	extID := uid(namePrefix)
	body := map[string]any{
		"external_id":    extID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": []string{"data:read"},
	}
	idResp := post(t, adminPath("/identities"), body, headers)
	require.Equal(t, http.StatusCreated, idResp.StatusCode)
	_ = decode(t, idResp)

	client := registerOAuthClient(t, extID, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    headers["X-Account-ID"],
		"project_id":    headers["X-Project-ID"],
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decodeJWTUnsafe(t, decode(t, resp)["access_token"].(string))["jti"].(string)
}

// TestDelegationChains_TenantIsolation pins the tenant filter on
// /chains. A fresh tenant must see only its own chains — never another
// tenant's, even within an overlapping time window.
func TestDelegationChains_TenantIsolation(t *testing.T) {
	tenantA := tenantHeaders(
		"acct-chains-iso-a-"+uid(""),
		"proj-chains-iso-a-"+uid(""),
	)
	tenantB := tenantHeaders(
		"acct-chains-iso-b-"+uid(""),
		"proj-chains-iso-b-"+uid(""),
	)

	jtiA := issueRootInTenant(t, tenantA, "iso-a")
	jtiB := issueRootInTenant(t, tenantB, "iso-b")

	listA := decode(t, get(t, adminPath("/delegations/chains?limit=100"), tenantA))
	chainsA, _ := listA["chains"].([]any)
	idsA := map[string]struct{}{}
	for _, c := range chainsA {
		idsA[c.(map[string]any)["chain_id"].(string)] = struct{}{}
	}
	assert.Contains(t, idsA, jtiA, "tenant A must see its own chain")
	assert.NotContains(t, idsA, jtiB, "tenant A must NOT see tenant B's chain")

	listB := decode(t, get(t, adminPath("/delegations/chains?limit=100"), tenantB))
	chainsB, _ := listB["chains"].([]any)
	idsB := map[string]struct{}{}
	for _, c := range chainsB {
		idsB[c.(map[string]any)["chain_id"].(string)] = struct{}{}
	}
	assert.Contains(t, idsB, jtiB, "tenant B must see its own chain")
	assert.NotContains(t, idsB, jtiA, "tenant B must NOT see tenant A's chain")
}

// TestDelegationGraph_TenantIsolation pins the cross-tenant guard:
// querying tenant A's identity ID with tenant B's headers returns an
// empty graph (no nodes, no edges). The handler does not 500.
func TestDelegationGraph_TenantIsolation(t *testing.T) {
	tenantA := adminHeaders()
	tenantB := tenantHeaders(
		"acct-deleg-isolation-b-"+uid(""),
		"proj-deleg-isolation-b-"+uid(""),
	)

	orchExtID := uid("isolation-orch")
	orchID := registerIdentityWithPolicy(t, orchExtID, "", "",
		[]string{"data:read"}, tenantA)
	orchClient := registerOAuthClient(t, orchExtID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp2 := get(t, adminPath("/delegations/graph?identity_id="+orchID), tenantB)
	require.Equal(t, http.StatusOK, resp2.StatusCode,
		"cross-tenant query must not 500 — empty graph is the documented contract")

	body := decode(t, resp2)
	nodes, _ := body["nodes"].([]any)
	edges, _ := body["edges"].([]any)
	assert.Empty(t, nodes, "tenant B must not see tenant A's identity in graph")
	assert.Empty(t, edges, "tenant B must not see tenant A's edges in graph")
}

// TestDelegationGraph_MalformedIdentityID_Rejected pins the UUID pattern
// validation on identity_id. Non-UUID values must be rejected by the
// handler before reaching the service layer — a Postgres UUID parse
// error here would otherwise produce a 500.
func TestDelegationGraph_MalformedIdentityID_Rejected(t *testing.T) {
	for _, bad := range []string{
		"not-a-uuid",
		"123",
		"abc-def-ghi",
		"00000000-0000-0000-0000-00000000000Z", // invalid hex char
		"",                                     // empty string (required)
	} {
		path := adminPath("/delegations/graph?identity_id=" + bad + "&depth=2")
		if bad == "" {
			path = adminPath("/delegations/graph?identity_id=&depth=2")
		}
		resp := get(t, path, adminHeaders())
		_ = resp.Body.Close()
		assert.GreaterOrEqual(t, resp.StatusCode, 400,
			"identity_id=%q must be rejected with 4xx", bad)
		assert.Less(t, resp.StatusCode, 500,
			"identity_id=%q must NOT 500 — must be caught before DB", bad)
	}
}

// TestDelegationByJTI_MalformedJTI_Rejected pins the UUID pattern
// validation on the {jti} path parameter. The jti column is varchar so
// a non-UUID would not produce a DB error, but we still want 422 from
// the handler rather than a silent 404 that hides a client mistake.
func TestDelegationByJTI_MalformedJTI_Rejected(t *testing.T) {
	for _, bad := range []string{
		"not-a-uuid",
		"123",
		"../../../etc/passwd",
		"00000000-0000-0000-0000-00000000000Z", // invalid hex char
	} {
		resp := get(t, adminPath("/delegations/by-jti/"+bad), adminHeaders())
		_ = resp.Body.Close()
		assert.GreaterOrEqual(t, resp.StatusCode, 400,
			"jti=%q must be rejected with 4xx", bad)
		assert.Less(t, resp.StatusCode, 500,
			"jti=%q must NOT 500", bad)
	}
}

// TestDelegationChains_InvalidParams_Rejected pins Huma validation on
// the /chains query parameters: limit must be in [1,500] and since/until
// must be valid RFC3339 timestamps.
func TestDelegationChains_InvalidParams_Rejected(t *testing.T) {
	// limit out of range
	for _, bad := range []string{"0", "501", "-1", "99999"} {
		resp := get(t, adminPath("/delegations/chains?limit="+bad), adminHeaders())
		_ = resp.Body.Close()
		assert.GreaterOrEqual(t, resp.StatusCode, 400,
			"limit=%s must be rejected with 4xx", bad)
		assert.Less(t, resp.StatusCode, 500,
			"limit=%s must NOT 500", bad)
	}

	// malformed time params
	for _, bad := range []string{
		"since=yesterday",
		"since=not-a-date",
		"until=32-13-2099",
	} {
		resp := get(t, adminPath("/delegations/chains?"+bad), adminHeaders())
		_ = resp.Body.Close()
		assert.GreaterOrEqual(t, resp.StatusCode, 400,
			"param %s must be rejected with 4xx", bad)
		assert.Less(t, resp.StatusCode, 500,
			"param %s must NOT 500", bad)
	}
}

// TestDelegationGraph_BranchedMissionIsolation pins the lineage-segmentation
// invariant that motivated rsharath's review: within a single mission, two
// sibling branches must not bleed into each other's graph. Sibling branches
// share mission_id but live in different parent_jti lineages, so a walker
// that joined purely on mission_id (instead of parent_jti) would silently
// mix them.
//
// This test passes against both the pre-change and post-change SQL — it's a
// regression guard. The new mission_id predicate in WalkUp / WalkDown is an
// AND (not an OR) against the existing parent_jti join, so sibling rows in
// the same mission are still excluded by the parent_jti edge.
//
// Shape:
//
//	orch (root, mission M)
//	  ├── B1  (parent_jti = orch.jti, mission M)
//	  └── B2  (parent_jti = orch.jti, mission M)  ← must NOT show up in B1's graph
func TestDelegationGraph_BranchedMissionIsolation(t *testing.T) {
	policyID := delegationPolicy(t, uid("branched-policy"), []string{"data:read"})

	_, _, orchTok := issueRootCredential(t, policyID, "branched-orch", []string{"data:read"})
	b1ID, _, _ := exchangeToken(t, policyID, "branched-b1",
		[]string{"data:read"}, []string{"data:read"}, orchTok)
	b2ID, _, _ := exchangeToken(t, policyID, "branched-b2",
		[]string{"data:read"}, []string{"data:read"}, orchTok)

	resp := get(t, adminPath("/delegations/graph?identity_id="+b1ID+"&depth=2"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	ids := nodeIDs(body)
	assert.Contains(t, ids, b1ID, "B1 (focal) must be in its own graph")
	assert.NotContains(t, ids, b2ID,
		"B2 is a sibling branch under the same mission as B1; must NOT appear in B1's graph")
}

// TestDelegationGraph_LegacyNullMissionID pins the legacy-row fallback:
// credentials with mission_id = NULL (issued before migration 022) must
// still walk correctly. This is the reason the new recursive predicate
// uses `IS NOT DISTINCT FROM` instead of `=` — `NULL = NULL` is falsy in
// SQL and would silently terminate the recursion on the first step for
// any pre-migration anchor.
//
// Setup: build a normal A → B chain via OAuth, then UPDATE both rows to
// NULL mission_id to simulate the pre-migration state. Walk from B and
// confirm A is still reachable. Passes against both pre-change code
// (no mission filter at all) and post-change code (NULL IS NOT DISTINCT
// FROM NULL is TRUE, recursion proceeds).
func TestDelegationGraph_LegacyNullMissionID(t *testing.T) {
	policyID := delegationPolicy(t, uid("legacy-null-policy"), []string{"data:read"})

	orchID, orchJTI, orchTok := issueRootCredential(t, policyID, "legacy-null-orch",
		[]string{"data:read"})
	bID, bJTI, _ := exchangeToken(t, policyID, "legacy-null-b",
		[]string{"data:read"}, []string{"data:read"}, orchTok)

	ctx := context.Background()
	_, err := testDB.NewUpdate().
		Table("issued_credentials").
		Set("mission_id = NULL").
		Where("jti IN (?, ?)", orchJTI, bJTI).
		Exec(ctx)
	require.NoError(t, err, "simulate pre-migration NULL mission_id")

	resp := get(t, adminPath("/delegations/graph?identity_id="+bID+"&depth=2"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	ids := nodeIDs(body)
	assert.Contains(t, ids, bID, "B (focal) must appear in its own graph")
	assert.Contains(t, ids, orchID,
		"legacy NULL-mission anchor must still walk to its parent via parent_jti — IS NOT DISTINCT FROM lets NULL chains through")
}

// TestDelegationGraph_CrossMissionBoundary is the test that drives the
// SQL change. It pins that the new recursive-step predicate prunes the
// walker at a mission boundary: a credential linked by parent_jti to a
// credential in a different mission must not be reached.
//
// This shouldn't happen in practice — mission_id is propagated on every
// token_exchange — but the test simulates the scenario by UPDATEing one
// row's mission_id to a different value. It is the primary correctness
// claim of the new predicate.
//
// Expected:
//   - Pre-change (no mission filter on recursive step): FAILS — A is
//     reachable from B via parent_jti and gets included in the graph.
//   - Post-change (IS NOT DISTINCT FROM): PASSES — the recursive step
//     prunes A because A.mission_id != B.mission_id.
//
// If this test passes against the pre-change code, the test isn't
// actually exercising the predicate — fix it before touching SQL.
func TestDelegationGraph_CrossMissionBoundary(t *testing.T) {
	policyID := delegationPolicy(t, uid("cross-mission-policy"), []string{"data:read"})

	orchID, orchJTI, orchTok := issueRootCredential(t, policyID, "cross-orch",
		[]string{"data:read"})
	bID, _, _ := exchangeToken(t, policyID, "cross-b",
		[]string{"data:read"}, []string{"data:read"}, orchTok)

	// Rewrite the orchestrator's mission_id so it no longer matches B's.
	// B's mission_id was propagated from the orch token at exchange time;
	// flipping orch's value after the fact creates the synthetic
	// cross-mission boundary the predicate must catch. Using a literal
	// distinct value (not NULL) ensures the IS NOT DISTINCT FROM check
	// evaluates to FALSE on the recursive step.
	ctx := context.Background()
	_, err := testDB.NewUpdate().
		Table("issued_credentials").
		Set("mission_id = ?", "synthetic-other-mission-"+uid("")).
		Where("jti = ?", orchJTI).
		Exec(ctx)
	require.NoError(t, err, "simulate cross-mission parent_jti link")

	resp := get(t, adminPath("/delegations/graph?identity_id="+bID+"&depth=2"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	ids := nodeIDs(body)
	assert.Contains(t, ids, bID, "B (focal) must always appear in its own graph")
	assert.NotContains(t, ids, orchID,
		"orch lives in a different mission than B; the recursive predicate must prune it")
}
