package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the subagent-delegation half of epic slice S9 (T5,
// highflame-ai/highflame-architecture#138): a parent code-agent's delegated
// token plus a child subagent's signed assertion are exchanged via
// token_exchange (RFC 8693) for an ATTENUATED child token. They assert the
// CAP-IDN-018 attenuation invariants specifically for the coding-agent scope
// vocabulary (tools:*), on top of the generic delegation coverage in
// delegation_test.go:
//
//   - child scopes = requested ∩ parent.granted ∩ child-policy.allowed
//     (monotonic — a child can never hold a scope its parent lacks),
//   - delegation_depth = parent.depth + 1, capped by the child credential
//     policy's max_delegation_depth,
//   - parent_jti references the parent credential, mission_id is inherited,
//   - the act chain records the delegating parent (act.sub = parent.sub).
//
// The attenuation logic lives in OAuthService.tokenExchange +
// CredentialService.IssueCredential + CredentialPolicyService.EnforcePolicy;
// these tests are black-box regression coverage that it holds end-to-end for
// the code-agent case. Tool-scope strings are used as literals here (as in
// id_jag_test.go). The canonical tool-scope vocabulary lives in
// highflame-policy (codegen'd), consumed by Shield/Guardian.

// attemptSubagentExchange registers a fresh child subagent identity bound to
// policyID, then performs a token_exchange WITHOUT asserting success — so
// rejection-path tests can inspect the OAuth error. Mirrors the exchangeToken
// helper in delegation_test.go minus the 200 assertion.
func attemptSubagentExchange(t *testing.T, policyID, namePrefix string, childAllowedScopes, requestedScopes []string, parentToken string) *http.Response {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	extID := uid(namePrefix)
	registerIdentityWithPolicy(t, extID, policyID, ecPublicKeyPEM(t, key), childAllowedScopes, adminHeaders())
	wimse := fetchIdentityWIMSEByExternalID(t, extID)
	return post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": parentToken,
		"actor_token":   buildAssertion(t, key, wimse),
		"scope":         scopesToString(requestedScopes),
	}, nil)
}

// TestSubagentDelegation_AttenuatedChildToken is the happy path. A parent
// holding [tools:read, tools:write] delegates to a subagent that requests only
// [tools:read]. The child token must be strictly reduced and carry the
// inherited delegation lineage.
func TestSubagentDelegation_AttenuatedChildToken(t *testing.T) {
	policyID := delegationPolicy(t, uid("s9-attn-cp"), []string{"tools:read", "tools:write"})

	_, rootJTI, rootTok := issueRootCredential(t, policyID, "s9-attn-root",
		[]string{"tools:read", "tools:write"})

	_, childJTI, childTok := exchangeToken(t, policyID, "s9-attn-child",
		[]string{"tools:read", "tools:write"}, // child scope ceiling (superset of what it asks for)
		[]string{"tools:read"},                // requested: strictly fewer than the parent holds
		rootTok)
	require.NotEmpty(t, childJTI)

	parent := decodeJWTUnsafe(t, rootTok)
	child := decodeJWTUnsafe(t, childTok)

	parentScopes := stringSlice(parent["scopes"])
	childScopes := stringSlice(child["scopes"])

	// Scopes strictly reduced: child ⊊ parent.
	assert.ElementsMatch(t, []string{"tools:read", "tools:write"}, parentScopes,
		"parent must hold both scopes")
	assert.ElementsMatch(t, []string{"tools:read"}, childScopes,
		"child scopes must be exactly the requested subset")
	parentSet := make(map[string]struct{}, len(parentScopes))
	for _, s := range parentScopes {
		parentSet[s] = struct{}{}
	}
	for _, s := range childScopes {
		_, ok := parentSet[s]
		assert.True(t, ok, "child scope %q must be present in the parent (monotonic attenuation)", s)
	}
	assert.Less(t, len(childScopes), len(parentScopes),
		"child scope set must be STRICTLY reduced, not merely a subset")

	// delegation_depth = parent.depth + 1. The root credential omits the
	// delegation_depth claim entirely (depth 0 via omitempty), so the child is
	// the first delegated hop at depth 1.
	_, hasParentDepth := parent["delegation_depth"]
	assert.False(t, hasParentDepth, "root credential must not carry a delegation_depth claim (depth 0)")
	childDepth, ok := child["delegation_depth"].(float64)
	require.True(t, ok, "child token must carry a numeric delegation_depth")
	assert.Equal(t, 1, int(childDepth), "child delegation_depth must be parent.depth(0) + 1")

	// parent_jti is recorded on the credential lineage (not embedded as a JWT
	// claim) and surfaced through the delegation graph. Assert it via the
	// by-jti walk: the child's edge must reference the parent (root) jti.
	assert.Equal(t, rootJTI, parent["jti"], "sanity: root token jti must equal the returned rootJTI")
	chainResp := get(t, adminPath("/delegations/by-jti/"+url.PathEscape(childJTI)), adminHeaders())
	require.NotNil(t, chainResp)
	defer func() { _ = chainResp.Body.Close() }()
	require.Equal(t, http.StatusOK, chainResp.StatusCode)
	chain := decode(t, chainResp)
	edges, _ := chain["edges"].([]any)
	require.Len(t, edges, 2, "child lineage has 2 hops: root + token_exchange")
	childEdge := edges[1].(map[string]any)
	assert.Equal(t, rootJTI, childEdge["parent_jti"],
		"child credential's parent_jti must reference the parent (root) credential")

	// mission_id inherited (denormalised down the tree). For a root credential
	// mission_id defaults to its own jti; the child must inherit that value.
	require.NotEmpty(t, parent["mission_id"], "parent must carry a mission_id")
	assert.Equal(t, parent["mission_id"], child["mission_id"],
		"child must inherit the parent's mission_id")

	// act chain records the delegating parent (RFC 8693 §4.1).
	act, ok := child["act"].(map[string]any)
	require.True(t, ok, "child token must carry an act claim")
	require.NotEmpty(t, parent["sub"], "parent must carry a sub")
	assert.Equal(t, parent["sub"], act["sub"],
		"child act.sub must reference the delegating parent's sub")
}

// TestSubagentDelegation_OverBroadScopeRejected proves the parent ceiling is
// authoritative: a subagent cannot escalate to a scope its parent never held,
// EVEN when the subagent's own credential policy would allow that scope. The
// parent holds only [tools:read]; the child (policy allows [tools:read,
// tools:write]) asks for [tools:write] → the intersection is empty → the
// exchange is rejected.
func TestSubagentDelegation_OverBroadScopeRejected(t *testing.T) {
	rootPolicy := delegationPolicy(t, uid("s9-esc-root-cp"), []string{"tools:read"})
	_, _, rootTok := issueRootCredential(t, rootPolicy, "s9-esc-root", []string{"tools:read"})

	// Child policy is broader than the parent — this is the escalation attempt
	// that must still fail because the parent lacks tools:write.
	childPolicy := delegationPolicy(t, uid("s9-esc-child-cp"), []string{"tools:read", "tools:write"})

	resp := attemptSubagentExchange(t, childPolicy, "s9-esc-child",
		[]string{"tools:read", "tools:write"}, // child ceiling permits write…
		[]string{"tools:write"},               // …but the parent never held it
		rootTok)
	require.NotNil(t, resp)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"an over-broad child request must be rejected, not silently granted")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"],
		"requesting a scope the parent lacks must yield invalid_scope")
}

// TestSubagentDelegation_EmptyRequestGrantsNothing pins the least-privilege
// default that replaces the (dropped) persona catalog: a subagent that requests
// NO scopes gets NONE — it never silently inherits the parent's grant. The
// guarantee is structural (child scopes = requested ∩ parent ∩ child-policy;
// an empty request makes the intersection empty), so it holds without any
// persona/preset machinery. This is the safety property the "one credential
// policy for all code agents" decision relies on.
func TestSubagentDelegation_EmptyRequestGrantsNothing(t *testing.T) {
	rootPolicy := delegationPolicy(t, uid("s9-empty-root-cp"), []string{"tools:read", "tools:execute"})
	_, _, rootTok := issueRootCredential(t, rootPolicy, "s9-empty-root", []string{"tools:read", "tools:execute"})

	// The child's own policy would allow tools:read, but it requests nothing.
	childPolicy := delegationPolicy(t, uid("s9-empty-child-cp"), []string{"tools:read"})
	resp := attemptSubagentExchange(t, childPolicy, "s9-empty-child",
		[]string{"tools:read"}, // child ceiling permits read…
		[]string{},             // …but the subagent requests no scopes at all
		rootTok)
	require.NotNil(t, resp)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a subagent requesting no scopes must be rejected, not granted the parent's scopes")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"],
		"empty scope request yields invalid_scope — least privilege by construction")
}

// TestSubagentDelegation_DepthCapRejected proves the child credential policy's
// max_delegation_depth caps chain depth. With a policy capped at depth 1:
// root (depth 0) → A (depth 1, allowed) → B (depth 2, rejected).
func TestSubagentDelegation_DepthCapRejected(t *testing.T) {
	capPolicy := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("s9-depthcap-cp"),
		"allowed_grant_types":  []string{"client_credentials", "token_exchange"},
		"allowed_scopes":       []string{"tools:read"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	_, _, rootTok := issueRootCredential(t, capPolicy, "s9-depth-root", []string{"tools:read"})

	// Depth 1 is within the cap — succeeds.
	_, _, tokA := exchangeToken(t, capPolicy, "s9-depth-a",
		[]string{"tools:read"}, []string{"tools:read"}, rootTok)

	// Depth 2 exceeds the child policy's max_delegation_depth (1) — rejected.
	resp := attemptSubagentExchange(t, capPolicy, "s9-depth-b",
		[]string{"tools:read"}, []string{"tools:read"}, tokA)
	require.NotNil(t, resp)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a delegation depth exceeding the child policy's max_delegation_depth must be rejected")
	body := decode(t, resp)
	assert.Equal(t, "policy_violation", body["error"],
		"exceeding max_delegation_depth must surface as a policy_violation")
}
