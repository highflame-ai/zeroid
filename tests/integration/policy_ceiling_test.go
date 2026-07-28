package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the security finding that IssueCredential — documented as
// "the authoritative chokepoint" — was a no-op whenever its caller didn't
// supply IdentityPolicyID. Three issuance paths did exactly that:
// RotateCredential, the admin /credentials/issue handler, and post-attestation
// verification. The fix makes the chokepoint resolve the identity's policy
// itself when none is passed, so a since-tightened ceiling is enforced on
// every path, not just the OAuth grants that happened to resolve it.
//
// Each test below would PASS (i.e. the bypass would succeed) if the fix were
// reverted — that's the property that makes them regression coverage rather
// than mere happy-path checks.

// seedCredential issues an initial credential for identityID via the admin
// path and returns its credential ID. Used to seed a rotation target.
func seedCredential(t *testing.T, identityID string, ttlSeconds int, scopes []string) string {
	t.Helper()
	body := map[string]any{
		"identity_id": identityID,
		"grant_type":  "client_credentials",
	}
	if ttlSeconds > 0 {
		body["ttl_seconds"] = ttlSeconds
	}
	if len(scopes) > 0 {
		body["scopes"] = scopes
	}
	resp := post(t, adminPath("/credentials/issue"), body, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode, "seedCredential: initial issue must succeed under permissive policy")
	cred := decode(t, resp)["credential"].(map[string]any)
	id, ok := cred["id"].(string)
	require.True(t, ok, "seedCredential: response missing credential id")
	require.NotEmpty(t, id)
	return id
}

// TestPolicyCeiling_RotateEnforcesTightenedTTL is the load-bearing regression
// for the RotateCredential bypass. Sequence:
//
//  1. Permissive policy (max_ttl=3600). Identity bound to it.
//  2. Seed a credential with TTL=3600 — succeeds (within policy).
//  3. Admin tightens the policy to max_ttl=60.
//  4. Rotate the seeded credential. RotateCredential re-mints with the OLD
//     TTL (3600), which now exceeds the tightened ceiling.
//
// Pre-fix: rotate left IdentityPolicyID empty, the chokepoint skipped policy
// enforcement entirely, and the rotate succeeded — re-minting a 3600s token
// the security team had since capped at 60s. Post-fix: the chokepoint resolves
// the (now-tightened) policy and rejects the over-TTL re-issue.
func TestPolicyCeiling_RotateEnforcesTightenedTTL(t *testing.T) {
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ceiling-rotate-ttl-cp"),
		"allowed_grant_types":  []string{"client_credentials"},
		"max_ttl_seconds":      3600,
		"max_delegation_depth": 1,
	}, adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("ceiling-rotate-ttl"), policyID, "", nil, adminHeaders())

	credID := seedCredential(t, identityID, 3600, nil)

	// Tighten the ceiling well below the seeded credential's TTL.
	patchCredentialPolicy(t, policyID, map[string]any{
		"max_ttl_seconds": 60,
	}, adminHeaders())

	resp := post(t, adminPath("/credentials/"+credID+"/rotate"), nil, adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	assert.NotEqual(t, http.StatusCreated, resp.StatusCode,
		"rotate must NOT re-mint a credential whose inherited TTL exceeds the since-tightened policy ceiling")
	assert.GreaterOrEqual(t, resp.StatusCode, 400,
		"rotate against a tightened TTL ceiling must fail, not silently re-issue the old TTL")
}

// TestPolicyCeiling_RotateEnforcesGrantType pins the grant-type axis on the
// rotate path. The seeded credential is client_credentials; after the policy
// is tightened to forbid that grant type, rotation (which re-mints with the
// old grant type) must be rejected at the chokepoint.
func TestPolicyCeiling_RotateEnforcesGrantType(t *testing.T) {
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ceiling-rotate-gt-cp"),
		"allowed_grant_types":  []string{"client_credentials"},
		"max_ttl_seconds":      3600,
		"max_delegation_depth": 1,
	}, adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("ceiling-rotate-gt"), policyID, "", nil, adminHeaders())

	credID := seedCredential(t, identityID, 600, nil)

	// Tighten: drop client_credentials from the allow-list (only token_exchange
	// permitted now). The seeded credential's grant type is no longer allowed.
	patchCredentialPolicy(t, policyID, map[string]any{
		"allowed_grant_types": []string{"token_exchange"},
	}, adminHeaders())

	resp := post(t, adminPath("/credentials/"+credID+"/rotate"), nil, adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	assert.GreaterOrEqual(t, resp.StatusCode, 400,
		"rotate must be rejected when the inherited grant type is no longer permitted by the tightened policy")
}

// TestPolicyCeiling_AdminIssueEnforcesTightenedTTL pins the admin
// /credentials/issue path. The handler clamps TTL only against the
// service-wide maxTTL (90 days in the test config), NOT the identity's policy
// — so before the fix an operator could request a 3600s token against an
// identity whose policy caps TTL at 60s and the chokepoint would let it
// through. Post-fix the resolved policy rejects it.
func TestPolicyCeiling_AdminIssueEnforcesTightenedTTL(t *testing.T) {
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ceiling-issue-ttl-cp"),
		"allowed_grant_types":  []string{"client_credentials"},
		"max_ttl_seconds":      60,
		"max_delegation_depth": 1,
	}, adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("ceiling-issue-ttl"), policyID, "", nil, adminHeaders())

	// Request a TTL above the policy ceiling (60s) but well below the
	// service maxTTL (90 days), so only policy enforcement can reject it.
	resp := post(t, adminPath("/credentials/issue"), map[string]any{
		"identity_id": identityID,
		"grant_type":  "client_credentials",
		"ttl_seconds": 3600,
	}, adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	assert.NotEqual(t, http.StatusCreated, resp.StatusCode,
		"admin issue must NOT mint a token whose TTL exceeds the identity policy ceiling")
	assert.GreaterOrEqual(t, resp.StatusCode, 400,
		"admin issue against an over-TTL request must fail at the policy ceiling")
}

// TestPolicyCeiling_AdminIssueEnforcesGrantType pins the grant-type axis on
// the admin issue path: requesting a grant type the identity's policy forbids
// must be rejected even though the admin handler itself does no grant-type
// check.
func TestPolicyCeiling_AdminIssueEnforcesGrantType(t *testing.T) {
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ceiling-issue-gt-cp"),
		"allowed_grant_types":  []string{"token_exchange"},
		"max_ttl_seconds":      3600,
		"max_delegation_depth": 1,
	}, adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("ceiling-issue-gt"), policyID, "", nil, adminHeaders())

	// Policy permits only token_exchange; request client_credentials.
	resp := post(t, adminPath("/credentials/issue"), map[string]any{
		"identity_id": identityID,
		"grant_type":  "client_credentials",
		"ttl_seconds": 60,
	}, adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	assert.GreaterOrEqual(t, resp.StatusCode, 400,
		"admin issue must reject a grant type the identity policy forbids")
}

// TestPolicyCeiling_NoPolicyStillIssues is the don't-fail-closed guard. An
// identity bound to the tenant default policy (the normal case when no
// explicit policy is configured) must still issue and rotate cleanly with a
// reasonable TTL — the chokepoint's self-resolution must fall back to the
// permissive default exactly as ResolveCredentialPolicy does, never reject a
// tenant that simply never set a custom policy.
func TestPolicyCeiling_NoPolicyStillIssues(t *testing.T) {
	// Omit credential_policy_id → identity is bound to the tenant default.
	identityID := registerIdentityWithPolicy(t, uid("ceiling-no-policy"), "", "", nil, adminHeaders())

	resp := post(t, adminPath("/credentials/issue"), map[string]any{
		"identity_id": identityID,
		"grant_type":  "client_credentials",
		"ttl_seconds": 600,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"identity with no custom policy must still issue under the permissive tenant default")
	credID := decode(t, resp)["credential"].(map[string]any)["id"].(string)
	require.NotEmpty(t, credID)

	// And rotation of that credential must also succeed — the chokepoint's
	// self-resolution must not turn the default-policy case into a rejection.
	rotateResp := post(t, adminPath("/credentials/"+credID+"/rotate"), nil, adminHeaders())
	require.Equal(t, http.StatusCreated, rotateResp.StatusCode,
		"rotating a credential under the permissive tenant default must succeed")
	rotateResp.Body.Close()
}
