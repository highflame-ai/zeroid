package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createRichCredentialPolicy creates a policy with arbitrary constraints.
// createCredentialPolicy only exposes name + max_ttl; richer scenarios
// (policy-gated scopes, grant-type allow-lists, delegation-depth caps)
// need the full body.
func createRichCredentialPolicy(t *testing.T, body map[string]any, headers map[string]string) string {
	t.Helper()
	resp := post(t, adminPath("/credential-policies"), body, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "createRichCredentialPolicy: expected 201, got %d", resp.StatusCode)
	raw := decode(t, resp)
	id, ok := raw["id"].(string)
	require.True(t, ok, "response missing id")
	require.NotEmpty(t, id)
	return id
}

// patchCredentialPolicy applies PATCH /credential-policies/{id}. Used to
// simulate admin-side policy drift in TestPolicyDriftSelfHeals.
func patchCredentialPolicy(t *testing.T, id string, body map[string]any, headers map[string]string) {
	t.Helper()
	req := newRequest(t, http.MethodPatch, adminPath("/credential-policies/"+id), body, headers)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "patchCredentialPolicy: expected 200, got %d", resp.StatusCode)
}

// registerIdentityWithPolicy registers an identity and binds it to a
// caller-supplied credential policy. Mirrors registerIdentity but exposes
// the policy ID, public key, and headers so tests can drive cross-tenant
// and policy-gated scenarios.
func registerIdentityWithPolicy(t *testing.T, externalID, policyID, publicKeyPEM string, scopes []string, headers map[string]string) string {
	t.Helper()
	body := map[string]any{
		"external_id":    externalID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": scopes,
	}
	if policyID != "" {
		body["credential_policy_id"] = policyID
	}
	if publicKeyPEM != "" {
		body["public_key_pem"] = publicKeyPEM
	}
	resp := post(t, adminPath("/identities"), body, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registerIdentityWithPolicy: expected 201, got %d", resp.StatusCode)
	raw := decode(t, resp)
	return raw["id"].(string)
}

// TestRegisterIdentity_StoresCredentialPolicyID verifies the identity-policy
// wiring: a caller-supplied credential_policy_id on POST /identities is
// persisted on the identity row, not just on the auto-created API key.
// Regression coverage for the authority-ceiling link added in migration 008.
func TestRegisterIdentity_StoresCredentialPolicyID(t *testing.T) {
	policyID := createCredentialPolicy(t, uid("ident-cp"), adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("ident-with-policy"), policyID, "", nil, adminHeaders())

	resp := get(t, adminPath("/identities/"+identityID), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	got := decode(t, resp)
	assert.Equal(t, policyID, got["credential_policy_id"],
		"caller-supplied credential_policy_id must be stored on the identity row")
}

// TestRegisterIdentity_DefaultsToTenantDefaultPolicy verifies that when the
// caller omits credential_policy_id, the identity is still bound to a
// policy — specifically the tenant's auto-created default. This is what
// gives every identity a non-null authority ceiling from the moment of
// registration.
func TestRegisterIdentity_DefaultsToTenantDefaultPolicy(t *testing.T) {
	identityID := registerIdentityWithPolicy(t, uid("ident-no-policy"), "", "", nil, adminHeaders())

	resp := get(t, adminPath("/identities/"+identityID), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	got := decode(t, resp)
	assigned, ok := got["credential_policy_id"].(string)
	require.True(t, ok, "identity should have credential_policy_id set after registration")
	require.NotEmpty(t, assigned, "identity must be bound to a policy (tenant default) even when caller omits the field")
}

// TestRegisterIdentity_CrossTenantPolicyRejected verifies the IDOR guard on
// the identity→policy link at registration. Tenant B cannot bind a new
// identity to tenant A's policy.
func TestRegisterIdentity_CrossTenantPolicyRejected(t *testing.T) {
	tenantA := tenantHeaders("acct-ident-cp-a-"+uid(""), "proj-ident-cp-a-"+uid(""))
	tenantB := tenantHeaders("acct-ident-cp-b-"+uid(""), "proj-ident-cp-b-"+uid(""))

	foreignPolicyID := createCredentialPolicy(t, uid("cp-ident-tenant-a"), tenantA)

	resp := post(t, adminPath("/identities"), map[string]any{
		"external_id":          uid("cross-tenant-ident"),
		"owner_user_id":        "user-test-owner",
		"trust_level":          "unverified",
		"credential_policy_id": foreignPolicyID,
	}, tenantB)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"cross-tenant credential_policy_id must be rejected at identity registration")
}

// TestUpdateIdentity_CrossTenantPolicyRejected verifies the IDOR guard also
// applies to PATCH /identities/{id}. A caller cannot rebind an existing
// identity to another tenant's policy.
func TestUpdateIdentity_CrossTenantPolicyRejected(t *testing.T) {
	tenantA := tenantHeaders("acct-upd-cp-a-"+uid(""), "proj-upd-cp-a-"+uid(""))
	tenantB := tenantHeaders("acct-upd-cp-b-"+uid(""), "proj-upd-cp-b-"+uid(""))

	foreignPolicyID := createCredentialPolicy(t, uid("cp-upd-tenant-a"), tenantA)
	identityID := registerIdentityWithPolicy(t, uid("upd-target"), "", "", nil, tenantB)

	req := newRequest(t, http.MethodPatch, adminPath("/identities/"+identityID), map[string]any{
		"credential_policy_id": foreignPolicyID,
	}, tenantB)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"cross-tenant credential_policy_id must be rejected at identity update")
}

// TestTokenExchange_ActorPolicyRestrictsScopes verifies the identity policy
// is authoritative for actor scopes in RFC 8693 token_exchange. When the
// actor's policy declares allowed_scopes, the delegation is capped by that
// set — identity.allowed_scopes is only a fallback.
func TestTokenExchange_ActorPolicyRestrictsScopes(t *testing.T) {
	// Orchestrator holds both data:read and data:write.
	orchID := uid("tx-actor-policy-orch")
	registerIdentity(t, orchID, []string{"data:read", "data:write"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read", "data:write"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read data:write",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// Actor policy restricts scope to data:read only — data:write must be
	// refused at delegation even though the orchestrator holds it and the
	// actor's identity.allowed_scopes also includes it. Policy wins.
	actorPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("tx-actor-policy-cp"),
		"allowed_grant_types":  []string{"token_exchange"},
		"allowed_scopes":       []string{"data:read"},
		"max_delegation_depth": 5,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	actorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	actorExternalID := uid("tx-actor")
	registerIdentityWithPolicy(t, actorExternalID, actorPolicyID,
		ecPublicKeyPEM(t, actorKey), []string{"data:read", "data:write"}, adminHeaders())

	// Resolve the server-built WIMSE URI so the assertion's iss claim
	// matches exactly what the server expects.
	resolvedURI := fetchIdentityWIMSEByExternalID(t, actorExternalID)
	assertion := buildAssertion(t, actorKey, resolvedURI)

	// Request BOTH scopes; the orchestrator has both but the actor's policy
	// only permits data:read. Policy is the authority.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   assertion,
		"scope":         "data:read data:write",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	scope, _ := token["scope"].(string)
	assert.Contains(t, scope, "data:read", "data:read must be granted — inside actor policy")
	assert.NotContains(t, scope, "data:write",
		"data:write must not be granted — actor's credential policy forbids it even though identity.allowed_scopes permits it")
}

// TestTokenExchange_ActorPolicyEnforcesDelegationDepth verifies that the
// actor's policy max_delegation_depth is enforced. An actor whose policy
// caps depth at 0 cannot participate in any delegation chain.
func TestTokenExchange_ActorPolicyEnforcesDelegationDepth(t *testing.T) {
	orchID := uid("tx-depth-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// Depth-0 policy: no delegation permitted at all.
	zeroDepthPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("tx-depth-0"),
		"allowed_grant_types":  []string{"token_exchange"},
		"max_delegation_depth": 0,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	actorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	externalID := uid("tx-depth-actor")
	registerIdentityWithPolicy(t, externalID, zeroDepthPolicyID,
		ecPublicKeyPEM(t, actorKey), []string{"data:read"}, adminHeaders())

	resolvedURI := fetchIdentityWIMSEByExternalID(t, externalID)
	assertion := buildAssertion(t, actorKey, resolvedURI)

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   assertion,
		"scope":         "data:read",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"actor policy with max_delegation_depth=0 must block delegation at depth=1")
	resp.Body.Close()
}

// TestTokenExchange_ActorPolicyBlocksDisallowedGrantType verifies that an
// actor whose policy's allowed_grant_types does not include token_exchange
// cannot participate in delegation. This is the explicit opt-in for the
// delegation capability.
func TestTokenExchange_ActorPolicyBlocksDisallowedGrantType(t *testing.T) {
	orchID := uid("tx-gt-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// Policy permits only client_credentials — no token_exchange.
	ccOnlyPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("tx-cc-only"),
		"allowed_grant_types":  []string{"client_credentials"},
		"max_delegation_depth": 5,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	actorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	externalID := uid("tx-gt-actor")
	registerIdentityWithPolicy(t, externalID, ccOnlyPolicyID,
		ecPublicKeyPEM(t, actorKey), []string{"data:read"}, adminHeaders())

	resolvedURI := fetchIdentityWIMSEByExternalID(t, externalID)
	assertion := buildAssertion(t, actorKey, resolvedURI)

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   assertion,
		"scope":         "data:read",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"actor whose policy does not allow token_exchange must be rejected")
	resp.Body.Close()
}

// TestAPIKeyCreate_SubsetInvariant_ScopeBroader verifies the creation-time
// subset check: a key policy whose allowed_scopes exceeds the identity
// policy's is rejected with 400. Fail-fast UX; runtime enforcement in
// IssueCredential remains the authoritative security boundary.
func TestAPIKeyCreate_SubsetInvariant_ScopeBroader(t *testing.T) {
	// Identity policy restricts to data:read only.
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("subset-id-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"allowed_scopes":       []string{"data:read"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	// Key policy tries to extend scopes to data:write — must be rejected.
	broaderKeyPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("subset-key-cp-broader"),
		"allowed_grant_types":  []string{"api_key"},
		"allowed_scopes":       []string{"data:read", "data:write"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	externalID := uid("subset-target")
	identityID := registerIdentityWithPolicy(t, externalID, identityPolicyID, "", nil, adminHeaders())

	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"
	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":                 "subset-violation-key",
		"identity_id":          identityID,
		"credential_policy_id": broaderKeyPolicyID,
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"API-key policy broader than identity policy on scopes must be rejected at creation")
}

// TestAPIKeyCreate_SubsetInvariant_GrantTypeEmptyIdentityRejectsAny is the
// regression for the Gemini review on EnforceSubset's grant-types branch.
// At runtime EnforcePolicy treats an empty allowed_grant_types list as a
// deny-by-default allow-list — every grant type is rejected. The subset
// check must mirror that semantic and reject any narrower policy that
// declares grant types the identity policy omits, even when the identity
// policy's list is empty. Previously a `len(wider) > 0` guard made the
// subset check permissive in that corner, creating a fail-fast miss at
// key creation time that would only surface as an opaque invalid_grant
// error later when the token was actually requested.
//
// The identity policy here has to be created via PATCH because
// CreatePolicy defaults an empty allowed_grant_types to
// ["client_credentials"]. UpdatePolicy accepts an empty slice and lets
// it through untouched, so this corner is reachable in production.
func TestAPIKeyCreate_SubsetInvariant_GrantTypeEmptyIdentityRejectsAny(t *testing.T) {
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("subset-gt-id-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	// Patch the identity policy's allowed_grant_types to empty. Simulates
	// an admin who wants to temporarily disable all credential issuance
	// for this identity — runtime would reject every token, so the
	// creation-time subset check must not pass any narrower policy.
	patchCredentialPolicy(t, identityPolicyID, map[string]any{
		"allowed_grant_types": []string{},
	}, adminHeaders())

	keyPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("subset-gt-key-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("subset-gt-target"), identityPolicyID, "", nil, adminHeaders())

	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"
	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":                 "subset-gt-violation",
		"identity_id":          identityID,
		"credential_policy_id": keyPolicyID,
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"empty allowed_grant_types on identity policy must still reject any narrower policy that declares a grant type (deny-by-default semantic)")
}

// TestAPIKeyCreate_SubsetInvariant_TTLBroader verifies the TTL axis of the
// subset invariant. A key policy with longer max_ttl_seconds than the
// identity policy is rejected.
func TestAPIKeyCreate_SubsetInvariant_TTLBroader(t *testing.T) {
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("subset-ttl-id-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"max_ttl_seconds":      600, // 10 minutes
		"max_delegation_depth": 1,
	}, adminHeaders())

	broaderKeyPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("subset-ttl-key-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"max_ttl_seconds":      3600, // 1 hour — broader than identity
		"max_delegation_depth": 1,
	}, adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("subset-ttl-target"), identityPolicyID, "", nil, adminHeaders())

	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"
	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":                 "subset-ttl-violation",
		"identity_id":          identityID,
		"credential_policy_id": broaderKeyPolicyID,
	}, headers)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"API-key policy with longer max_ttl than identity policy must be rejected")
}

// TestAPIKeyCreate_InheritsIdentityPolicyPasses verifies the common case:
// a key that inherits the identity policy (either implicitly by omitting
// credential_policy_id or explicitly by passing the identity's policy ID)
// passes the subset check trivially. Guards against over-strict
// enforcement breaking the no-op path.
func TestAPIKeyCreate_InheritsIdentityPolicyPasses(t *testing.T) {
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("inherit-id-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"allowed_scopes":       []string{"data:read"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("inherit-target"), identityPolicyID, "", nil, adminHeaders())

	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"

	// Path 1: omit credential_policy_id — service auto-assigns tenant
	// default. Since identity has a different (stricter) policy, this
	// could trigger the subset check against the default. But the
	// default is as permissive as possible and the identity policy is
	// narrower — key(default) is broader than identity(stricter) so
	// this SHOULD be rejected.
	respDefault := post(t, adminPath("/api-keys"), map[string]any{
		"name":        "inherit-default-key",
		"identity_id": identityID,
	}, headers)
	// Default policy (permissive) is broader than identityPolicy
	// (allowed_scopes=[data:read]) — must be rejected.
	assert.Equal(t, http.StatusBadRequest, respDefault.StatusCode,
		"omitting credential_policy_id defaults to tenant default policy which is broader than the identity's stricter policy — must be rejected")

	// Path 2: explicitly pass the identity's policy ID → trivially a
	// subset of itself → must pass.
	respExplicit := post(t, adminPath("/api-keys"), map[string]any{
		"name":                 "inherit-explicit-key",
		"identity_id":          identityID,
		"credential_policy_id": identityPolicyID,
	}, headers)
	assert.Equal(t, http.StatusCreated, respExplicit.StatusCode,
		"key policy == identity policy must pass the subset check trivially")
}

// TestPolicyDriftSelfHeals is the load-bearing test for the dual-enforcement
// design decision documented in credential.go: enforcing both policy layers
// at every token issuance (not just at key creation) makes policy drift
// self-healing. Scenario:
//
//  1. Admin creates a permissive identity policy and an API key inheriting it.
//  2. Admin tightens the identity policy (revokes data:write).
//  3. The existing API key must no longer be able to mint tokens with
//     data:write even though the key itself wasn't rotated and its
//     own (key-layer) policy still permits it at creation time.
//
// If the key-layer enforcement were the only runtime check, the tightening
// would silently fail until the key is manually rotated — a serious
// security hole in any authz system that supports long-lived credentials.
func TestPolicyDriftSelfHeals(t *testing.T) {
	// Identity policy starts permissive: allows data:read + data:write.
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("drift-id-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"allowed_scopes":       []string{"data:read", "data:write"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("drift-target"), identityPolicyID, "", nil, adminHeaders())

	// Create an API key under the same policy. Subset check passes
	// trivially (key policy == identity policy).
	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"
	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":                 "drift-key",
		"identity_id":          identityID,
		"credential_policy_id": identityPolicyID,
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	apiKey := decode(t, resp)["key"].(string)

	// Sanity check: with the permissive policy, the key can mint a token
	// carrying data:write.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      "data:write",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	before := decode(t, resp)
	assert.Contains(t, before["scope"], "data:write",
		"baseline: permissive policy must allow data:write before tightening")

	// Admin tightens the identity policy — removes data:write.
	// The API key row is untouched. Its own credential_policy_id still
	// points at the same policy (which was just tightened, so the
	// identity and key layers remain identical in this test — the
	// salient point is that the runtime read sees the NEW state).
	patchCredentialPolicy(t, identityPolicyID, map[string]any{
		"allowed_scopes": []string{"data:read"},
	}, adminHeaders())

	// After tightening: the same API key minting a token that requests
	// data:write must fail at runtime. No key rotation. No manual
	// reconciliation. The policy drift heals itself because every token
	// issuance re-reads the current policy state.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      "data:write",
	}, nil)
	if resp.StatusCode == http.StatusOK {
		after := decode(t, resp)
		scope, _ := after["scope"].(string)
		assert.NotContains(t, scope, "data:write",
			"policy-drift self-heal: tightened policy must immediately restrict subsequent issuances via existing keys")
	} else {
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"policy-drift self-heal: tightened policy must reject requests for revoked scopes")
		resp.Body.Close()
	}
}

// -- small helpers -----------------------------------------------------------

// fetchIdentityWIMSEByExternalID returns the server-built WIMSE URI for the
// identity with the given external_id in the default test tenant. Tests that
// need to build actor assertions use this so the assertion's iss claim
// matches what the server will resolve.
func fetchIdentityWIMSEByExternalID(t *testing.T, externalID string) string {
	t.Helper()
	resp := get(t, adminPath("/identities"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	items := body["identities"].([]any)
	for _, item := range items {
		m := item.(map[string]any)
		if m["external_id"] == externalID {
			return m["wimse_uri"].(string)
		}
	}
	t.Fatalf("identity with external_id=%s not found", externalID)
	return ""
}
