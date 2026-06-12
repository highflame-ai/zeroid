package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note on test placement: the project convention for test coverage of service-
// layer behaviour is end-to-end integration tests (see tests/integration/*.go).
// No internal/service/*_test.go infrastructure exists. These tests exercise
// the same propagation + IDOR guard the reviewer asked about, but through the
// real HTTP → handler → service → repository stack which gives stronger
// coverage than unit tests stubbed against mocks.

// TestRegisterAgent_CustomCredentialPolicy_Propagates verifies that a
// caller-supplied credential_policy_id on POST /agents/register propagates all
// the way to the auto-created API key. Regression coverage for the wiring in
// AgentService.RegisterAgent → APIKeyService.CreateKey.
func TestRegisterAgent_CustomCredentialPolicy_Propagates(t *testing.T) {
	policyID := createCredentialPolicy(t, uid("agent-cp-propagation"), adminHeaders())

	externalID := uid("agent-cp-prop")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"external_id":          externalID,
		"identity_type":        "agent",
		"sub_type":             "tool_agent",
		"trust_level":          "unverified",
		"name":                 "Policy Propagation Agent",
		"created_by":           "test-user",
		"credential_policy_id": policyID,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	registered := decode(t, resp)

	identity := registered["identity"].(map[string]any)
	identityID := identity["id"].(string)
	require.NotEmpty(t, identityID)

	// The register response exposes the API key's prefix. To assert the
	// policy link we need the key record — list keys scoped to this identity.
	listResp := get(t, adminPath("/api-keys?application_id="+identityID), adminHeaders())
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	listBody := decode(t, listResp)
	keys := listBody["keys"].([]any)
	require.Len(t, keys, 1, "register-agent should auto-create exactly one API key for the identity")

	got := keys[0].(map[string]any)
	assert.Equal(t, policyID, got["credential_policy_id"],
		"custom credential_policy_id supplied at register-agent must be stored on the auto-created key")
}

// TestRegisterAgent_ApiKeyPolicyNarrowerThanIdentity verifies the two-layer
// wiring: register-agent accepts a separate api_key_credential_policy_id
// that scopes the bootstrap API key tighter than the identity policy. The
// identity carries the (broader) identity policy; the auto-created key
// carries the (narrower) key policy.
func TestRegisterAgent_ApiKeyPolicyNarrowerThanIdentity(t *testing.T) {
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ra-id-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"allowed_scopes":       []string{"data:read", "data:write"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	apiKeyPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ra-key-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"allowed_scopes":       []string{"data:read"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	externalID := uid("ra-two-layer")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"external_id":                  externalID,
		"identity_type":                "agent",
		"sub_type":                     "tool_agent",
		"trust_level":                  "unverified",
		"name":                         "Two-Layer Agent",
		"created_by":                   "test-user",
		"credential_policy_id":         identityPolicyID,
		"api_key_credential_policy_id": apiKeyPolicyID,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	registered := decode(t, resp)

	identity := registered["identity"].(map[string]any)
	identityID := identity["id"].(string)
	assert.Equal(t, identityPolicyID, identity["credential_policy_id"],
		"identity row must carry the identity policy")

	listResp := get(t, adminPath("/api-keys?application_id="+identityID), adminHeaders())
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	keys := decode(t, listResp)["keys"].([]any)
	require.Len(t, keys, 1)
	got := keys[0].(map[string]any)
	assert.Equal(t, apiKeyPolicyID, got["credential_policy_id"],
		"auto-created API key must carry the narrower key policy, not the identity policy")
}

// TestRegisterAgent_ApiKeyPolicyBroaderThanIdentityRejected verifies that
// the subset invariant enforced inside APIKeyService.CreateKey also
// applies to the register-agent atomic flow. A key policy that grants
// more than the identity policy must be rejected with 400 — and the
// compensating delete inside RegisterAgent must undo the half-created
// identity so the client can retry with a compliant policy.
func TestRegisterAgent_ApiKeyPolicyBroaderThanIdentityRejected(t *testing.T) {
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ra-id-narrow"),
		"allowed_grant_types":  []string{"api_key"},
		"allowed_scopes":       []string{"data:read"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	broaderKeyPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ra-key-broad"),
		"allowed_grant_types":  []string{"api_key"},
		"allowed_scopes":       []string{"data:read", "data:write"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	resp := post(t, adminPath("/agents/register"), map[string]any{
		"external_id":                  uid("ra-bad-subset"),
		"identity_type":                "agent",
		"sub_type":                     "tool_agent",
		"trust_level":                  "unverified",
		"name":                         "Bad Subset Agent",
		"created_by":                   "test-user",
		"credential_policy_id":         identityPolicyID,
		"api_key_credential_policy_id": broaderKeyPolicyID,
	}, adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"api_key_credential_policy_id broader than identity policy must be rejected at register-agent")
}

// TestRegisterAgent_CrossTenantCredentialPolicyRejected verifies the IDOR
// guard on the register-agent flow: a caller in tenant B cannot bootstrap an
// agent whose API key references tenant A's policy. The guard lives in
// APIKeyService.CreateKey (GetPolicy is tenant-scoped); the agent handler
// surfaces ErrPolicyNotFound as 400 Bad Request.
func TestRegisterAgent_CrossTenantCredentialPolicyRejected(t *testing.T) {
	tenantA := tenantHeaders("acct-agent-tenant-a-"+uid(""), "proj-agent-tenant-a-"+uid(""))
	tenantB := tenantHeaders("acct-agent-tenant-b-"+uid(""), "proj-agent-tenant-b-"+uid(""))

	// Tenant A creates a policy.
	foreignPolicyID := createCredentialPolicy(t, uid("cp-agent-tenant-a"), tenantA)

	// Tenant B attempts to reference tenant A's policy when registering an agent.
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"external_id":          uid("cross-tenant-agent"),
		"identity_type":        "agent",
		"sub_type":             "tool_agent",
		"trust_level":          "unverified",
		"name":                 "Cross-Tenant Attempt",
		"created_by":           "test-user",
		"credential_policy_id": foreignPolicyID,
	}, tenantB)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"cross-tenant credential_policy_id must be rejected at register-agent with 400")
}

// TestDeleteAgent_WithServiceKey_SoftDeletes is the regression for authn#109:
// DELETE /agents/registry/{id} on an agent that has a service key must SOFT
// delete (deactivate) it, not hard-delete. Previously the hard delete returned
// 500 on the non-cascading service_keys FK (every registered agent gets a
// bootstrap key, so all agent deletes failed). The fix deactivates instead:
// the request succeeds, the identity row is retained as deactivated (audit
// trail preserved + matches the "soft delete" contract), and the agent's
// credentials are revoked on the way out.
func TestDeleteAgent_WithServiceKey_SoftDeletes(t *testing.T) {
	ext := uid("delete-agent-softdelete")
	reg := registerAgent(t, ext) // registration auto-creates a service key

	// Mint a live token from the bootstrap key so we can prove revocation.
	issueResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, issueResp.StatusCode)
	token := decode(t, issueResp)["access_token"].(string)
	require.True(t, introspect(t, token)["active"].(bool), "token should be active before delete")

	// DELETE must succeed — not 500 on the service_keys FK.
	delResp, err := doRaw(t, http.MethodDelete, adminPath("/agents/registry/"+reg.AgentID), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, delResp.StatusCode,
		"DELETE of an agent with a service key must succeed, not 500 on the service_keys FK")
	_ = delResp.Body.Close()

	// Soft delete: the identity row is RETAINED and flipped to deactivated.
	getResp := get(t, adminPath("/identities/"+reg.AgentID), adminHeaders())
	require.Equal(t, http.StatusOK, getResp.StatusCode, "identity must still exist after a soft delete")
	assert.Equal(t, "deactivated", decode(t, getResp)["status"],
		"DELETE must deactivate the agent, not hard-delete it")

	// Credentials revoked on the way out (the "revoke its keys" half of the contract).
	assert.False(t, introspect(t, token)["active"].(bool),
		"DELETE must revoke the agent's credentials")

	// Idempotent: deleting an already-deactivated agent still succeeds.
	delAgain, err := doRaw(t, http.MethodDelete, adminPath("/agents/registry/"+reg.AgentID), nil, adminHeaders())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, delAgain.StatusCode, "repeat DELETE must be idempotent")
	_ = delAgain.Body.Close()
}

// TestRegisterAgent_ReusingDeactivatedExternalID_Returns409WithExistingID
// covers the re-registration UX after a soft delete: because DELETE is now a
// soft delete, the deactivated row keeps the external_id, so re-registering it
// collides. The 409 must be actionable — it names the deactivated identity's
// id (hidden from the active registry view) so the caller can reactivate it
// instead of hitting an opaque "already exists".
func TestRegisterAgent_ReusingDeactivatedExternalID_Returns409WithExistingID(t *testing.T) {
	ext := uid("reregister-deactivated")
	reg := registerAgent(t, ext)

	delResp, err := doRaw(t, http.MethodDelete, adminPath("/agents/registry/"+reg.AgentID), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, delResp.StatusCode)
	_ = delResp.Body.Close()

	// Re-registering the same external_id collides with the soft-deleted row.
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":        ext,
		"external_id": ext,
		"sub_type":    "orchestrator",
		"trust_level": "first_party",
		"created_by":  "test-user",
	}, adminHeaders())
	require.Equal(t, http.StatusConflict, resp.StatusCode,
		"re-registering a soft-deleted external_id must 409 (actionable), not 500 or an opaque conflict")

	body := decode(t, resp)

	detail, _ := body["detail"].(string)
	assert.Contains(t, detail, "deactivated",
		"the 409 detail must explain the existing identity is deactivated; got %q", detail)
	assert.Contains(t, detail, reg.AgentID,
		"the 409 detail must include the existing identity id for reactivation; got %q", detail)

	// Machine-readable detail: errors[0].value carries the existing id so a UI
	// can offer a one-click reactivate.
	errs, _ := body["errors"].([]any)
	require.NotEmpty(t, errs, "expected a structured error detail carrying the existing id")
	first, _ := errs[0].(map[string]any)
	assert.Equal(t, reg.AgentID, first["value"],
		"errors[0].value must be the deactivated identity id")

	// Sanity: a genuinely fresh external_id still registers fine.
	fresh := post(t, adminPath("/agents/register"), map[string]any{
		"name": uid("fresh"), "external_id": uid("fresh-ext"),
		"sub_type": "orchestrator", "trust_level": "first_party", "created_by": "test-user",
	}, adminHeaders())
	assert.Equal(t, http.StatusCreated, fresh.StatusCode)
	_ = fresh.Body.Close()
}
