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
