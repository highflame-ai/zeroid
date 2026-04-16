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
