package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerIdentityIn creates an identity under a specific tenant, used for
// cross-tenant IDOR test scenarios where the default tenant helpers would
// collapse both sides into one tenant.
func registerIdentityIn(t *testing.T, headers map[string]string, externalID string, scopes []string) identityResp {
	t.Helper()
	body := map[string]any{
		"external_id":    externalID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": scopes,
	}
	resp := post(t, adminPath("/identities"), body, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registerIdentityIn: expected 201, got %d", resp.StatusCode)
	decoded := decode(t, resp)
	return identityResp{
		ID:         decoded["id"].(string),
		ExternalID: decoded["external_id"].(string),
	}
}

// createAPIKeyIn creates an API key under a specific tenant and returns the
// key's UUID. Exercises the same POST /api-keys handler but via caller-
// supplied tenant headers rather than the default test tenant.
func createAPIKeyIn(t *testing.T, headers map[string]string, name, product string) string {
	t.Helper()
	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":    name,
		"product": product,
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "createAPIKeyIn: expected 201")
	body := decode(t, resp)
	id, _ := body["id"].(string)
	require.NotEmpty(t, id, "createAPIKeyIn: response missing id")
	return id
}

// TestAPIKeyGetIsTenantScoped verifies a caller with tenant B's headers cannot
// GET /api-keys/{id} for a key that belongs to tenant A, even with the correct
// UUID. Guards the IDOR at handler:getAPIKeyOp that previously dropped tenant
// context between the middleware check and the service lookup.
func TestAPIKeyGetIsTenantScoped(t *testing.T) {
	tenantA := tenantHeaders("acct-apikey-a-"+uid(""), "proj-apikey-a-"+uid(""))
	tenantB := tenantHeaders("acct-apikey-b-"+uid(""), "proj-apikey-b-"+uid(""))

	keyID := createAPIKeyIn(t, tenantA, "tenant-a-key", "idor-test")

	// Tenant A owns the key — GET must succeed.
	ownResp := get(t, adminPath("/api-keys/"+keyID), tenantA)
	require.Equal(t, http.StatusOK, ownResp.StatusCode,
		"owning tenant must be able to read its own key")
	_ = ownResp.Body.Close()

	// Tenant B presenting the correct UUID must see 404 — not the key body,
	// not a 403 (existence disclosure).
	crossResp := get(t, adminPath("/api-keys/"+keyID), tenantB)
	assert.Equal(t, http.StatusNotFound, crossResp.StatusCode,
		"cross-tenant GET /api-keys/{id} must return 404")
	_ = crossResp.Body.Close()
}

// TestAPIKeyRevokeIsTenantScoped verifies that tenant B cannot revoke tenant
// A's API key even if B knows the UUID. The key remains usable afterward —
// we confirm by introspecting a token minted from it.
func TestAPIKeyRevokeIsTenantScoped(t *testing.T) {
	tenantA := tenantHeaders("acct-revoke-a-"+uid(""), "proj-revoke-a-"+uid(""))
	tenantB := tenantHeaders("acct-revoke-b-"+uid(""), "proj-revoke-b-"+uid(""))

	// Tenant A: create a key that can mint tokens.
	createResp := post(t, adminPath("/api-keys"), map[string]any{
		"name":    "tenant-a-revoke-target",
		"product": "idor-revoke",
	}, tenantA)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	created := decode(t, createResp)
	keyID := created["id"].(string)
	apiKey := created["key"].(string)
	require.NotEmpty(t, apiKey)

	// Sanity: the key works in its own tenant.
	tokResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
	}, nil)
	require.Equal(t, http.StatusOK, tokResp.StatusCode, "tenant A key must issue tokens")
	token := decode(t, tokResp)["access_token"].(string)

	// Tenant B: try to revoke by UUID.
	revResp := post(t, adminPath("/api-keys/"+keyID+"/revoke"), map[string]any{
		"reason": "IDOR attempt",
	}, tenantB)
	assert.Equal(t, http.StatusNotFound, revResp.StatusCode,
		"cross-tenant revoke must return 404, not 200 'revoked'")
	_ = revResp.Body.Close()

	// Tenant A's token must still introspect as active — the revoke must not
	// have touched the underlying state.
	after := introspect(t, token)
	assert.True(t, after["active"].(bool),
		"target tenant's token must stay active after cross-tenant revoke attempt")

	// Same-tenant revoke still works normally.
	ownRev := post(t, adminPath("/api-keys/"+keyID+"/revoke"), map[string]any{
		"reason": "cleanup",
	}, tenantA)
	assert.Equal(t, http.StatusOK, ownRev.StatusCode,
		"owning tenant must still be able to revoke its own key")
	_ = ownRev.Body.Close()
}

// TestSignalHighSeverityAutoRevokeIsTenantScoped verifies the CAE auto-revoke
// cascade only fires when the caller-supplied identity_id actually belongs to
// the caller's tenant. Otherwise a caller with any valid tenant headers could
// revoke another tenant's credentials by guessing an identity UUID.
func TestSignalHighSeverityAutoRevokeIsTenantScoped(t *testing.T) {
	tenantA := tenantHeaders("acct-sig-a-"+uid(""), "proj-sig-a-"+uid(""))
	tenantB := tenantHeaders("acct-sig-b-"+uid(""), "proj-sig-b-"+uid(""))

	// Tenant A: register identity + OAuth client + mint a token. Cross-tenant
	// mint needs the identity and client in the same tenant, so bind the
	// client_id to the identity's external_id — matches the wiring used by
	// OAuthService.clientCredentials for identity resolution.
	victimExternalID := uid("victim-agent")
	identA := registerIdentityIn(t, tenantA, victimExternalID, []string{"data:read"})
	oauthResp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":    victimExternalID,
		"name":         victimExternalID + "-client",
		"confidential": true,
		"grant_types":  []string{"client_credentials"},
		"scopes":       []string{"data:read"},
	}, tenantA)
	require.Equal(t, http.StatusCreated, oauthResp.StatusCode, "oauth client creation failed")
	clientBody := decode(t, oauthResp)
	client := clientBody["client"].(map[string]any)
	clientID := client["client_id"].(string)
	clientSecret := clientBody["client_secret"].(string)

	tokResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    tenantA["X-Account-ID"],
		"project_id":    tenantA["X-Project-ID"],
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, tokResp.StatusCode, "victim tenant token mint failed")
	victimToken := decode(t, tokResp)["access_token"].(string)
	require.True(t, introspect(t, victimToken)["active"].(bool),
		"victim token must start active")

	// Tenant B: submit a high-severity signal carrying tenant A's identity_id.
	// The signal row itself is allowed to be recorded under tenant B (audit
	// trail of the attempt), but the auto-revoke cascade must NOT fire.
	sigResp := post(t, adminPath("/signals/ingest"), map[string]any{
		"identity_id": identA.ID,
		"signal_type": "anomalous_behavior",
		"severity":    "high",
		"source":      "idor-test",
		"payload":     map[string]any{"reason": "cross-tenant revoke attempt"},
	}, tenantB)
	require.Equal(t, http.StatusCreated, sigResp.StatusCode,
		"signal ingest should succeed so the attempt is auditable in the caller tenant")
	_ = sigResp.Body.Close()

	// Give any async revoke goroutine a moment.
	time.Sleep(150 * time.Millisecond)

	// Victim token must still be active.
	result := introspect(t, victimToken)
	assert.True(t, result["active"].(bool),
		"cross-tenant high-severity signal must NOT revoke another tenant's credentials")

	// Sanity check: a same-tenant high-severity signal DOES still revoke.
	sameTenantSig := post(t, adminPath("/signals/ingest"), map[string]any{
		"identity_id": identA.ID,
		"signal_type": "anomalous_behavior",
		"severity":    "high",
		"source":      "idor-test-control",
		"payload":     map[string]any{"reason": "same-tenant control"},
	}, tenantA)
	require.Equal(t, http.StatusCreated, sameTenantSig.StatusCode)
	_ = sameTenantSig.Body.Close()
	time.Sleep(150 * time.Millisecond)
	result = introspect(t, victimToken)
	assert.False(t, result["active"].(bool),
		"same-tenant high-severity signal must still revoke (sanity check)")
}
