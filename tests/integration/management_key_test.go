package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testManagementKeyWriteHeader stands in for the deployer's trusted caller:
// when present, the test global middleware marks the request with
// zeroid.WithManagementKeyWrite.
const testManagementKeyWriteHeader = "X-Test-Management-Key-Write"

// createKeyForAgent creates an API key linked to agentID and returns its ID
// and the raw key.
func createKeyForAgent(t *testing.T, agentID string, management bool, headers map[string]string) (int, string, string) {
	t.Helper()
	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":        uid("mgmt-key"),
		"identity_id": agentID,
		"management":  management,
	}, headers)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		return resp.StatusCode, "", ""
	}
	body := decode(t, resp)
	return resp.StatusCode, body["id"].(string), body["key"].(string)
}

func mintAPIKeyToken(t *testing.T, key string) map[string]any {
	t.Helper()
	resp := post(t, "/oauth2/token", map[string]any{"grant_type": "api_key", "api_key": key}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer func() { _ = resp.Body.Close() }()
	return decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
}

// TestAPIKeyGrant_CarriesKeyID: ADR 0051 D2. The api_key grant names the key
// it was minted from, so a resource server can look up the key's mark and
// creator.
func TestAPIKeyGrant_CarriesKeyID(t *testing.T) {
	agent := registerAgent(t, uid("keyid-agent"))
	status, keyID, key := createKeyForAgent(t, agent.AgentID, false, adminHeaders())
	require.Equal(t, http.StatusCreated, status)

	claims := mintAPIKeyToken(t, key)
	assert.Equal(t, keyID, claims["api_key_id"])
	assert.Equal(t, "api_key", claims["grant_type"])
}

// TestAPIKeyID_CannotBeForgedViaAdditionalClaims: the broker path filters
// additional_claims by reservedClaims; api_key_id must be dropped.
func TestAPIKeyID_CannotBeForgedViaAdditionalClaims(t *testing.T) {
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":        "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":     "external-principal-assertion",
		"account_id":        testAccountID,
		"project_id":        testProjectID,
		"user_id":           uid("keyid-user"),
		"additional_claims": map[string]any{"api_key_id": "00000000-0000-0000-0000-000000000001"},
	}, map[string]string{testTrustedServiceHeader: "trusted-service"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "reserved claims are dropped, not fatal")
	defer func() { _ = resp.Body.Close() }()
	claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
	assert.NotContains(t, claims, "api_key_id")
}

// TestAPIKeyID_NotCarriedThroughExchange: a token delegated from an api_key
// token is not minted from a key, so it must not name one.
func TestAPIKeyID_NotCarriedThroughExchange(t *testing.T) {
	scopes := []string{"data:read"}
	tn := newTenant(t, "rfc8693")
	root, _ := tn.apiKeyRoot(t, scopes)
	require.NotEmpty(t, decodeJWTPayload(t, root)["api_key_id"])

	body, _ := tn.exchange(t, tn.policy(t, scopes), uid("keyid-child"), scopes, root)
	assert.NotContains(t, decodeJWTPayload(t, body["access_token"].(string)), "api_key_id")
}

// TestManagementMark_RequiresTrustedWrite: ADR 0053 D3. Only a caller the
// deployer marked with WithManagementKeyWrite may set the mark; the mark is
// returned on GET so the deployer can read it by key ID.
func TestManagementMark_RequiresTrustedWrite(t *testing.T) {
	agent := registerAgent(t, uid("mgmt-agent"))

	status, _, _ := createKeyForAgent(t, agent.AgentID, true, adminHeaders())
	assert.Equal(t, http.StatusForbidden, status, "an unmarked caller cannot set the management mark")

	trusted := adminHeaders()
	trusted[testManagementKeyWriteHeader] = "1"

	status, keyID, _ := createKeyForAgent(t, agent.AgentID, true, trusted)
	require.Equal(t, http.StatusCreated, status)
	resp := get(t, adminPath("/api-keys/"+keyID), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, true, decode(t, resp)["management"])
	_ = resp.Body.Close()

	status, keyID, _ = createKeyForAgent(t, agent.AgentID, false, trusted)
	require.Equal(t, http.StatusCreated, status)
	resp = get(t, adminPath("/api-keys/"+keyID), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, false, decode(t, resp)["management"], "the trusted caller still has to ask for the mark")
	_ = resp.Body.Close()
}
