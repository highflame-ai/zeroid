package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The harness reserves testReservedPrefix (Server.SetReservedScopes) with an
// authorizer that refuses keys created by testDemotedUser.
const (
	testReservedPrefix           = "testreserved."
	testReservedScope            = "testreserved.config.manage"
	testReservedMaxTTL           = 2 * time.Minute // well under the 1h default, so the cap shows
	testDemotedUser              = "demoted-user"
	testBrokenAuthorizerUser     = "broken-authorizer-user"
	testReservedScopeWriteHeader = "X-Test-Reserved-Scope-Write"
)

// createProductKey creates a product key (linked to an auto-provisioned
// service identity, created by createdBy) and returns status, key ID and key.
func createProductKey(t *testing.T, createdBy string, scopes []string, trusted bool) (int, string, string) {
	t.Helper()
	headers := adminHeaders()
	headers["X-User-ID"] = createdBy
	if trusted {
		headers[testReservedScopeWriteHeader] = "1"
	}
	body := map[string]any{"name": uid("rs-key"), "product": uid("rs-product")}
	if scopes != nil {
		body["scopes"] = scopes
	}
	resp := post(t, adminPath("/api-keys"), body, headers)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		return resp.StatusCode, "", ""
	}
	created := decode(t, resp)
	return resp.StatusCode, created["id"].(string), created["key"].(string)
}

// exchangeKey runs the api_key grant, optionally naming a scope.
func exchangeKey(t *testing.T, key, scope string) (int, map[string]any) {
	t.Helper()
	body := map[string]any{"grant_type": "api_key", "api_key": key}
	if scope != "" {
		body["scope"] = scope
	}
	resp := post(t, "/oauth2/token", body, nil)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, decode(t, resp)
}

// TestAPIKeyGrant_CarriesKeyID: ADR 0051 D2. The api_key grant names the key
// it was minted from, for audit.
func TestAPIKeyGrant_CarriesKeyID(t *testing.T) {
	status, keyID, key := createProductKey(t, "test-user", nil, false)
	require.Equal(t, http.StatusCreated, status)

	code, body := exchangeKey(t, key, "")
	require.Equal(t, http.StatusOK, code)
	claims := decodeJWTPayload(t, body["access_token"].(string))
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

// Only the deployer's trusted path writes a reserved scope onto a key.
func TestReservedScope_WriteNeedsTrustedPath(t *testing.T) {
	status, _, _ := createProductKey(t, "test-user", []string{testReservedScope}, false)
	assert.Equal(t, http.StatusForbidden, status)

	status, _, _ = createProductKey(t, "test-user", []string{testReservedScope}, true)
	assert.Equal(t, http.StatusCreated, status)
}

// A key that does not list the scope cannot ask for it, even though its
// unbounded ceiling would grant any other scope by name.
func TestReservedScope_UnlistedKeyCannotAsk(t *testing.T) {
	status, _, key := createProductKey(t, "test-user", nil, false)
	require.Equal(t, http.StatusCreated, status)
	code, body := exchangeKey(t, key, testReservedScope)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_scope", body["error"])

	// An agent's key, the other common shape, is refused the same way.
	agent := registerAgent(t, uid("rs-agent"))
	code, body = exchangeKey(t, agent.APIKey, testReservedScope)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_scope", body["error"])
}

// A key that lists the scope gets it without asking, named for its creator,
// tied to the key, and capped at the reserved lifetime.
func TestReservedScope_ListedKeyIsIssued(t *testing.T) {
	status, keyID, key := createProductKey(t, "test-user", []string{testReservedScope}, true)
	require.Equal(t, http.StatusCreated, status)

	code, body := exchangeKey(t, key, "")
	require.Equal(t, http.StatusOK, code, "%v", body)
	claims := decodeJWTPayload(t, body["access_token"].(string))
	assert.Contains(t, claims["scopes"], testReservedScope)
	assert.Equal(t, "test-user", claims["owner_user_id"])
	assert.Equal(t, keyID, claims["api_key_id"])
	lifetime := claims["exp"].(float64) - claims["iat"].(float64)
	assert.LessOrEqual(t, lifetime, testReservedMaxTTL.Seconds())
}

// The deployer's authorizer can refuse the exchange (Highflame: the creator
// is no longer an org owner or admin).
func TestReservedScope_AuthorizerRefuses(t *testing.T) {
	status, _, key := createProductKey(t, testDemotedUser, []string{testReservedScope}, true)
	require.Equal(t, http.StatusCreated, status)

	code, body := exchangeKey(t, key, "")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", body["error"])
}

// An authorizer that fails (not refuses) fails the grant closed, without
// passing its error text to the client.
func TestReservedScope_AuthorizerFailureIsServerError(t *testing.T) {
	status, _, key := createProductKey(t, testBrokenAuthorizerUser, []string{testReservedScope}, true)
	require.Equal(t, http.StatusCreated, status)

	code, body := exchangeKey(t, key, "")
	assert.Equal(t, http.StatusInternalServerError, code)
	assert.Equal(t, "server_error", body["error"])
	assert.NotContains(t, body["error_description"], "internal-admin")
}
