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

// Human-rooted delegation, phase 1 (highflame-architecture#359). The tests in
// this file follow the design's test plan (§9); the names it gives are kept so
// the plan and the suite can be read side by side.

const issuedTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

// exchangeForResponse registers a fresh actor under policyID and exchanges
// parentToken for it, returning the whole token response so tests can assert on
// response fields, not only on the JWT.
func exchangeForResponse(t *testing.T, policyID, namePrefix string, scopes []string, parentToken string) map[string]any {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	extID := uid(namePrefix)
	registerIdentityWithPolicy(t, extID, policyID, ecPublicKeyPEM(t, key), scopes, adminHeaders())
	wimse := fetchIdentityWIMSEByExternalID(t, extID)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": parentToken,
		"actor_token":   buildAssertion(t, key, wimse),
		"scope":         scopesToString(scopes),
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token_exchange %s", namePrefix)
	body := decode(t, resp)
	_ = resp.Body.Close()
	return body
}

// TestTokenExchange_IssuedTokenType covers D7: RFC 8693 §2.2.1 makes
// issued_token_type REQUIRED on a token-exchange response. It is checked on
// both an NHI delegation and the trusted-broker principal exchange, the two
// exchange modes most callers use, and confirmed absent on a non-exchange
// grant, where RFC 6749 §5.1 does not define it.
func TestTokenExchange_IssuedTokenType(t *testing.T) {
	scopes := []string{"data:read"}
	policyID := delegationPolicy(t, uid("d7-policy"), scopes)

	t.Run("client_credentials does not carry it", func(t *testing.T) {
		extID := uid("d7-root")
		registerIdentityWithPolicy(t, extID, policyID, "", scopes, adminHeaders())
		client := registerOAuthClient(t, extID, scopes)
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := decode(t, resp)
		_ = resp.Body.Close()
		assert.NotContains(t, body, "issued_token_type")
	})

	t.Run("NHI delegation carries it", func(t *testing.T) {
		_, _, root := issueRootCredential(t, policyID, "d7-orch", scopes)
		body := exchangeForResponse(t, policyID, "d7-actor", scopes, root)
		assert.Equal(t, issuedTokenTypeAccessToken, body["issued_token_type"])
	})

	t.Run("trusted-broker principal exchange carries it", func(t *testing.T) {
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": "external-principal-assertion",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"user_id":       uid("d7-user"),
		}, map[string]string{testTrustedServiceHeader: "trusted-service"})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := decode(t, resp)
		_ = resp.Body.Close()
		assert.Equal(t, issuedTokenTypeAccessToken, body["issued_token_type"])
	})
}
