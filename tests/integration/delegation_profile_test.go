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
	body, _ := exchangeAs(t, policyID, uid(namePrefix), scopes, parentToken)
	return body
}

// exchangeAs is exchangeForResponse with a caller-chosen actor external_id, so
// a test can assert claims that name the actor. Returns the token response and
// the actor's WIMSE URI.
func exchangeAs(t *testing.T, policyID, extID string, scopes []string, parentToken string) (map[string]any, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	registerIdentityWithPolicy(t, extID, policyID, ecPublicKeyPEM(t, key), scopes, adminHeaders())
	wimse := fetchIdentityWIMSEByExternalID(t, extID)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": parentToken,
		"actor_token":   buildAssertion(t, key, wimse),
		"scope":         scopesToString(scopes),
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token_exchange as %s", extID)
	body := decode(t, resp)
	_ = resp.Body.Close()
	return body, wimse
}

// TestIntrospection_Fields covers D2: RFC 7662 introspection now returns the
// lineage and attribution claims the token carries, so a resource server that
// introspects instead of verifying locally sees the same delegation tree and
// accountable human. Every value must equal the token's own claim.
func TestIntrospection_Fields(t *testing.T) {
	scopes := []string{"data:read"}
	policyID := delegationPolicy(t, uid("d2-policy"), scopes)
	_, _, root := issueRootCredential(t, policyID, "d2-orch", scopes)
	body := exchangeForResponse(t, policyID, "d2-actor", scopes, root)
	token := body["access_token"].(string)
	claims := decodeJWTPayload(t, token)

	got := introspect(t, token)
	require.Equal(t, true, got["active"])
	for _, claim := range []string{"client_id", "mission_id"} {
		require.NotEmpty(t, claims[claim], "precondition: the exchanged token carries %s", claim)
		assert.Equal(t, claims[claim], got[claim], "introspection must return the token's %s", claim)
	}
	if owner, ok := claims["owner_user_id"]; ok {
		assert.Equal(t, owner, got["owner_user_id"])
	} else {
		assert.NotContains(t, got, "owner_user_id", "a claim the token lacks is not invented")
	}
}

// TestTokenExchange_ClientIDIsTheActor covers the exchange half of D8: RFC 9068
// §2.2 and RFC 8693 §4.3 put the client the token was issued to in client_id,
// and on an exchange that client is the actor. Emitted for every tenant, so
// this holds under the default legacy profile too. The ID-JAG half is asserted
// in TestIDJAG_EndToEnd.
func TestTokenExchange_ClientIDIsTheActor(t *testing.T) {
	scopes := []string{"data:read"}
	policyID := delegationPolicy(t, uid("d8-policy"), scopes)
	_, _, root := issueRootCredential(t, policyID, "d8-orch", scopes)

	actorExtID := uid("d8-actor")
	body, _ := exchangeAs(t, policyID, actorExtID, scopes, root)
	claims := decodeJWTPayload(t, body["access_token"].(string))
	assert.Equal(t, actorExtID, claims["client_id"])
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
