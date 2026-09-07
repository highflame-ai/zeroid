package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAccessTokenCarriesClientIDClaim pins the RFC 9068 §2.2 `client_id` claim
// on the authorization_code grant (issue #325).
//
// The identity was never actually lost — it has always been emitted as
// `application_id`, because the authorization_code path passes the client_id to
// `IssueRequest.ApplicationID`. But `application_id` is a Highflame name whose
// documented meaning is broader ("the optional application scope, set when an
// API key is linked to an application"), so a resource server that has never
// seen this stack has no reason to look there. `client_id` is the registered
// claim for exactly this, and it is what a partner's MCP server will read.
//
// Both are asserted: dropping `application_id` would break anything already
// keying on it, so the fix adds a claim rather than renaming one.
func TestAccessTokenCarriesClientIDClaim(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-cid-001", testRedirectURI, challenge,
		[]string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	claims := decodeJWTUnsafe(t, decode(t, resp)["access_token"].(string))

	assert.Equal(t, testMCPClientID, claims["client_id"],
		"RFC 9068 §2.2 `client_id` claim missing — a resource server cannot "+
			"attribute this call to a client without it")
	assert.Equal(t, testMCPClientID, claims["application_id"],
		"`application_id` must keep its existing value; the fix adds a claim "+
			"rather than renaming one, so existing consumers are unaffected")
}

// TestRefreshedAccessTokenKeepsClientIDClaim is the half that would have looked
// fixed and silently regressed.
//
// A refreshed access token is minted by a different IssueCredential call in
// `refreshToken`, not by the authorization_code path. Wiring `ClientID` into
// only the first would give a token that identifies its client for one hour and
// then stops — the attribution gap reappearing at renewal, where nobody would
// think to look for it.
func TestRefreshedAccessTokenKeepsClientIDClaim(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-cid-002", testRedirectURI, challenge,
		[]string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	initial := decode(t, resp)
	refreshToken, ok := initial["refresh_token"].(string)
	require.True(t, ok, "MCP client must receive a refresh_token for this test to mean anything")

	// Sanity: the claim is present before the refresh, so a failure below is
	// about the refresh path rather than the initial grant.
	require.Equal(t, testMCPClientID,
		decodeJWTUnsafe(t, initial["access_token"].(string))["client_id"],
		"initial token has no client_id — wrong test is failing")

	refreshResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"client_id":     testMCPClientID,
		"refresh_token": refreshToken,
	}, nil)
	require.Equal(t, http.StatusOK, refreshResp.StatusCode)

	refreshed := decodeJWTUnsafe(t, decode(t, refreshResp)["access_token"].(string))
	assert.Equal(t, testMCPClientID, refreshed["client_id"],
		"the refreshed access token dropped `client_id` — a refresh is continuity "+
			"of an existing grant, so the client it was granted to must survive it")
}
