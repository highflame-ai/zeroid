// The user's display attributes (email, display name) a PrincipalResolver
// vouches for at /oauth2/authorize reach the access token as `user_email` /
// `user_name`, and keep reaching it across refresh-token rotation.
//
// CLIs show these on `whoami`. Before they were carried, an interactive login
// produced a token naming only the opaque user id, and nothing a refresh minted
// could ever name more.
package integration_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authorizeForCode runs POST /oauth2/authorize with the stub resolver and
// returns the code from the 302.
func authorizeForCode(t *testing.T, form url.Values) string {
	t.Helper()

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)

	return code
}

func exchangeCode(t *testing.T, clientID, code, verifier string) map[string]any {
	t.Helper()

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	return decode(t, resp)
}

func refresh(t *testing.T, clientID, refreshToken string) map[string]any {
	t.Helper()

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     clientID,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	return decode(t, resp)
}

// The full path: authorize → code → access token → refresh → refresh. The
// second refresh is load-bearing: it proves the attributes are copied onto the
// successor row on rotation, not merely seeded on the family once.
func TestPrincipalUserEmail_SurvivesCodeExchangeAndRotation(t *testing.T) {
	const email = "ada@example.com"
	const name = "Ada Lovelace"

	form, verifier := authorizeBaseForm(t)
	form.Set("client_id", testMCPClientID) // registered for refresh_token
	form.Set("test_principal_user", "user-principal-email")
	form.Set("test_principal_email", email)
	form.Set("test_principal_name", name)

	tok := exchangeCode(t, testMCPClientID, authorizeForCode(t, form), verifier)

	claims := decodeJWTUnsafe(t, tok["access_token"].(string))
	assert.Equal(t, "user-principal-email", claims["sub"])
	assert.Equal(t, email, claims["user_email"])
	assert.Equal(t, name, claims["user_name"])

	rt, _ := tok["refresh_token"].(string)
	require.NotEmpty(t, rt, "the MCP test client is registered for refresh_token")

	first := refresh(t, testMCPClientID, rt)
	claims = decodeJWTUnsafe(t, first["access_token"].(string))
	assert.Equal(t, email, claims["user_email"], "first refresh must keep user_email")
	assert.Equal(t, name, claims["user_name"], "first refresh must keep user_name")

	second := refresh(t, testMCPClientID, first["refresh_token"].(string))
	claims = decodeJWTUnsafe(t, second["access_token"].(string))
	assert.Equal(t, email, claims["user_email"],
		"second refresh must keep user_email — proves the rotation copies it to the successor row")
	assert.Equal(t, name, claims["user_name"])
}

// A principal with no display attributes mints exactly what it did before: no
// claim, on the code-exchange token or on a refresh.
func TestPrincipalUserEmail_AbsentWhenResolverSetsNone(t *testing.T) {
	form, verifier := authorizeBaseForm(t)
	form.Set("client_id", testMCPClientID)

	tok := exchangeCode(t, testMCPClientID, authorizeForCode(t, form), verifier)

	claims := decodeJWTUnsafe(t, tok["access_token"].(string))
	assert.NotContains(t, claims, "user_email")
	assert.NotContains(t, claims, "user_name")

	refreshed := refresh(t, testMCPClientID, tok["refresh_token"].(string))
	claims = decodeJWTUnsafe(t, refreshed["access_token"].(string))
	assert.NotContains(t, claims, "user_email")
	assert.NotContains(t, claims, "user_name")
}

// A value that could hide or reorder text on the terminal that prints it, or
// that is implausibly long, is dropped — and the login still succeeds. The
// attribute is display only; refusing the login over it would be worse than
// not showing it.
func TestPrincipalUserEmail_UnprintableOrOversizedValuesDropped(t *testing.T) {
	form, verifier := authorizeBaseForm(t)
	form.Set("test_principal_email", "evil\u202e@example.com") // RIGHT-TO-LEFT OVERRIDE
	form.Set("test_principal_name", string(make([]byte, 300))) // NULs, and too long

	tok := exchangeCode(t, testCLIClientID, authorizeForCode(t, form), verifier)

	claims := decodeJWTUnsafe(t, tok["access_token"].(string))
	assert.NotContains(t, claims, "user_email")
	assert.NotContains(t, claims, "user_name")
	assert.Equal(t, "user-authorize-test", claims["sub"], "the login itself is unaffected")
}
