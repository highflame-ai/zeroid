package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// revokeStatus posts an RFC 7009 revocation request and returns the status and
// decoded body.
func revokeStatus(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	resp := post(t, "/oauth2/token/revoke", body, nil)
	return resp.StatusCode, decode(t, resp)
}

// TestRevokeRefreshToken pins RFC 7009 §2 for refresh tokens: the revocation
// endpoint MUST support them. Revoking one ends the grant — every refresh
// token in its family — and, per §2.1's SHOULD, the access tokens issued from
// it. Before this, an opaque refresh token was "not found" by the JWT-only
// lookup, the endpoint answered 200 {"revoked": true}, and the token kept
// refreshing.
func TestRevokeRefreshToken(t *testing.T) {
	for _, hint := range []string{"", "refresh_token", "access_token", "not_a_registered_hint"} {
		t.Run("hint="+hint, func(t *testing.T) {
			at1, rt1 := exchangeMCPCode(t, uid("user-revoke-rt"))
			status, body := refreshMCP(t, rt1)
			require.Equal(t, http.StatusOK, status)
			rt2 := body["refresh_token"].(string)
			at2 := body["access_token"].(string)

			req := map[string]any{"token": rt2, "client_id": testMCPClientID}
			if hint != "" {
				req["token_type_hint"] = hint
			}
			status, body = revokeStatus(t, req)
			require.Equal(t, http.StatusOK, status, "%v", body)
			assert.Equal(t, true, body["revoked"])

			// Access tokens first: presenting the revoked refresh token below is
			// itself reuse, which would revoke them too and mask a missing
			// cascade here.
			assert.False(t, introspect(t, at1)["active"].(bool),
				"the exchange's access token is revoked with the grant (RFC 7009 §2.1 SHOULD)")
			assert.False(t, introspect(t, at2)["active"].(bool),
				"the refreshed access token is revoked with the grant (RFC 7009 §2.1 SHOULD)")

			status, body = refreshMCP(t, rt2)
			assert.Equal(t, http.StatusBadRequest, status, "a revoked refresh token must not refresh")
			assert.Equal(t, "invalid_grant", body["error"])
		})
	}
}

// Presenting a rotated-out refresh token for revocation still names the
// grant: the family, including the newest token, is revoked.
func TestRevokeRefreshToken_RotatedOutTokenRevokesFamily(t *testing.T) {
	_, rt1 := exchangeMCPCode(t, uid("user-revoke-rt-old"))
	status, body := refreshMCP(t, rt1)
	require.Equal(t, http.StatusOK, status)
	rt2 := body["refresh_token"].(string)

	status, _ = revokeStatus(t, map[string]any{"token": rt1, "client_id": testMCPClientID})
	require.Equal(t, http.StatusOK, status)

	status, _ = refreshMCP(t, rt2)
	assert.Equal(t, http.StatusBadRequest, status, "the family's newest token is revoked too")
}

// With no client identified, possession of the refresh token authorizes its
// revocation — the rule this endpoint applies to access tokens.
func TestRevokeRefreshToken_Anonymous(t *testing.T) {
	_, rt := exchangeMCPCode(t, uid("user-revoke-rt-anon"))

	status, _ := revokeStatus(t, map[string]any{"token": rt, "token_type_hint": "refresh_token"})
	require.Equal(t, http.StatusOK, status)

	status, _ = refreshMCP(t, rt)
	assert.Equal(t, http.StatusBadRequest, status)
}

// A client may only revoke refresh tokens issued to it (RFC 7009 §2.1). A
// request from another client gets the same 200 and body — the endpoint does
// not reveal whose token it was — and the token keeps working.
func TestRevokeRefreshToken_OtherClientCannotRevoke(t *testing.T) {
	at, rt := exchangeMCPCode(t, uid("user-revoke-rt-other"))

	_, ownBody := revokeStatus(t, map[string]any{"token": "zid_rt_" + uid("never-issued"), "client_id": testCLIClientID})
	status, body := revokeStatus(t, map[string]any{"token": rt, "client_id": testCLIClientID})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, ownBody, body, "a foreign token is answered like an unknown one")

	assert.True(t, introspect(t, at)["active"].(bool), "the owner's access token is untouched")
	status, _ = refreshMCP(t, rt)
	assert.Equal(t, http.StatusOK, status, "the owner's refresh token still works")
}

// An unknown or malformed token is still a 200 (RFC 7009 §2.2).
func TestRevokeRefreshToken_UnknownTokenIs200(t *testing.T) {
	for _, tok := range []string{"zid_rt_" + uid("unknown"), "not-a-token", "a.b.c"} {
		status, body := revokeStatus(t, map[string]any{"token": tok, "token_type_hint": "refresh_token"})
		assert.Equal(t, http.StatusOK, status, "token %q: %v", tok, body)
	}
}

// When the server cannot carry out the revocation it must say so, not answer
// 200: a client is told not to use a token after a 200 (RFC 7009 §2.1), and
// would drop a token that is in fact still live. Forced here with a trigger
// that rejects the family revocation for one user.
func TestRevokeRefreshToken_ServerFailureIsNotReportedAsSuccess(t *testing.T) {
	ctx := context.Background()
	user := uid("user-revoke-rt-fail")
	_, rt := exchangeMCPCode(t, user)

	fn := "zeroid_test_fail_revoke_" + strings.ReplaceAll(uid(""), "-", "_")
	_, err := testDB.ExecContext(ctx, fmt.Sprintf(`
CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF NEW.user_id = '%[2]s' AND NEW.state = 'revoked' THEN
		RAISE EXCEPTION 'forced failure for %[2]s';
	END IF;
	RETURN NEW;
END $$;
CREATE TRIGGER %[1]s BEFORE UPDATE ON refresh_tokens
	FOR EACH ROW EXECUTE FUNCTION %[1]s();`, fn, user))
	require.NoError(t, err)
	dropped := false
	drop := func() {
		if !dropped {
			dropped = true
			_, err := testDB.ExecContext(ctx, fmt.Sprintf(
				"DROP TRIGGER IF EXISTS %[1]s ON refresh_tokens; DROP FUNCTION IF EXISTS %[1]s();", fn))
			require.NoError(t, err)
		}
	}
	t.Cleanup(drop)

	status, body := revokeStatus(t, map[string]any{"token": rt, "client_id": testMCPClientID})
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Equal(t, "server_error", body["error"])
	assert.NotEqual(t, true, body["revoked"])
	assert.NotContains(t, fmt.Sprint(body), "forced failure", "the cause stays server-side")

	drop()
	status, _ = refreshMCP(t, rt)
	assert.Equal(t, http.StatusOK, status, "precondition of the assertion above: the token was in fact still live")
}

// A wrong hint does not stop the search (RFC 7009 §2.1): an access token
// presented with token_type_hint=refresh_token is still revoked.
func TestRevokeAccessTokenWithRefreshHint(t *testing.T) {
	at, rt := exchangeMCPCode(t, uid("user-revoke-at-hint"))

	status, _ := revokeStatus(t, map[string]any{"token": at, "token_type_hint": "refresh_token", "client_id": testMCPClientID})
	require.Equal(t, http.StatusOK, status)
	assert.False(t, introspect(t, at)["active"].(bool))

	// Revoking an access token leaves its refresh token alone (RFC 7009 §2.1
	// makes that cascade a MAY; it is not done).
	status, _ = refreshMCP(t, rt)
	assert.Equal(t, http.StatusOK, status)
}
