package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExternalPrincipalRefreshToken is the behavioral contract for the
// self-reliant refresh-token feature that lets an embedded harness (codeoid)
// keep its session alive by rotating its own token, instead of the broker
// (Forge/Studio) re-minting on a timer.
//
// The trusted external-principal exchange, when asked (issue_refresh_token) AND
// only for a PROFILED audience:
//  1. returns a rotating refresh token alongside the short-lived access token;
//  2. rotation at /oauth2/token re-stamps the SAME `aud` + profile scopes on the
//     successor access token (so the daemon's per-message `aud` check still
//     passes) and issues a fresh refresh token;
//  3. binds the refresh token to the audience name as client_id (RFC 6749
//     §10.4) — a mismatched client_id is rejected without consuming the token;
//  4. detects reuse of a rotated token and revokes the whole family.
//
// It is a no-op without the flag (backward compatible) and ignored without a
// profiled audience (the rotation can only re-stamp a real profile).
func TestExternalPrincipalRefreshToken(t *testing.T) {
	trusted := map[string]string{testTrustedServiceHeader: "trusted-service"}
	baseExchange := func(userID string) map[string]any {
		return map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": "external-principal-assertion",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"user_id":       userID,
		}
	}

	t.Run("codeoid audience + issue_refresh_token mints a refresh token alongside the access token", func(t *testing.T) {
		b := baseExchange("codeoid-rt-001")
		b["audience"] = "codeoid"
		b["issue_refresh_token"] = true

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		out := decode(t, resp)

		access, _ := out["access_token"].(string)
		require.NotEmpty(t, access, "access token must be issued")
		refresh, ok := out["refresh_token"].(string)
		require.True(t, ok, "a refresh token must be returned when issue_refresh_token is set")
		assert.NotEmpty(t, refresh)
		assert.Contains(t, refresh, "zid_rt_", "refresh token must carry the zid_rt_ prefix")

		claims := decodeJWTPayload(t, access)
		assert.Equal(t, []string{"codeoid"}, audienceOf(t, claims), "aud must be the codeoid profile")
		assert.ElementsMatch(t, codeoidScopeProfile, scopesOf(t, claims), "scopes must be the codeoid profile set")
	})

	t.Run("no refresh token without the flag (backward compatible)", func(t *testing.T) {
		b := baseExchange("codeoid-rt-002")
		b["audience"] = "codeoid"
		// issue_refresh_token omitted → legacy access-token-only response.

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		out := decode(t, resp)

		assert.NotEmpty(t, out["access_token"], "access token must still be issued")
		assert.Empty(t, out["refresh_token"], "no refresh token unless explicitly requested")
	})

	t.Run("issue_refresh_token is ignored without a profiled audience", func(t *testing.T) {
		b := baseExchange("codeoid-rt-003")
		// No audience: rotation would have no profile to re-stamp, so the flag is
		// a no-op rather than minting an un-rotatable refresh token.
		b["issue_refresh_token"] = true

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		out := decode(t, resp)

		assert.NotEmpty(t, out["access_token"], "access token must still be issued")
		assert.Empty(t, out["refresh_token"], "refresh token requires a profiled audience")
	})

	t.Run("rotation preserves aud + scopes + subject and rotates the refresh token", func(t *testing.T) {
		b := baseExchange("codeoid-rt-004")
		b["audience"] = "codeoid"
		b["issue_refresh_token"] = true

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		initial := decode(t, resp)
		refresh := initial["refresh_token"].(string)

		// Rotate — codeoid presents the audience name as client_id (no secret;
		// it is a public, client-less audience-profile token).
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": refresh,
			"client_id":     "codeoid",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		rotated := decode(t, resp)

		newAccess := rotated["access_token"].(string)
		newRefresh, ok := rotated["refresh_token"].(string)
		require.True(t, ok, "rotation must issue a fresh refresh token")
		assert.NotEqual(t, refresh, newRefresh, "the refresh token must rotate (single-use)")

		claims := decodeJWTPayload(t, newAccess)
		assert.Equal(t, []string{"codeoid"}, audienceOf(t, claims),
			"the refreshed access token MUST keep aud=codeoid — else the daemon rejects it")
		assert.ElementsMatch(t, codeoidScopeProfile, scopesOf(t, claims),
			"the refreshed access token MUST keep the codeoid profile scopes")
		assert.Equal(t, "codeoid-rt-004", claims["sub"],
			"the refreshed token must still act AS the original external user")
	})

	t.Run("client_id mismatch on refresh is rejected without consuming the token", func(t *testing.T) {
		b := baseExchange("codeoid-rt-005")
		b["audience"] = "codeoid"
		b["issue_refresh_token"] = true

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		refresh := decode(t, resp)["refresh_token"].(string)

		// Wrong client_id → rejected. The RFC 6749 §10.4 binding is the audience
		// name; a mismatch must NOT consume the token (no reuse-detection nuke).
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": refresh,
			"client_id":     "not-codeoid",
		}, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_grant", decode(t, resp)["error"])

		// The original token still works (was not consumed by the mismatch).
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": refresh,
			"client_id":     "codeoid",
		}, nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"a client_id mismatch must not consume the refresh token")
	})

	t.Run("reuse of a rotated refresh token is rejected", func(t *testing.T) {
		b := baseExchange("codeoid-rt-006")
		b["audience"] = "codeoid"
		b["issue_refresh_token"] = true

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		original := decode(t, resp)["refresh_token"].(string)

		// First rotation succeeds (single-use).
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": original,
			"client_id":     "codeoid",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		decode(t, resp) // consume body

		// Reusing the now-rotated token must be rejected — the audience-profile
		// family participates in the same single-use rotation as every other
		// refresh token. (Family-revocation on reuse is a property of the shared
		// RotateRefreshToken path, verified in the rotation-race suite; here we
		// assert the audience path plugs into it and rejects the reuse.)
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": original,
			"client_id":     "codeoid",
		}, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "reused refresh token must be rejected")
		assert.Equal(t, "invalid_grant", decode(t, resp)["error"])
	})
}
