package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// codeoidScopeProfile is the fixed web-operator scope set the "codeoid"
// audience profile mints. It mirrors the server-defined profile in
// internal/service/oauth.go (audienceScopeProfiles) — the test asserts the
// issued token carries exactly this set, so a drift on either side fails here.
var codeoidScopeProfile = []string{
	"session:list",
	"session:create",
	"session:attach",
	"session:watch",
	"session:send",
	"session:interrupt",
	"session:approve",
	"session:destroy",
	"session:read",
	"session:dispatch",
	"fs:read",
}

// codeoidRuntimeScopeProfile mirrors audienceScopeProfiles["codeoid-runtime"]:
// the codeoid web-operator set PLUS nhi:manage, for the forge-brokered
// per-sandbox identity mint (forge #25).
var codeoidRuntimeScopeProfile = append(append([]string{}, codeoidScopeProfile...), "nhi:manage")

// audienceOf normalizes a decoded JWT `aud` claim (which JSON-encodes as either
// a bare string or an array of strings) into []string so assertions don't
// depend on the single-vs-multi audience serialization.
func audienceOf(t *testing.T, claims map[string]any) []string {
	t.Helper()
	switch v := claims["aud"].(type) {
	case nil:
		return nil
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			require.True(t, ok, "aud array element must be a string")
			out = append(out, s)
		}
		return out
	default:
		t.Fatalf("unexpected aud claim type %T", v)
		return nil
	}
}

// scopesOf normalizes a decoded JWT `scopes` claim into []string.
func scopesOf(t *testing.T, claims map[string]any) []string {
	t.Helper()
	raw, ok := claims["scopes"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		s, ok := e.(string)
		require.True(t, ok, "scopes array element must be a string")
		out = append(out, s)
	}
	return out
}

// TestExternalPrincipalExchange_AudienceProfile is the behavioral contract for
// the audience-profile feature that Studio uses to mint codeoid embedded-UI SSO
// tokens. The trusted external-principal exchange:
//  1. for audience="codeoid", stamps aud=codeoid, keeps sub=the external user,
//     and adds the FIXED server-defined web-operator scope set to `scopes`;
//  2. NEVER honours caller-supplied scopes for a profiled audience — the
//     profile is the whole authority, so a caller cannot widen the token;
//  3. leaves issuance unchanged when no audience (default aud=issuer, no codeoid
//     scopes) or an unknown audience is supplied.
func TestExternalPrincipalExchange_AudienceProfile(t *testing.T) {
	baseExchange := func(userID string) map[string]any {
		return map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
			// Not verified on the external-principal path — trust comes from the
			// TrustedServiceValidator, not the subject_token signature.
			"subject_token": "external-principal-assertion",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"user_id":       userID,
		}
	}
	trusted := map[string]string{testTrustedServiceHeader: "trusted-service"}

	t.Run("codeoid audience stamps aud + fixed scope set, keeps user subject", func(t *testing.T) {
		b := baseExchange("codeoid-user-001")
		b["audience"] = "codeoid"

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		assert.Equal(t, []string{"codeoid"}, audienceOf(t, claims),
			"aud must be stamped to the audience-profile name")
		assert.Equal(t, "codeoid-user-001", claims["sub"],
			"sub must remain the external user, unchanged by the audience profile")
		assert.ElementsMatch(t, codeoidScopeProfile, scopesOf(t, claims),
			"scopes must be exactly the server-defined codeoid web-operator set")
	})

	t.Run("codeoid audience ignores caller-supplied scopes (never widened)", func(t *testing.T) {
		b := baseExchange("codeoid-user-002")
		b["audience"] = "codeoid"
		// An attacker-style attempt to widen authority via the scope parameter —
		// must be dropped in favour of the hard-coded profile.
		b["scope"] = "admin:* fs:write session:list"

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		got := scopesOf(t, claims)
		assert.ElementsMatch(t, codeoidScopeProfile, got,
			"caller scopes must never be honoured for a profiled audience")
		assert.NotContains(t, got, "admin:*", "caller scope must not leak into a profiled token")
		assert.NotContains(t, got, "fs:write", "caller scope must not leak into a profiled token")
	})

	t.Run("codeoid-runtime audience adds nhi:manage for the per-sandbox mint", func(t *testing.T) {
		b := baseExchange("codeoid-user-005")
		b["audience"] = "codeoid-runtime"

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		assert.Equal(t, []string{"codeoid-runtime"}, audienceOf(t, claims),
			"aud must be stamped to codeoid-runtime")
		assert.Equal(t, "codeoid-user-005", claims["sub"],
			"sub must remain the external user — the forge-brokered token acts AS the user")
		got := scopesOf(t, claims)
		assert.ElementsMatch(t, codeoidRuntimeScopeProfile, got,
			"codeoid-runtime must carry the web-operator set PLUS nhi:manage")
		assert.Contains(t, got, "nhi:manage",
			"nhi:manage is what lets the forge-brokered token register the sandbox identity")
	})

	t.Run("no audience leaves issuance unchanged (default aud, no codeoid scopes)", func(t *testing.T) {
		b := baseExchange("plain-user-003")

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		_ = resp.Body.Close()

		assert.Equal(t, []string{testIssuer}, audienceOf(t, claims),
			"aud defaults to the issuer when no audience is requested")
		assert.Empty(t, scopesOf(t, claims),
			"no audience ⇒ no codeoid scopes on the token")
	})

	t.Run("unknown audience is rejected with invalid_target", func(t *testing.T) {
		b := baseExchange("plain-user-004")
		b["audience"] = "not-a-real-profile"

		resp := post(t, "/oauth2/token", b, trusted)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"a non-empty audience that names no known profile must be rejected, "+
				"not silently downgraded to a default token")
		body := decode(t, resp)

		assert.Equal(t, "invalid_target", body["error"],
			"RFC 8693 §2.2.2: an unrecognized audience is rejected with invalid_target")
	})
}
