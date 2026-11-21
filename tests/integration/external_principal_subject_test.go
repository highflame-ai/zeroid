// The external-principal exchange verifies the subject it is given and never
// mints a person token for a workload URI; and the claims receivers rely on
// to identify an internal service token are never settable by a caller.
package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var trustedServiceHeaders = map[string]string{testTrustedServiceHeader: "trusted-service"}

// brokerExchange is the external-principal exchange on the token endpoint:
// token-exchange with a subject_token and no actor_token.
func brokerExchange(subject, accountID, projectID, userID string) map[string]any {
	return map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": subject,
		"account_id":    accountID,
		"project_id":    projectID,
		"user_id":       userID,
	}
}

// ── Reserved claims ──────────────────────────────────────────────────────────

// A receiver trusts tenant_source, resolved_user_id/_source and act.client_id
// to be ZeroID's own. additional_claims must not reach any of them, on either
// external-principal entry point.
func TestServiceClaims_NotSettableThroughAdditionalClaims(t *testing.T) {
	forged := map[string]any{
		"tenant_source":        "proven",
		"resolved_user_id":     "victim",
		"resolved_user_source": "subject",
		"act":                  map[string]any{"sub": "spiffe://zeroid.dev/platform/p/service/gw", "client_id": "gw"},
	}
	user := uid("svc-claims-user")
	for name, body := range map[string]map[string]any{
		"session grant": {
			"grant_type": testUserSessionGrant, "account_id": testAccountID, "project_id": testProjectID, "user_id": user,
		},
		"token exchange": brokerExchange(personToken(t, testAccountID, testProjectID, user), testAccountID, testProjectID, user),
	} {
		t.Run(name, func(t *testing.T) {
			body["additional_claims"] = forged
			resp := post(t, "/oauth2/token", body, trustedServiceHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode, "reserved claims are dropped, not fatal")
			claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
			for _, k := range []string{"tenant_source", "resolved_user_id", "resolved_user_source", "act"} {
				assert.NotContains(t, claims, k, "%s must never come from additional_claims", k)
			}
		})
	}
}

// ── External-principal exchange ──────────────────────────────────────────────

func TestExternalPrincipalExchange_RefusesWorkloadUserID(t *testing.T) {
	for _, user := range []string{"spiffe://zeroid.dev/acct/proj/agent/a", "SPIFFE://zeroid.dev/acct/proj/agent/a"} {
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type": testUserSessionGrant, "account_id": testAccountID, "project_id": testProjectID, "user_id": user,
		}, trustedServiceHeaders)
		body := decode(t, resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
		assert.Equal(t, "invalid_request", body["error"])
	}
}

func TestExternalPrincipalExchange_VerifiesSubjectToken(t *testing.T) {
	user := uid("ep-subject")
	subject := personToken(t, testAccountID, testProjectID, user)

	t.Run("a subject for the same person and tenant is accepted", func(t *testing.T) {
		resp := post(t, "/oauth2/token", brokerExchange(subject, testAccountID, testProjectID, user), trustedServiceHeaders)
		body := decode(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
		assert.Equal(t, user, decodeJWTPayload(t, body["access_token"].(string))["sub"])
	})

	refused := func(t *testing.T, body map[string]any) {
		t.Helper()
		resp := post(t, "/oauth2/token", body, trustedServiceHeaders)
		got := decode(t, resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", got)
		assert.Equal(t, "invalid_grant", got["error"])
		assert.Empty(t, got["access_token"])
	}

	t.Run("another person is refused", func(t *testing.T) {
		refused(t, brokerExchange(subject, testAccountID, testProjectID, uid("someone-else")))
	})
	t.Run("another tenant is refused", func(t *testing.T) {
		refused(t, brokerExchange(subject, uid("other-acct"), testProjectID, user))
		refused(t, brokerExchange(subject, testAccountID, uid("other-proj"), user))
	})
	t.Run("a token that is not this server's is refused", func(t *testing.T) {
		refused(t, brokerExchange("not-a-token", testAccountID, testProjectID, user))
		refused(t, brokerExchange(subject+"x", testAccountID, testProjectID, user))
	})
	t.Run("a workload token names no person", func(t *testing.T) {
		policyID := createRichCredentialPolicy(t, map[string]any{
			"name": uid("ep-wl"), "allowed_grant_types": []string{"client_credentials"}, "allowed_scopes": []string{"data:read"},
		}, adminHeaders())
		_, _, workload := issueRootCredential(t, policyID, "ep-wl", []string{"data:read"})
		// Its owner is a person, but the token does not act for one.
		refused(t, brokerExchange(workload, testAccountID, testProjectID, "user-test-owner"))
	})
	t.Run("a revoked subject is refused", func(t *testing.T) {
		revokedUser := uid("ep-revoked")
		tok := personToken(t, testAccountID, testProjectID, revokedUser)
		rv := post(t, "/oauth2/token/revoke", map[string]string{"token": tok}, nil)
		require.Less(t, rv.StatusCode, 300)
		_ = rv.Body.Close()
		refused(t, brokerExchange(tok, testAccountID, testProjectID, revokedUser))
	})

	t.Run("the opt-out restores the unverified behaviour", func(t *testing.T) {
		testZeroIDServer.SetAllowUnverifiedExternalPrincipalSubject(true)
		t.Cleanup(func() { testZeroIDServer.SetAllowUnverifiedExternalPrincipalSubject(false) })
		resp := post(t, "/oauth2/token", brokerExchange("opaque-assertion", testAccountID, testProjectID, user), trustedServiceHeaders)
		body := decode(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)

		// The workload-URI refusal does not depend on the opt-out.
		resp = post(t, "/oauth2/token", brokerExchange("opaque-assertion", testAccountID, testProjectID, "spiffe://zeroid.dev/a/p/agent/x"), trustedServiceHeaders)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("an untrusted caller is refused before the subject is looked at", func(t *testing.T) {
		resp := post(t, "/oauth2/token", brokerExchange(subject, testAccountID, testProjectID, user), nil)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		_ = resp.Body.Close()
	})
}
