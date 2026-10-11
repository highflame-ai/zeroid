package integration_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// A CIBA request made with a requesting_token is redeemed only by a poll that
// presents that same token (requesting_token parameter), and, when that token
// is DPoP-bound, a DPoP proof for its key. The approved token keeps the
// requesting token's cnf.jkt.

func TestCIBAChainRedemptionRequiresRequestingToken(t *testing.T) {
	alice := externalPrincipalToken(t, testAccountID, testProjectID, "alice")
	c := newConfidentialCIBAClient(t)
	resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": "user-a", "requesting_token": alice})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)
	repo := postgres.NewBackchannelRequestRepository(testDB)

	t.Run("PendingWithoutToken_AccessDenied", func(t *testing.T) {
		status, body := pollCIBARaw(t, c, id)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "access_denied", body["error"])
	})

	approveAs(t, id, "user-a")

	t.Run("WithoutToken_AccessDenied", func(t *testing.T) {
		status, body := pollCIBARaw(t, c, id)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "access_denied", body["error"])
	})

	t.Run("OtherValidToken_AccessDenied", func(t *testing.T) {
		other := externalPrincipalToken(t, testAccountID, testProjectID, "alice")
		status, body := pollCIBARaw(t, c, id, other)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "access_denied", body["error"])
	})

	t.Run("MalformedToken_AccessDenied", func(t *testing.T) {
		status, body := pollCIBARaw(t, c, id, "not-a-token")
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "access_denied", body["error"])
	})

	require.Equal(t, domain.BackchannelStatusApproved, loadBackchannelRow(t, repo, id).Status,
		"a refused poll must not consume the approval")

	claims := decodeJWTPayload(t, pollCIBA(t, c, id, alice)["access_token"].(string))
	require.Equal(t, "alice", claims["sub"])
	require.Equal(t, domain.BackchannelStatusIssued, loadBackchannelRow(t, repo, id).Status)
}

// TestCIBARootRequestPollUnchanged: a request made without requesting_token
// is redeemed as before, with no extra parameter.
func TestCIBARootRequestPollUnchanged(t *testing.T) {
	c := newConfidentialCIBAClient(t)
	resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": "user-a"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)
	approveAs(t, id, "user-a")
	claims := decodeJWTPayload(t, pollCIBA(t, c, id)["access_token"].(string))
	require.Equal(t, "user-a", claims["sub"])
}

func TestCIBAChainRedemptionKeepsDPoPBinding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](&key.PublicKey)
	require.NoError(t, err)
	tp, err := pubJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	jkt := base64.RawURLEncoding.EncodeToString(tp)

	externalID := uid("ciba-dpop-agent")
	reg := post(t, adminPath("/agents/register"), map[string]any{
		"name": externalID, "external_id": externalID, "sub_type": "tool_agent",
		"trust_level": "first_party", "created_by": "user-owner-1",
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, reg.StatusCode)
	apiKey, _ := decode(t, reg)["api_key"].(string)
	tr := post(t, "/oauth2/token", map[string]any{"grant_type": "api_key", "api_key": apiKey},
		map[string]string{"DPoP": buildCustomDPoPProof(t, key, nil, nil)})
	require.Equal(t, http.StatusOK, tr.StatusCode)
	agentToken, _ := decode(t, tr)["access_token"].(string)
	cnf, _ := decodeJWTPayload(t, agentToken)["cnf"].(map[string]any)
	require.Equal(t, jkt, cnf["jkt"], "the requesting token is DPoP-bound")

	c := newConfidentialCIBAClient(t)
	resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": "user-a", "requesting_token": agentToken})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)
	approveAs(t, id, "user-a")

	t.Run("NoProof_AccessDenied", func(t *testing.T) {
		status, body := pollCIBARaw(t, c, id, agentToken)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "access_denied", body["error"])
	})

	t.Run("ProofForOtherKey_AccessDenied", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		status, body := pollCIBAWithHeaders(t, c, id,
			map[string]string{"DPoP": buildCustomDPoPProof(t, other, nil, nil)}, agentToken)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "access_denied", body["error"])
	})

	require.Equal(t, domain.BackchannelStatusApproved,
		loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id).Status)

	status, body := pollCIBAWithHeaders(t, c, id,
		map[string]string{"DPoP": buildCustomDPoPProof(t, key, nil, nil)}, agentToken)
	require.Equal(t, http.StatusOK, status, "poll: %v", body)
	require.Equal(t, "DPoP", body["token_type"])
	claims := decodeJWTPayload(t, body["access_token"].(string))
	approvedCnf, _ := claims["cnf"].(map[string]any)
	require.Equal(t, jkt, approvedCnf["jkt"], "the approved token keeps the requesting token's key binding")
}
