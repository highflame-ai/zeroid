package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// token.require_dpop closes the Bearer fallback: every /oauth2/token issuance
// must carry a valid RFC 9449 proof (the ODIS-L1-09 holder-of-key posture).
// The flag defaults to false; tests toggle it via Server.SetDPoPRequired,
// mirroring the SetAttestationPermissive pattern.

func TestRequireDPoPRefusesProoflessIssuance(t *testing.T) {
	testZeroIDServer.SetDPoPRequired(true)
	t.Cleanup(func() { testZeroIDServer.SetDPoPRequired(false) })

	agentID := uid("require-dpop")
	registerIdentity(t, agentID, []string{"billing:read"})
	client := registerOAuthClient(t, agentID, []string{"billing:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "billing:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"proof-less issuance must be refused under require_dpop")
	body := decode(t, resp)
	assert.Equal(t, "invalid_dpop_proof", body["error"])
}

func TestRequireDPoPIssuesBoundTokenWithProof(t *testing.T) {
	testZeroIDServer.SetDPoPRequired(true)
	t.Cleanup(func() { testZeroIDServer.SetDPoPRequired(false) })

	agentID := uid("require-dpop-ok")
	registerIdentity(t, agentID, []string{"billing:read"})
	client := registerOAuthClient(t, agentID, []string{"billing:read"})

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildDPoPProof(t, dpopKey, http.MethodPost, testServer.URL+"/oauth2/token", uuid.New().String())

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "billing:read",
	}, map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)
	assert.Equal(t, "DPoP", token["token_type"])
}

func TestRequireDPoPAdvertisedInASMetadata(t *testing.T) {
	// Default off: advertised false (RFC 9449 §5.1 boolean, explicit).
	resp := get(t, "/.well-known/oauth-authorization-server", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, false, decode(t, resp)["dpop_bound_access_tokens_required"])

	testZeroIDServer.SetDPoPRequired(true)
	t.Cleanup(func() { testZeroIDServer.SetDPoPRequired(false) })

	resp = get(t, "/.well-known/oauth-authorization-server", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, true, decode(t, resp)["dpop_bound_access_tokens_required"],
		"require_dpop must be advertised per RFC 9449 §5.1")
}
