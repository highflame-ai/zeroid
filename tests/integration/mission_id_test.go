package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMissionID_ChainPropagation pins the issue #81 invariant: every
// credential in a delegation tree carries the same mission_id, and the
// admin filter `GET /credentials?mission_id=<id>` returns the whole
// chain ordered root → leaves.
//
// Builds a 3-node chain:
//
//	client_credentials  (orchestrator)              depth 0
//	   └── token_exchange  (sub-agent A)            depth 1
//	          └── token_exchange  (sub-agent B)     depth 2
//
// The orchestrator's credential is the mission root; mission_id =
// orchestrator's own JTI. Both sub-agent credentials propagate the same
// mission_id from the subject_token they were issued against.
func TestMissionID_ChainPropagation(t *testing.T) {
	// ── Step 0: depth-5 policy that all three identities share so
	// nothing in this test trips on the delegation-depth ceiling. ──
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("mission-policy"),
		"allowed_grant_types":  []string{"client_credentials", "token_exchange"},
		"allowed_scopes":       []string{"data:read"},
		"max_delegation_depth": 5,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	// ── Step 1: register the orchestrator with a confidential OAuth
	// client; issue its root credential via client_credentials. ──
	orchExtID := uid("mission-orch")
	registerIdentityWithPolicy(t, orchExtID, policyID, "", []string{"data:read"}, adminHeaders())
	orchClient := registerOAuthClient(t, orchExtID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "orchestrator client_credentials: expected 200")
	orchToken := decode(t, resp)["access_token"].(string)

	orchClaims := decodeJWTUnsafe(t, orchToken)
	rootMission := orchClaims["mission_id"].(string)
	rootJTI := orchClaims["jti"].(string)
	assert.Equal(t, rootJTI, rootMission,
		"first issuance: mission_id defaults to this credential's own jti")

	// ── Step 2: register sub-agent A with its own keypair, exchange
	// orchestrator's token for A's depth-1 token. ──
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	extA := uid("mission-agent-a")
	registerIdentityWithPolicy(t, extA, policyID, ecPublicKeyPEM(t, keyA),
		[]string{"data:read"}, adminHeaders())
	wimseA := fetchIdentityWIMSEByExternalID(t, extA)

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   buildAssertion(t, keyA, wimseA),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "depth-1 token_exchange: expected 200")
	tokenA := decode(t, resp)["access_token"].(string)

	claimsA := decodeJWTUnsafe(t, tokenA)
	assert.Equal(t, rootMission, claimsA["mission_id"],
		"depth-1: mission_id must propagate from orchestrator's subject_token")

	// ── Step 3: register sub-agent B; exchange A's token for B's
	// depth-2 token. ──
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	extB := uid("mission-agent-b")
	registerIdentityWithPolicy(t, extB, policyID, ecPublicKeyPEM(t, keyB),
		[]string{"data:read"}, adminHeaders())
	wimseB := fetchIdentityWIMSEByExternalID(t, extB)

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": tokenA,
		"actor_token":   buildAssertion(t, keyB, wimseB),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "depth-2 token_exchange: expected 200")
	tokenB := decode(t, resp)["access_token"].(string)

	claimsB := decodeJWTUnsafe(t, tokenB)
	assert.Equal(t, rootMission, claimsB["mission_id"],
		"depth-2: mission_id must propagate transitively through the chain")

	// ── Step 4: the headline filter must return all 3 in root → leaves
	// order. ──
	listResp := get(t,
		adminPath("/credentials?mission_id="+url.QueryEscape(rootMission)),
		adminHeaders())
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	body := decode(t, listResp)
	creds, _ := body["credentials"].([]any)
	require.Len(t, creds, 3, "GET /credentials?mission_id=<id> must return all 3 chain credentials")

	// Order: depth ASC, then issued_at ASC. Verify by depth column.
	depths := []int{}
	for _, c := range creds {
		m := c.(map[string]any)
		assert.Equal(t, rootMission, m["mission_id"],
			"every returned credential must carry the queried mission_id")
		// JSON numbers decode as float64; cast.
		d, _ := m["delegation_depth"].(float64)
		depths = append(depths, int(d))
	}
	assert.Equal(t, []int{0, 1, 2}, depths,
		"credentials must be ordered root → leaves by delegation_depth")
}

// TestMissionID_RejectAmbiguousFilter pins the handler-level guard:
// the new mission_id query is mutually exclusive with the existing
// identity_id query. Both omitted = 400 (no dump-everything path).
// Both supplied = 400 (ambiguous intent).
func TestMissionID_RejectAmbiguousFilter(t *testing.T) {
	// No filter at all.
	resp := get(t, adminPath("/credentials"), adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"GET /credentials with neither identity_id nor mission_id must 400")

	// Both filters together.
	resp2 := get(t,
		adminPath("/credentials?identity_id=00000000-0000-0000-0000-000000000000&mission_id=anything"),
		adminHeaders())
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode,
		"GET /credentials with both identity_id and mission_id must 400")
}

// decodeJWTUnsafe parses a JWT WITHOUT signature verification — fine for
// test assertions on claim values, never for trust decisions.
func decodeJWTUnsafe(t *testing.T, token string) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseInsecure([]byte(token))
	require.NoError(t, err, "ParseInsecure")
	out := map[string]any{}
	for k, v := range parsed.Claims() {
		out[k] = v
	}
	return out
}
