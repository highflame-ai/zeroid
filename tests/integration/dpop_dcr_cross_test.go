// Cross-feature tests for DPoP × DCR + the boundaries where prior bugs hid.
// The complementary suites (`dpop_*_test.go`, `dcr_compliance_test.go`,
// `dynamic_registration_test.go`) cover each feature in isolation; this file
// covers the *compositions* — historically where regressions land.

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

// registerDCRClient performs a complete RFC 7591 registration and returns the
// freshly-minted client_id and client_secret ready to use in /oauth2/token.
func registerDCRClient(t *testing.T, clientName string, grantTypes []string, scope string) (clientID, clientSecret string) {
	t.Helper()
	iat := issueClientRegisterToken(t)
	body := map[string]any{
		"client_name": clientName,
		"grant_types": grantTypes,
	}
	if scope != "" {
		body["scope"] = scope
	}
	resp := post(t, "/oauth2/register", body,
		map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	r := decode(t, resp)
	clientID, _ = r["client_id"].(string)
	clientSecret, _ = r["client_secret"].(string)
	require.NotEmpty(t, clientID)
	require.NotEmpty(t, clientSecret)
	return
}

// TestDCRClient_ClientCredentialsRoundTrip is the regression guard for the
// pre-merge blocker: a DCR-registered client was 500-ing on
// /oauth2/register because the OAuthClient row violated the
// backchannel_token_delivery_mode CHECK constraint. The full POST →
// register → /oauth2/token chain proves the row is valid AND surfaces the
// specific OAuth error that today distinguishes "DCR client exists, ZeroID
// can't issue tokens to it" from infrastructure failures.
//
// Current behaviour (pinned by this test): DCR-registered clients are NOT
// linked to a zeroid Identity at registration time (the platform issues
// no identity-binding contract through DCR), so /oauth2/token rejects
// with HTTP 401 and `error: invalid_client` carrying an error_description
// that names the missing-identity cause. If the platform ever decides to
// support identity-less DCR clients (or to require identity binding at
// registration), this test pins the contract that today's behaviour is.
func TestDCRClient_ClientCredentialsRoundTrip(t *testing.T) {
	clientID, clientSecret := registerDCRClient(t,
		"cross-dcr-cc-roundtrip", []string{"client_credentials"}, "data:read")

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}, nil)

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"DCR client without identity binding gets 401 invalid_client, not 5xx (regression guard for the migration-021 CHECK-constraint blocker)")
	body := decode(t, resp)
	assert.Equal(t, "invalid_client", body["error"],
		"OAuth error code for identity-less DCR client must be invalid_client")
	desc, _ := body["error_description"].(string)
	assert.Contains(t, desc, "no identity found",
		"error_description must name the cause — proves the dispatcher reached the identity-resolution step, i.e. the registration row is valid")
}

// TestDCRClient_TokenExchangeRejected verifies the policy boundary end-to-end:
// the DCR allow-list excludes token_exchange, and a DCR-registered client
// must not be able to even register with it (the register call rejects).
// This is the regression guard for the security-review finding that DCR
// clients can't legitimately be delegation actors.
func TestDCRClient_TokenExchangeRejected(t *testing.T) {
	iat := issueClientRegisterToken(t)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "cross-dcr-token-exchange",
		"grant_types": []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"DCR registration with token_exchange MUST be rejected — DCR clients have no IdentityID and cannot act as delegation actors")
	body := decode(t, resp)
	assert.Equal(t, "invalid_client_metadata", body["error"])
}

// TestDCRClient_DPoPBoundTokenIssuance exercises the full DPoP × DCR loop:
// self-register, then immediately use that client to obtain a token while
// presenting a DPoP proof. The DCR client_id and client_secret are the only
// state the caller persists; the DPoP key is held only in process memory.
//
// Pins the cross-feature property: DPoP validation runs cleanly first
// (proof is well-formed, jti recorded, thumbprint computed) and only then
// does the request reach the grant dispatcher. Because today's
// DCR-registered clients have no identity binding, the dispatcher returns
// invalid_client — same as TestDCRClient_ClientCredentialsRoundTrip. The
// presence of a valid DPoP proof must not change THAT outcome (a stolen
// secret presenting a perfect DPoP proof still can't unlock an
// identity-less client) and must not 5xx through the proof-validation path
// either (regression guard for any path that might have leaked DPoP
// failures as 500s).
func TestDCRClient_DPoPBoundTokenIssuance(t *testing.T) {
	clientID, clientSecret := registerDCRClient(t,
		"cross-dcr-dpop", []string{"client_credentials"}, "data:read")

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildDPoPProof(t, dpopKey, http.MethodPost,
		testServer.URL+"/oauth2/token", uuid.New().String())

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}, map[string]string{"DPoP": proof})

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"DCR+DPoP composition must reach the identity-resolution step (401 invalid_client), not 5xx through DPoP validation")
	body := decode(t, resp)
	assert.Equal(t, "invalid_client", body["error"],
		"a valid DPoP proof does not unlock an identity-less client; the underlying invalid_client error stands")
	desc, _ := body["error_description"].(string)
	assert.Contains(t, desc, "no identity found",
		"error_description must come from the identity-resolution step — proves DPoP validation completed without short-circuiting")
}

// TestDPoPTokenExchange_PropagatesBindingToSubAgent walks the full RFC 8693
// token_exchange delegation hop end-to-end and verifies that the binding
// follows the *per-call* DPoP proof — not anything persisted from upstream:
//
//  1. Orchestrator gets a client_credentials token under DPoP key K1.
//     Issued JWT carries cnf.jkt = thumbprint(K1).
//  2. Sub-agent (distinct identity, ECDSA keypair K2 for its actor assertion)
//     and the orchestrator together call /oauth2/token grant=token-exchange.
//     The DPoP proof on *this* request is signed by a fresh key K3 (which is
//     intentionally different from both K1 and K2 to prove the binding is
//     independent of both upstream parties).
//  3. The delegated token returned to the sub-agent MUST carry
//     cnf.jkt = thumbprint(K3) — the proof from THIS request, not the
//     orchestrator's K1 and not the actor's signing key K2.
//
// This is the cross-feature property the security review highlighted:
// each IssueCredential call site has its own DPoPKeyThumbprint, and the
// binding cannot leak across hops.
func TestDPoPTokenExchange_PropagatesBindingToSubAgent(t *testing.T) {
	// Orchestrator: NHI identity, DPoP-bound token under K1.
	orchID := uid("cross-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	orchKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	orchProof := buildDPoPProof(t, orchKey, http.MethodPost,
		testServer.URL+"/oauth2/token", uuid.New().String())

	orchResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}, map[string]string{"DPoP": orchProof})
	require.Equal(t, http.StatusOK, orchResp.StatusCode)
	orchToken, _ := decode(t, orchResp)["access_token"].(string)
	require.NotEmpty(t, orchToken)
	// Sanity: orchestrator's token IS bound to K1.
	orchIntrospect := introspect(t, orchToken)
	orchCnf, ok := orchIntrospect["cnf"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, dpopKeyThumbprint(t, &orchKey.PublicKey), orchCnf["jkt"])

	// Sub-agent: distinct identity with its own ECDSA keypair K2 (signs the
	// actor assertion required for jwt_bearer-style delegation).
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("cross-sub")
	subIdentity := registerIdentity(t, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))
	actorAssertion := buildAssertion(t, subKey, subIdentity.WIMSEURI)

	// K3: the proof key on THIS token_exchange request. Distinct from K1
	// (orchestrator's binding) and K2 (sub-agent's actor signing key) so
	// the assertion below is unambiguous.
	hopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	hopProof := buildDPoPProof(t, hopKey, http.MethodPost,
		testServer.URL+"/oauth2/token", uuid.New().String())

	exchResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, map[string]string{"DPoP": hopProof})
	require.Equal(t, http.StatusOK, exchResp.StatusCode)
	exchBody := decode(t, exchResp)
	assert.Equal(t, "DPoP", exchBody["token_type"],
		"delegated token must report token_type=DPoP because the hop carried a valid proof")

	delegatedToken, _ := exchBody["access_token"].(string)
	require.NotEmpty(t, delegatedToken)

	// Introspect the delegated token: cnf.jkt MUST be K3's thumbprint,
	// proving the binding follows the per-call proof and is not inherited
	// from the orchestrator's K1 or the actor's K2.
	delResult := introspect(t, delegatedToken)
	cnf, ok := delResult["cnf"].(map[string]any)
	require.True(t, ok, "delegated token MUST carry cnf when the exchange call presented DPoP")
	jkt, _ := cnf["jkt"].(string)
	assert.Equal(t, dpopKeyThumbprint(t, &hopKey.PublicKey), jkt,
		"binding MUST track THIS request's proof key (K3), not the orchestrator's K1 or the actor's K2")
	assert.NotEqual(t, dpopKeyThumbprint(t, &orchKey.PublicKey), jkt,
		"explicit anti-leak assertion: the orchestrator's binding K1 must NOT propagate downstream")
	assert.NotEqual(t, dpopKeyThumbprint(t, &subKey.PublicKey), jkt,
		"explicit anti-leak assertion: the sub-agent's signing key K2 must NOT become the cnf binding")
}
