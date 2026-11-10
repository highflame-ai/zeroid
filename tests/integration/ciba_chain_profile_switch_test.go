package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A CIBA step-up into a delegation chain is issued in the shape of the token
// profile in effect when it is minted, whichever profile the chain's earlier
// tokens were minted under, and always carries the actor's attributes (#411).

// cibaClient registers a confidential CIBA client in the tenant.
func (tn hrdTenant) cibaClient(t *testing.T) cibaClient {
	t.Helper()
	id := uid("ciba-switch")
	resp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id": id, "name": id, "confidential": true,
		"grant_types": []string{zeroidGrantTypeCIBA},
	}, tn.headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	secret, _ := decode(t, resp)["client_secret"].(string)
	require.NotEmpty(t, secret)
	return cibaClient{ID: id, Secret: secret}
}

// stepUp runs a CIBA request made with requestingToken through approval and
// redemption, and returns the approved token's claims.
func (tn hrdTenant) stepUp(t *testing.T, requestingToken, scope string) map[string]any {
	t.Helper()
	c := tn.cibaClient(t)
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id": c.ID, "client_secret": c.Secret,
		"account_id": tn.account, "project_id": tn.project,
		"login_hint": "user-a", "requesting_token": requestingToken, "scope": scope,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)
	require.NotEmpty(t, id)

	ap := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{"subject_id": "user-a"}, tn.headers)
	require.Equal(t, http.StatusOK, ap.StatusCode)
	_ = ap.Body.Close()

	return decodeJWTPayload(t, pollCIBA(t, c, id, requestingToken)["access_token"].(string))
}

func (tn hrdTenant) setTokenProfile(t *testing.T, profile string) {
	t.Helper()
	resp := doRequest(t, http.MethodPut, adminPath("/tenant-settings"), map[string]any{"token_profile": profile}, tn.headers)
	require.Equal(t, http.StatusOK, resp.StatusCode, "set token_profile=%s", profile)
	_ = resp.Body.Close()
}

// workloadChain mints root -> A -> B in the tenant and returns B's token with
// the WIMSE URIs and external ids of the agents.
func (tn hrdTenant) workloadChain(t *testing.T, scopes []string) (leaf, rootWIMSE, wimseA, wimseB, extB string) {
	t.Helper()
	policyID := tn.policy(t, scopes)
	root, rootWIMSE := tn.workloadRoot(t, policyID, scopes)
	mid, wimseA := tn.exchange(t, policyID, uid("switch-a"), scopes, root)
	extB = uid("switch-b")
	body, wimseB := tn.exchange(t, policyID, extB, scopes, mid["access_token"].(string))
	return body["access_token"].(string), rootWIMSE, wimseA, wimseB, extB
}

// assertActorInAct checks the rfc8693 placement of the current actor's
// attributes: inside the outermost act, not at the top level.
func assertActorInAct(t *testing.T, claims map[string]any, wimse, extID string) {
	t.Helper()
	act, ok := claims["act"].(map[string]any)
	require.True(t, ok, "act: %v", claims["act"])
	assert.Equal(t, wimse, act["sub"])
	assert.Equal(t, extID, act["external_id"])
	assert.Equal(t, "agent", act["identity_type"])
	assert.Equal(t, "unverified", act["trust_level"])
	for _, k := range []string{"external_id", "identity_type", "trust_level"} {
		assert.NotContains(t, claims, k, "%s is the actor's, not the principal's", k)
	}
}

func TestCIBAStepUp_LegacyChainAfterSwitchToRFC8693(t *testing.T) {
	tn := newTenant(t, "legacy")
	scopes := []string{"tools:read"}
	leaf, rootWIMSE, wimseA, wimseB, extB := tn.workloadChain(t, scopes)

	leafClaims := decodeJWTPayload(t, leaf)
	require.Equal(t, wimseB, leafClaims["sub"], "minted under legacy: the actor is sub")
	require.Equal(t, map[string]any{"sub": wimseA}, leafClaims["act"], "minted under legacy: one-level act")

	tn.setTokenProfile(t, "rfc8693")
	claims := tn.stepUp(t, leaf, "tools:read")

	assert.Equal(t, rootWIMSE, claims["sub"], "rfc8693: sub is the chain's principal")
	assert.Equal(t, "workload", claims["principal_type"])
	assertActorInAct(t, claims, wimseB, extB)
	assert.Equal(t, []string{wimseB, wimseA}, actChain(t, claims),
		"the delegating agent is kept as the prior actor; the principal is never an actor")
	inner := claims["act"].(map[string]any)["act"].(map[string]any)
	assert.Equal(t, []string{"sub"}, mapKeys(inner, "act"), "prior actors carry only sub")
}

// Same-profile control: a chain minted and stepped up under rfc8693 keeps the
// act it already carried.
func TestCIBAStepUp_RFC8693ChainUnderRFC8693(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"tools:read"}
	leaf, rootWIMSE, _, wimseB, extB := tn.workloadChain(t, scopes)
	leafClaims := decodeJWTPayload(t, leaf)

	claims := tn.stepUp(t, leaf, "tools:read")

	assert.Equal(t, rootWIMSE, claims["sub"])
	assert.Equal(t, leafClaims["sub"], claims["sub"])
	assert.Equal(t, leafClaims["act"], claims["act"], "the chain's act is carried over unchanged")
	assertActorInAct(t, claims, wimseB, extB)
}

// Same-profile control: a chain minted and stepped up under legacy keeps its
// one-level act and the actor's attributes at the top level.
func TestCIBAStepUp_LegacyChainUnderLegacy(t *testing.T) {
	tn := newTenant(t, "legacy")
	scopes := []string{"tools:read"}
	leaf, _, _, wimseB, extB := tn.workloadChain(t, scopes)
	leafClaims := decodeJWTPayload(t, leaf)

	claims := tn.stepUp(t, leaf, "tools:read")

	assert.Equal(t, wimseB, claims["sub"])
	assert.Equal(t, leafClaims["act"], claims["act"])
	assert.Equal(t, extB, claims["external_id"])
	assert.NotContains(t, claims, "principal_type")
}
