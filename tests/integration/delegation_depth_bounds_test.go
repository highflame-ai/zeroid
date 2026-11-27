package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// max_delegation_depth is bounded so that every token a chain can reach
// carries its whole RFC 8693 act chain: a token at depth d names up to d+1
// actors, and the act claim holds at most domain.MaxActorChainDepth.

// delegationDepthLimit is domain.MaxDelegationDepthLimit, spelled out so the
// suite states the relationship it relies on.
const delegationDepthLimit = domain.MaxActorChainDepth - 1

// TestCredentialPolicy_MaxDelegationDepthRangeOnCreate: a policy may set
// max_delegation_depth from 0 (no delegation) to delegationDepthLimit,
// and anything else is a 400 naming the field.
func TestCredentialPolicy_MaxDelegationDepthRangeOnCreate(t *testing.T) {
	tn := newTenant(t, "")
	create := func(depth int) *http.Response {
		return post(t, adminPath("/credential-policies"), map[string]any{
			"name":                 uid("depth-range"),
			"allowed_grant_types":  []string{"client_credentials", "token_exchange"},
			"max_delegation_depth": depth,
		}, tn.headers)
	}

	for _, depth := range []int{-5, -1, delegationDepthLimit + 1, 25, 1_000_000} {
		resp := create(depth)
		body := decode(t, resp)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "max_delegation_depth=%d must be refused: %v", depth, body)
		assert.Contains(t, fmt.Sprint(body["detail"]), "max_delegation_depth", "the refusal names the field (depth %d)", depth)
	}
	for _, depth := range []int{0, 1, delegationDepthLimit} {
		resp := create(depth)
		body := decode(t, resp)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode, "max_delegation_depth=%d is in range: %v", depth, body)
		assert.EqualValues(t, depth, body["max_delegation_depth"])
	}
}

// TestCredentialPolicy_MaxDelegationDepthRangeOnUpdate: PATCH holds
// max_delegation_depth to the same range, and a refused PATCH leaves the
// stored value as it was.
func TestCredentialPolicy_MaxDelegationDepthRangeOnUpdate(t *testing.T) {
	tn := newTenant(t, "")
	id := tn.policyWith(t, []string{"data:read"}, map[string]any{"max_delegation_depth": 3})
	patch := func(depth int) (*http.Response, map[string]any) {
		resp := doRequest(t, http.MethodPatch, adminPath("/credential-policies/"+id),
			map[string]any{"max_delegation_depth": depth}, tn.headers)
		body := decode(t, resp)
		_ = resp.Body.Close()
		return resp, body
	}

	for _, depth := range []int{-5, -1, delegationDepthLimit + 1, 1_000_000} {
		resp, body := patch(depth)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "max_delegation_depth=%d must be refused: %v", depth, body)
		assert.Contains(t, fmt.Sprint(body["detail"]), "max_delegation_depth", "the refusal names the field (depth %d)", depth)
	}

	resp := get(t, adminPath("/credential-policies/"+id), tn.headers)
	stored := decode(t, resp)
	_ = resp.Body.Close()
	assert.EqualValues(t, 3, stored["max_delegation_depth"], "a refused update changes nothing")

	for _, depth := range []int{0, delegationDepthLimit} {
		resp, body := patch(depth)
		require.Equal(t, http.StatusOK, resp.StatusCode, "max_delegation_depth=%d is in range: %v", depth, body)
		assert.EqualValues(t, depth, body["max_delegation_depth"])
	}
}

// TestCredentialPolicy_PatchKeepsStoredOutOfRangeDepth: a policy stored with
// an out-of-range max_delegation_depth (written before the range existed)
// stays editable. A PATCH that omits the field works, and so does one that
// sends the stored value back unchanged, as a client that PATCHes every
// field of its edit form does. Setting a new out-of-range value is refused.
func TestCredentialPolicy_PatchKeepsStoredOutOfRangeDepth(t *testing.T) {
	tn := newTenant(t, "")
	id := tn.policyWith(t, []string{"data:read"}, map[string]any{"max_delegation_depth": 3})
	setInDB(t, "credential_policies", id, "max_delegation_depth = ?", 25)
	patch := func(body map[string]any) (int, map[string]any) {
		resp := doRequest(t, http.MethodPatch, adminPath("/credential-policies/"+id), body, tn.headers)
		out := decode(t, resp)
		_ = resp.Body.Close()
		return resp.StatusCode, out
	}

	status, body := patch(map[string]any{"description": "omits the depth"})
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.EqualValues(t, 25, body["max_delegation_depth"], "an omitted depth is left as stored")

	status, body = patch(map[string]any{"description": "repeats the depth", "max_delegation_depth": 25})
	require.Equal(t, http.StatusOK, status, "repeating the stored value changes nothing and is not refused: %v", body)
	assert.Equal(t, "repeats the depth", body["description"])
	assert.EqualValues(t, 25, body["max_delegation_depth"])

	status, body = patch(map[string]any{"max_delegation_depth": 20})
	assert.Equal(t, http.StatusBadRequest, status, "a new out-of-range value is refused: %v", body)

	status, body = patch(map[string]any{"max_delegation_depth": delegationDepthLimit})
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.EqualValues(t, delegationDepthLimit, body["max_delegation_depth"])
}

// exchangeWithKey exchanges subject for the actor that holds key, and returns
// the response status and body.
func exchangeWithKey(t *testing.T, subject string, key *ecdsa.PrivateKey, actorURI string, scopes []string) (int, map[string]any) {
	t.Helper()
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": subject,
		"actor_token":   buildAssertion(t, key, actorURI),
		"scope":         scopesToString(scopes),
	}, nil)
	body := decode(t, resp)
	_ = resp.Body.Close()
	return resp.StatusCode, body
}

// TestDelegationDepth_StoredPolicyAboveLimitIsClamped: a policy stored with a
// max_delegation_depth above the limit (written before the limit existed) is
// held to delegationDepthLimit at issuance. The deepest token the
// chain reaches still names every actor, back to the root grant's client, and
// the next hop is refused rather than issued with a shortened act chain.
func TestDelegationDepth_StoredPolicyAboveLimitIsClamped(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}
	policyID := tn.policyWith(t, scopes, map[string]any{"max_delegation_depth": 1})
	setInDB(t, "credential_policies", policyID, "max_delegation_depth = ?", 25)

	token, _ := tn.workloadRoot(t, policyID, scopes)
	rootClientID := decodeJWTPayload(t, token)["client_id"].(string)
	require.NotEmpty(t, rootClientID)

	var want []string
	for hop := 1; hop <= delegationDepthLimit; hop++ {
		body, wimse := tn.exchange(t, policyID, uid(fmt.Sprintf("depth-%02d", hop)), scopes, token)
		token = body["access_token"].(string)
		want = append([]string{wimse}, want...)
	}
	claims := decodeJWTPayload(t, token)
	assert.EqualValues(t, delegationDepthLimit, claims["delegation_depth"])
	chain := actChain(t, claims)
	assert.Len(t, chain, domain.MaxActorChainDepth, "the deepest token fills the act claim without overflowing it")
	assert.Equal(t, append(want, rootClientID), chain, "every actor is named, current first, back to the root grant's client")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wimse := tn.register(t, uid("depth-over"), policyID, ecPublicKeyPEM(t, key), scopes)
	status, body := exchangeWithKey(t, token, key, wimse, scopes)
	assert.Equal(t, http.StatusBadRequest, status, "the hop past the limit is refused: %v", body)
	assert.Equal(t, "policy_violation", body["error"])
	assert.Contains(t, body["error_description"], fmt.Sprintf("delegation depth %d exceeds", delegationDepthLimit+1))
}
