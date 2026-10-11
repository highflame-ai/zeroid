package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// A CIBA step-up approved into a requesting chain extends that chain (ADR 0041
// D15): the approved token's scopes are the chain's own, the chain's principal
// decides which policy rules apply, and the requesting identity's policy still
// shapes the token. These tests pin each of those.

// bcAuthorizeIn posts bc-authorize for c in the given tenant.
func bcAuthorizeIn(t *testing.T, c cibaClient, account, project string, body map[string]any) string {
	t.Helper()
	body["client_id"] = c.ID
	body["client_secret"] = c.Secret
	body["account_id"] = account
	body["project_id"] = project
	resp := post(t, "/oauth2/bc-authorize", body, nil)
	got := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "bc-authorize: %v", got)
	id, _ := got["auth_req_id"].(string)
	require.NotEmpty(t, id)
	return id
}

// approveInTenant approves authReqID as sub in the tenant named by headers.
func approveInTenant(t *testing.T, authReqID, sub string, headers map[string]string) {
	t.Helper()
	ap := post(t, adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"), map[string]any{"subject_id": sub}, headers)
	require.Equal(t, http.StatusOK, ap.StatusCode)
	_ = ap.Body.Close()
}

// stepUp runs bc-authorize (with the requesting token) → approve → poll in
// the tenant and returns the poll's status and body.
func stepUp(t *testing.T, account, project string, headers map[string]string, requesting, scope string) (int, map[string]any) {
	t.Helper()
	c := newConfidentialCIBAClient(t)
	body := map[string]any{"login_hint": "user-a", "requesting_token": requesting}
	if scope != "" {
		body["scope"] = scope
	}
	id := bcAuthorizeIn(t, c, account, project, body)
	approveInTenant(t, id, "user-a", headers)
	return pollCIBARaw(t, c, id, requesting)
}

// Bug 1: Shield always sends scope=openid, the CIBA protocol scope. A
// ceiling-bound agent's step-up must still redeem, and the approved token
// carries the requesting token's scopes — never a scope the chain lacks.
func TestCIBAStepUp_KeepsTheChainsScopes(t *testing.T) {
	externalID := uid("ciba-scoped-agent")
	reg := post(t, adminPath("/agents/register"), map[string]any{
		"name": externalID, "external_id": externalID, "sub_type": "tool_agent",
		"trust_level": "first_party", "created_by": "user-owner-1",
		"allowed_scopes": []string{"tools:read", "tools:write"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, reg.StatusCode)
	apiKey, _ := decode(t, reg)["api_key"].(string)
	// The requesting token holds less than the identity's ceiling allows, so
	// only the chain can refuse tools:write below.
	tr := mintAPIKeyScope(t, apiKey, "tools:read")
	require.Equal(t, http.StatusOK, tr.StatusCode)
	agentToken, _ := decode(t, tr)["access_token"].(string)
	chainScopes := decodeJWTPayload(t, agentToken)["scopes"]
	require.ElementsMatch(t, []any{"tools:read"}, chainScopes, "the requesting token holds what it asked for")

	t.Run("openid only redeems with the chain's scopes", func(t *testing.T) {
		status, body := stepUp(t, testAccountID, testProjectID, adminHeaders(), agentToken, "openid")
		require.Equal(t, http.StatusOK, status, "poll: %v", body)
		got := decodeJWTPayload(t, body["access_token"].(string))["scopes"]
		require.NotNil(t, got, "the approved token carries a scopes claim")
		assert.ElementsMatch(t, chainScopes, got, "the approved token carries the requesting token's scopes")
	})

	t.Run("no scope redeems with the chain's scopes", func(t *testing.T) {
		status, body := stepUp(t, testAccountID, testProjectID, adminHeaders(), agentToken, "")
		require.Equal(t, http.StatusOK, status, "poll: %v", body)
		got := decodeJWTPayload(t, body["access_token"].(string))["scopes"]
		require.NotNil(t, got, "the approved token carries a scopes claim")
		assert.ElementsMatch(t, chainScopes, got)
	})

	t.Run("a scope the chain holds narrows to it", func(t *testing.T) {
		status, body := stepUp(t, testAccountID, testProjectID, adminHeaders(), agentToken, "openid tools:read")
		require.Equal(t, http.StatusOK, status, "poll: %v", body)
		assert.ElementsMatch(t, []any{"tools:read"}, decodeJWTPayload(t, body["access_token"].(string))["scopes"])
	})

	t.Run("a scope the chain does not hold is refused without consuming the approval", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		id := bcAuthorizeIn(t, c, testAccountID, testProjectID, map[string]any{
			"login_hint": "user-a", "requesting_token": agentToken, "scope": "openid tools:write",
		})
		approveAs(t, id, "user-a")
		status, body := pollCIBARaw(t, c, id, agentToken)
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_scope", body["error"])
		assert.Contains(t, body["error_description"], "tools:write")
		assert.Contains(t, body["error_description"], "not held by the requesting token", "the chain, not a ceiling, refuses it")
		row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
		assert.Equal(t, domain.BackchannelStatusApproved, row.Status, "a refusal must not consume the approval")
	})
}

// Bug 2: a policy requiring a user subject accepts a step-up into a chain
// rooted in a person, and still refuses one rooted in a workload.
func TestCIBAStepUp_RequiredPrincipalTypeUsesTheChainsPrincipal(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}

	t.Run("user-rooted chain redeems", func(t *testing.T) {
		userOnly := tn.policyWith(t, scopes, map[string]any{"required_principal_type": "user"})
		alice, aliceID := tn.userRoot(t, scopes)
		child, _ := tn.exchange(t, userOnly, uid("ciba-rpt"), scopes, alice)
		childToken := child["access_token"].(string)

		status, body := stepUp(t, tn.account, tn.project, tn.headers, childToken, "data:read")
		require.Equal(t, http.StatusOK, status, "poll: %v", body)
		claims := decodeJWTPayload(t, body["access_token"].(string))
		assert.Equal(t, aliceID, claims["sub"], "the chain's principal stays the subject")
	})

	t.Run("workload-rooted chain is still refused", func(t *testing.T) {
		policyID := tn.policy(t, scopes)
		own, _ := tn.workloadRoot(t, policyID, scopes)
		// The policy starts requiring a user subject after the workload token
		// was minted; the step-up must not extend that token.
		patchCredentialPolicy(t, policyID, map[string]any{"required_principal_type": "user"}, tn.headers)

		status, body := stepUp(t, tn.account, tn.project, tn.headers, own, "data:read")
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "access_denied", body["error"])
	})
}

// Bug 3: a chain acting for a person is capped by the requesting identity's
// policy user_grant_scopes, not its allowed_scopes (ADR 0041 D2).
func TestCIBAStepUp_UserChainCappedByUserGrantScopes(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	own := []string{"nhi:manage"}
	crm := []string{"crm:write"}

	t.Run("allowed_scopes does not cap a person's chain", func(t *testing.T) {
		policyID := tn.policy(t, own)
		alice, _ := tn.userRoot(t, crm)
		child, _ := tn.exchange(t, policyID, uid("ciba-ugs"), crm, alice)

		status, body := stepUp(t, tn.account, tn.project, tn.headers, child["access_token"].(string), "crm:write")
		require.Equal(t, http.StatusOK, status, "poll: %v", body)
		assert.ElementsMatch(t, []any{"crm:write"}, decodeJWTPayload(t, body["access_token"].(string))["scopes"])
	})

	t.Run("user_grant_scopes caps it", func(t *testing.T) {
		policyID := tn.policyWith(t, own, map[string]any{"user_grant_scopes": crm})
		alice, _ := tn.userRoot(t, crm)
		child, _ := tn.exchange(t, policyID, uid("ciba-ugs-cap"), crm, alice)
		// Tightened after the chain was minted: the step-up re-checks it.
		patchCredentialPolicy(t, policyID, map[string]any{"user_grant_scopes": []string{"crm:read"}}, tn.headers)

		status, body := stepUp(t, tn.account, tn.project, tn.headers, child["access_token"].(string), "crm:write")
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_scope", body["error"])
		assert.Contains(t, body["error_description"], "user_grant_scopes", "the denial names the ceiling it came from")
	})
}

// Bug 4: the requesting identity's policy still chooses the token's typ
// header after the step-up enforced it, so jwt_typ JWT keeps the approved
// token a JWT-SVID.
func TestCIBAStepUp_PolicyJWTTyp(t *testing.T) {
	tn := newTenant(t, "")
	scopes := []string{"data:read"}
	policyID := tn.policyWith(t, scopes, map[string]any{"jwt_typ": "JWT"})
	root, _ := tn.workloadRoot(t, policyID, scopes)
	require.Equal(t, "JWT", headerTyp(t, root))

	status, body := stepUp(t, tn.account, tn.project, tn.headers, root, "data:read")
	require.Equal(t, http.StatusOK, status, "poll: %v", body)
	assert.Equal(t, "JWT", headerTyp(t, body["access_token"].(string)))
}

// requireRefusedWithoutConsuming polls id and asserts an invalid_scope
// refusal that leaves the approval redeemable.
func requireRefusedWithoutConsuming(t *testing.T, c cibaClient, id, requesting, mentions string) {
	t.Helper()
	status, body := pollCIBARaw(t, c, id, requesting)
	require.Equal(t, http.StatusBadRequest, status, "poll: %v", body)
	assert.Equal(t, "invalid_scope", body["error"])
	assert.Contains(t, body["error_description"], mentions)
	row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
	assert.Equal(t, domain.BackchannelStatusApproved, row.Status, "a refusal must not consume the approval")
}

// A requesting token that names no identity leaves the token anchored to the
// polling client's bound identity, whose ceilings the chokepoint applies. The
// chain's scopes must be checked against them before the burn, not only the
// request's own scope.
func TestCIBAStepUp_UnanchoredChainCheckedAgainstTheBoundClientBeforeTheBurn(t *testing.T) {
	// The requesting token: a root CIBA grant through an unbound client, so
	// its credential names no identity.
	unbound := newConfidentialCIBAClient(t)
	rootID := bcAuthorizeIn(t, unbound, testAccountID, testProjectID, map[string]any{
		"login_hint": "user-a", "scope": "openid tools:read",
	})
	approveAs(t, rootID, "user-a")
	requesting := pollCIBA(t, unbound, rootID)["access_token"].(string)
	require.ElementsMatch(t, []any{"openid", "tools:read"}, decodeJWTPayload(t, requesting)["scopes"])

	// The polling client is bound to an identity whose ceiling is openid.
	idResp := post(t, adminPath("/identities"), map[string]any{
		"external_id": uid("ciba-bound-narrow"), "owner_user_id": "user-test-owner",
		"identity_type": "agent", "sub_type": "human_proxy",
		"allowed_scopes": []string{"openid"}, "trust_level": "first_party",
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, idResp.StatusCode)
	identityID := decode(t, idResp)["id"].(string)
	clientID := uid("ciba-bound-narrow")
	clResp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id": clientID, "name": clientID, "confidential": true,
		"identity_id": identityID,
		"grant_types": []string{zeroidGrantTypeCIBA},
		"scopes":      []string{"openid"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, clResp.StatusCode)
	bound := cibaClient{ID: clientID, Secret: decode(t, clResp)["client_secret"].(string)}

	id := bcAuthorizeIn(t, bound, testAccountID, testProjectID, map[string]any{
		"login_hint": "user-a", "requesting_token": requesting, "scope": "openid",
	})
	approveAs(t, id, "user-a")
	requireRefusedWithoutConsuming(t, bound, id, requesting, "tools:read")
}

// ciba:approve is issued only from a trusted approval-channel credential, so
// an approval never carries it into a chain. A step-up into a chain holding it
// is refused before the burn.
func TestCIBAStepUp_ChainHoldingCIBAApproveRefusedBeforeTheBurn(t *testing.T) {
	ch := registerChannel(t, "approval_channel", "")
	resp := mintAPIKeyScope(t, ch.APIKey, "ciba:approve")
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	requesting := body["access_token"].(string)

	for _, scope := range []string{"openid", "ciba:approve"} {
		t.Run("scope="+scope, func(t *testing.T) {
			c := newConfidentialCIBAClient(t)
			id := bcAuthorizeIn(t, c, testAccountID, testProjectID, map[string]any{
				"login_hint": "user-a", "requesting_token": requesting, "scope": scope,
			})
			approveAs(t, id, "user-a")
			requireRefusedWithoutConsuming(t, c, id, requesting, "ciba:approve")
		})
	}
}
