package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Human-rooted delegation, phase 1 (highflame-architecture#359). The tests in
// this file follow the design's test plan (§9); the names it gives are kept so
// the plan and the suite can be read side by side.

const issuedTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

// hrdTenant is a tenant of its own for one test. Token profile is a tenant
// setting, so a test that switched the shared test tenant to rfc8693 would
// change the token shape every later test in the suite sees.
type hrdTenant struct {
	account, project string
	headers          map[string]string
}

func newTenant(t *testing.T, profile string) hrdTenant {
	t.Helper()
	tn := hrdTenant{account: uid("hrd-acct"), project: "hrd-proj"}
	tn.headers = map[string]string{"X-Account-ID": tn.account, "X-Project-ID": tn.project}
	if profile != "" {
		resp := doRequest(t, http.MethodPut, adminPath("/tenant-settings"), map[string]any{"token_profile": profile}, tn.headers)
		require.Equal(t, http.StatusOK, resp.StatusCode, "set token_profile=%s", profile)
		_ = resp.Body.Close()
	}
	return tn
}

// policy creates a credential policy in the tenant allowing the root and
// exchange grants, with the given scope ceiling.
func (tn hrdTenant) policy(t *testing.T, scopes []string) string {
	t.Helper()
	return createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("hrd-policy"),
		"allowed_grant_types":  []string{"client_credentials", "token_exchange"},
		"allowed_scopes":       scopes,
		"max_delegation_depth": 5,
		"max_ttl_seconds":      3600,
	}, tn.headers)
}

// register creates an identity in the tenant and returns its WIMSE URI.
func (tn hrdTenant) register(t *testing.T, extID, policyID, publicKeyPEM string, scopes []string) string {
	t.Helper()
	body := map[string]any{
		"external_id":    extID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": scopes,
	}
	if policyID != "" {
		body["credential_policy_id"] = policyID
	}
	if publicKeyPEM != "" {
		body["public_key_pem"] = publicKeyPEM
	}
	resp := post(t, adminPath("/identities"), body, tn.headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "register %s", extID)
	got := decode(t, resp)
	_ = resp.Body.Close()
	return got["wimse_uri"].(string)
}

// workloadRoot mints a client_credentials token for a new agent: a workload
// subject. Returns the token and the agent's WIMSE URI.
func (tn hrdTenant) workloadRoot(t *testing.T, policyID string, scopes []string) (string, string) {
	t.Helper()
	extID := uid("hrd-root")
	wimse := tn.register(t, extID, policyID, "", scopes)
	client := registerOAuthClient(t, extID, scopes)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    tn.account,
		"project_id":    tn.project,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         scopesToString(scopes),
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "client_credentials root")
	token := decode(t, resp)["access_token"].(string)
	_ = resp.Body.Close()
	return token, wimse
}

// userRoot mints a token for a person through the trusted-broker principal
// exchange: a user subject. Returns the token and the user id.
func (tn hrdTenant) userRoot(t *testing.T, scopes []string) (string, string) {
	t.Helper()
	userID := uid("alice")
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": "external-principal-assertion",
		"account_id":    tn.account,
		"project_id":    tn.project,
		"user_id":       userID,
		"scope":         scopesToString(scopes),
	}, map[string]string{testTrustedServiceHeader: "trusted-service"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "broker user root")
	token := decode(t, resp)["access_token"].(string)
	_ = resp.Body.Close()
	return token, userID
}

// exchange registers a new actor in the tenant and exchanges parent for it.
// Returns the token response and the actor's WIMSE URI.
func (tn hrdTenant) exchange(t *testing.T, policyID, extID string, scopes []string, parent string) (map[string]any, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wimse := tn.register(t, extID, policyID, ecPublicKeyPEM(t, key), scopes)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": parent,
		"actor_token":   buildAssertion(t, key, wimse),
		"scope":         scopesToString(scopes),
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token_exchange as %s", extID)
	body := decode(t, resp)
	_ = resp.Body.Close()
	return body, wimse
}

// principalRow reads the principal persisted on a credential.
type principalRow struct{ Type, Sub, Iss string }

func principalOf(t *testing.T, token string) principalRow {
	t.Helper()
	jti := decodeJWTPayload(t, token)["jti"].(string)
	var typ, sub, iss *string
	err := testDB.NewSelect().Table("issued_credentials").
		Column("principal_type", "principal_sub", "principal_iss").
		Where("jti = ?", jti).
		Scan(context.Background(), &typ, &sub, &iss)
	require.NoError(t, err)
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return principalRow{deref(typ), deref(sub), deref(iss)}
}

// forgetPrincipal clears a credential's persisted principal, making it look
// like a row minted before migration 047.
func forgetPrincipal(t *testing.T, token string) {
	t.Helper()
	jti := decodeJWTPayload(t, token)["jti"].(string)
	_, err := testDB.NewUpdate().Table("issued_credentials").
		Set("principal_type = NULL, principal_sub = NULL, principal_iss = NULL").
		Where("jti = ?", jti).
		Exec(context.Background())
	require.NoError(t, err)
}

// TestTenantSettings_TokenProfile covers the per-tenant switch: a tenant with
// no settings is on legacy, an admin can move it to rfc8693, the switch is
// scoped to that tenant alone, and an unknown profile is refused.
func TestTenantSettings_TokenProfile(t *testing.T) {
	tn := newTenant(t, "")
	other := newTenant(t, "")

	get := func(h map[string]string) string {
		resp := doRequest(t, http.MethodGet, adminPath("/tenant-settings"), nil, h)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := decode(t, resp)
		_ = resp.Body.Close()
		return body["token_profile"].(string)
	}
	assert.Equal(t, "legacy", get(tn.headers), "a tenant with no settings is on legacy")

	resp := doRequest(t, http.MethodPut, adminPath("/tenant-settings"), map[string]any{"token_profile": "rfc8693"}, tn.headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
	assert.Equal(t, "rfc8693", get(tn.headers))
	assert.Equal(t, "legacy", get(other.headers), "the switch is scoped to one tenant")

	resp = doRequest(t, http.MethodPut, adminPath("/tenant-settings"), map[string]any{"token_profile": "rfc9999"}, tn.headers)
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusUnprocessableEntity}, resp.StatusCode, "an unknown profile is refused")
	_ = resp.Body.Close()
	assert.Equal(t, "rfc8693", get(tn.headers), "a refused update leaves the setting unchanged")
}

// TestPrincipal_PersistedForEveryTenant: the principal is written for every
// credential whatever the profile, so a chain minted on legacy today is
// reachable by per-user revocation when it ships. On an exchange the child
// inherits the principal — under legacy too, where the token's own `sub` is
// the actor.
func TestPrincipal_PersistedForEveryTenant(t *testing.T) {
	tn := newTenant(t, "") // legacy
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)

	workload, wimse := tn.workloadRoot(t, policyID, scopes)
	iss := decodeJWTPayload(t, workload)["iss"].(string)
	assert.Equal(t, principalRow{"workload", wimse, iss}, principalOf(t, workload))

	user, userID := tn.userRoot(t, scopes)
	assert.Equal(t, principalRow{"user", userID, iss}, principalOf(t, user))

	child, _ := tn.exchange(t, policyID, uid("hrd-child"), scopes, user)
	childToken := child["access_token"].(string)
	assert.NotEqual(t, userID, decodeJWTPayload(t, childToken)["sub"], "precondition: legacy puts the actor in sub")
	assert.Equal(t, principalRow{"user", userID, iss}, principalOf(t, childToken),
		"the child's principal is the person, inherited from the parent")

	grandchild, _ := tn.exchange(t, policyID, uid("hrd-grandchild"), scopes, childToken)
	assert.Equal(t, principalRow{"user", userID, iss}, principalOf(t, grandchild["access_token"].(string)),
		"inherited at every hop")
}

// TestPrincipal_LegacyParentRule covers parents minted before principals were
// persisted. At depth 0 the parent's sub is genuine; above it, the legacy
// shape put the actor in sub, so the principal is unknown (fail closed).
func TestPrincipal_LegacyParentRule(t *testing.T) {
	tn := newTenant(t, "")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)

	t.Run("depth 0 workload parent", func(t *testing.T) {
		root, wimse := tn.workloadRoot(t, policyID, scopes)
		forgetPrincipal(t, root)
		child, _ := tn.exchange(t, policyID, uid("hrd-lp-w"), scopes, root)
		got := principalOf(t, child["access_token"].(string))
		assert.Equal(t, "workload", got.Type)
		assert.Equal(t, wimse, got.Sub)
	})

	t.Run("depth 0 user parent", func(t *testing.T) {
		root, userID := tn.userRoot(t, scopes)
		forgetPrincipal(t, root)
		child, _ := tn.exchange(t, policyID, uid("hrd-lp-u"), scopes, root)
		got := principalOf(t, child["access_token"].(string))
		assert.Equal(t, "user", got.Type)
		assert.Equal(t, userID, got.Sub)
	})

	t.Run("delegated parent is unknown", func(t *testing.T) {
		root, _ := tn.userRoot(t, scopes)
		mid, _ := tn.exchange(t, policyID, uid("hrd-lp-mid"), scopes, root)
		midToken := mid["access_token"].(string)
		forgetPrincipal(t, midToken)
		child, _ := tn.exchange(t, policyID, uid("hrd-lp-leaf"), scopes, midToken)
		assert.Equal(t, "unknown", principalOf(t, child["access_token"].(string)).Type)
	})
}

// exchangeForResponse registers a fresh actor under policyID and exchanges
// parentToken for it, returning the whole token response so tests can assert on
// response fields, not only on the JWT.
func exchangeForResponse(t *testing.T, policyID, namePrefix string, scopes []string, parentToken string) map[string]any {
	t.Helper()
	body, _ := exchangeAs(t, policyID, uid(namePrefix), scopes, parentToken)
	return body
}

// exchangeAs is exchangeForResponse with a caller-chosen actor external_id, so
// a test can assert claims that name the actor. Returns the token response and
// the actor's WIMSE URI.
func exchangeAs(t *testing.T, policyID, extID string, scopes []string, parentToken string) (map[string]any, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	registerIdentityWithPolicy(t, extID, policyID, ecPublicKeyPEM(t, key), scopes, adminHeaders())
	wimse := fetchIdentityWIMSEByExternalID(t, extID)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": parentToken,
		"actor_token":   buildAssertion(t, key, wimse),
		"scope":         scopesToString(scopes),
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token_exchange as %s", extID)
	body := decode(t, resp)
	_ = resp.Body.Close()
	return body, wimse
}

// TestIntrospection_Fields covers D2: RFC 7662 introspection now returns the
// lineage and attribution claims the token carries, so a resource server that
// introspects instead of verifying locally sees the same delegation tree and
// accountable human. Every value must equal the token's own claim.
func TestIntrospection_Fields(t *testing.T) {
	scopes := []string{"data:read"}
	policyID := delegationPolicy(t, uid("d2-policy"), scopes)
	_, _, root := issueRootCredential(t, policyID, "d2-orch", scopes)
	body := exchangeForResponse(t, policyID, "d2-actor", scopes, root)
	token := body["access_token"].(string)
	claims := decodeJWTPayload(t, token)

	got := introspect(t, token)
	require.Equal(t, true, got["active"])
	for _, claim := range []string{"client_id", "mission_id"} {
		require.NotEmpty(t, claims[claim], "precondition: the exchanged token carries %s", claim)
		assert.Equal(t, claims[claim], got[claim], "introspection must return the token's %s", claim)
	}
	if owner, ok := claims["owner_user_id"]; ok {
		assert.Equal(t, owner, got["owner_user_id"])
	} else {
		assert.NotContains(t, got, "owner_user_id", "a claim the token lacks is not invented")
	}
}

// TestTokenExchange_ClientIDIsTheActor covers the exchange half of D8: RFC 9068
// §2.2 and RFC 8693 §4.3 put the client the token was issued to in client_id,
// and on an exchange that client is the actor. Emitted for every tenant, so
// this holds under the default legacy profile too. The ID-JAG half is asserted
// in TestIDJAG_EndToEnd.
func TestTokenExchange_ClientIDIsTheActor(t *testing.T) {
	scopes := []string{"data:read"}
	policyID := delegationPolicy(t, uid("d8-policy"), scopes)
	_, _, root := issueRootCredential(t, policyID, "d8-orch", scopes)

	actorExtID := uid("d8-actor")
	body, _ := exchangeAs(t, policyID, actorExtID, scopes, root)
	claims := decodeJWTPayload(t, body["access_token"].(string))
	assert.Equal(t, actorExtID, claims["client_id"])
}

// TestTokenExchange_IssuedTokenType covers D7: RFC 8693 §2.2.1 makes
// issued_token_type REQUIRED on a token-exchange response. It is checked on
// both an NHI delegation and the trusted-broker principal exchange, the two
// exchange modes most callers use, and confirmed absent on a non-exchange
// grant, where RFC 6749 §5.1 does not define it.
func TestTokenExchange_IssuedTokenType(t *testing.T) {
	scopes := []string{"data:read"}
	policyID := delegationPolicy(t, uid("d7-policy"), scopes)

	t.Run("client_credentials does not carry it", func(t *testing.T) {
		extID := uid("d7-root")
		registerIdentityWithPolicy(t, extID, policyID, "", scopes, adminHeaders())
		client := registerOAuthClient(t, extID, scopes)
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := decode(t, resp)
		_ = resp.Body.Close()
		assert.NotContains(t, body, "issued_token_type")
	})

	t.Run("NHI delegation carries it", func(t *testing.T) {
		_, _, root := issueRootCredential(t, policyID, "d7-orch", scopes)
		body := exchangeForResponse(t, policyID, "d7-actor", scopes, root)
		assert.Equal(t, issuedTokenTypeAccessToken, body["issued_token_type"])
	})

	t.Run("trusted-broker principal exchange carries it", func(t *testing.T) {
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": "external-principal-assertion",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"user_id":       uid("d7-user"),
		}, map[string]string{testTrustedServiceHeader: "trusted-service"})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := decode(t, resp)
		_ = resp.Body.Close()
		assert.Equal(t, issuedTokenTypeAccessToken, body["issued_token_type"])
	})
}

// actChain flattens a token's nested `act` into the actors' subs, current
// actor first.
func actChain(t *testing.T, claims map[string]any) []string {
	t.Helper()
	var out []string
	act, _ := claims["act"].(map[string]any)
	for act != nil {
		out = append(out, act["sub"].(string))
		act, _ = act["act"].(map[string]any)
	}
	return out
}

// TestRFC8693Profile_UserSubjectThreeHops is the design's P2 fix: three
// exchanges from a person's token, and every token still names her as `sub`,
// with the agents nested in `act` current-first and client_id the holder.
func TestRFC8693Profile_UserSubjectThreeHops(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)

	t0, alice := tn.userRoot(t, scopes)
	t0Claims := decodeJWTPayload(t, t0)
	assert.Equal(t, alice, t0Claims["sub"])
	assert.Equal(t, "user", t0Claims["principal_type"])
	assert.Nil(t, t0Claims["act"], "a root grant has no actors")

	extA, extB, extC := uid("hrd-a"), uid("hrd-b"), uid("hrd-c")
	t1, wimseA := tn.exchange(t, policyID, extA, scopes, t0)
	t2, wimseB := tn.exchange(t, policyID, extB, scopes, t1["access_token"].(string))
	t3, wimseC := tn.exchange(t, policyID, extC, scopes, t2["access_token"].(string))

	for i, tc := range []struct {
		body   map[string]any
		holder string
		chain  []string
	}{
		{t1, extA, []string{wimseA}},
		{t2, extB, []string{wimseB, wimseA}},
		{t3, extC, []string{wimseC, wimseB, wimseA}},
	} {
		claims := decodeJWTPayload(t, tc.body["access_token"].(string))
		assert.Equal(t, alice, claims["sub"], "hop %d: sub stays the person", i+1)
		assert.Equal(t, "user", claims["principal_type"], "hop %d", i+1)
		assert.Equal(t, t0Claims["iss"], claims["user_id_iss"], "hop %d: the person's issuer travels with her", i+1)
		assert.Equal(t, tc.holder, claims["client_id"], "hop %d: client_id is the holder", i+1)
		assert.Equal(t, tc.chain, actChain(t, claims), "hop %d: act nests the agents, current first", i+1)
		assert.ElementsMatch(t, []any{"data:read"}, claims["scopes"], "hop %d: scopes stay within T0", i+1)
		assert.Equal(t, float64(i+1), claims["delegation_depth"], "hop %d", i+1)

		// The actor's attributes are inside the outermost act; the top level
		// describes the person.
		act := claims["act"].(map[string]any)
		assert.Equal(t, tc.holder, act["external_id"], "hop %d: actor attributes live in act", i+1)
		assert.NotEmpty(t, act["identity_type"], "hop %d", i+1)
		assert.NotEmpty(t, act["trust_level"], "hop %d", i+1)
		assert.NotContains(t, claims, "external_id", "hop %d: not at the top level", i+1)
		assert.NotContains(t, claims, "trust_level", "hop %d: not at the top level", i+1)
		assert.NotContains(t, claims, "identity_type", "hop %d: not at the top level", i+1)
		if inner, ok := act["act"].(map[string]any); ok {
			assert.Equal(t, []string{"sub"}, mapKeys(inner, "act"), "hop %d: prior actors carry only sub", i+1)
		}

		// Persisted principal agrees with the token.
		assert.Equal(t, principalRow{"user", alice, t0Claims["iss"].(string)}, principalOf(t, tc.body["access_token"].(string)))
	}
}

// mapKeys returns m's keys except those named in skip.
func mapKeys(m map[string]any, skip ...string) []string {
	var out []string
	for k := range m {
		ignored := false
		for _, s := range skip {
			if k == s {
				ignored = true
			}
		}
		if !ignored {
			out = append(out, k)
		}
	}
	return out
}

// TestRFC8693Profile_WorkloadSubject: a chain rooted in an agent's own
// authority keeps that agent as `sub`, with principal_type workload, and the
// sub-agent as the current actor.
func TestRFC8693Profile_WorkloadSubject(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)

	root, orch := tn.workloadRoot(t, policyID, scopes)
	rootClaims := decodeJWTPayload(t, root)
	assert.Equal(t, orch, rootClaims["sub"])
	assert.Equal(t, "workload", rootClaims["principal_type"])
	assert.Nil(t, rootClaims["user_id_iss"], "user_id_iss names a person's issuer only")

	child, sub := tn.exchange(t, policyID, uid("hrd-sub"), scopes, root)
	claims := decodeJWTPayload(t, child["access_token"].(string))
	assert.Equal(t, orch, claims["sub"], "the orchestrator stays the principal")
	assert.Equal(t, "workload", claims["principal_type"])
	assert.Equal(t, sub, actChain(t, claims)[0], "the sub-agent is the current actor")
}

// TestRFC8693_ScopeString covers D23 on the ZeroID side: the rfc8693 profile
// emits the RFC 9068 §2.2.3 space-delimited `scope` beside `scopes`.
func TestRFC8693_ScopeString(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read", "data:write"}
	policyID := tn.policy(t, scopes)
	root, _ := tn.workloadRoot(t, policyID, scopes)
	claims := decodeJWTPayload(t, root)
	assert.Equal(t, "data:read data:write", claims["scope"])
	assert.ElementsMatch(t, []any{"data:read", "data:write"}, claims["scopes"], "scopes stays until consumers move")
}

// TestLegacyProfile_Unchanged is the golden check that a tenant on the default
// profile sees today's claims, apart from the additive fixes (issued_token_type,
// client_id): the actor in `sub`, a single-level `act`, identity attributes at
// the top level, no principal_type and no scope string.
func TestLegacyProfile_Unchanged(t *testing.T) {
	tn := newTenant(t, "")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)

	root, alice := tn.userRoot(t, scopes)
	mid, wimseA := tn.exchange(t, policyID, uid("hrd-lg-a"), scopes, root)
	leaf, wimseB := tn.exchange(t, policyID, uid("hrd-lg-b"), scopes, mid["access_token"].(string))

	midClaims := decodeJWTPayload(t, mid["access_token"].(string))
	assert.Equal(t, wimseA, midClaims["sub"], "legacy: the actor is sub")
	assert.Equal(t, map[string]any{"sub": alice}, midClaims["act"], "legacy: act holds the parent's sub, one level")

	claims := decodeJWTPayload(t, leaf["access_token"].(string))
	assert.Equal(t, wimseB, claims["sub"])
	assert.Equal(t, map[string]any{"sub": wimseA}, claims["act"], "legacy: one level, no nesting")
	for _, absent := range []string{"principal_type", "scope", "user_id_iss"} {
		assert.NotContains(t, claims, absent, "legacy must not emit %s", absent)
	}
	for _, present := range []string{"external_id", "identity_type", "trust_level", "sub_type", "status"} {
		assert.Contains(t, claims, present, "legacy keeps %s at the top level", present)
	}
}

// TestRFC8693Profile_DelegationGraphKeepsTheDelegatingAgent: the delegation
// graph records which agent delegated (delegated_by_wimse_uri). Under rfc8693
// the parent's `sub` is the person, so the delegating agent must be read from
// the parent's current actor, or the graph would show Alice delegating.
func TestRFC8693Profile_DelegationGraphKeepsTheDelegatingAgent(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)

	root, _ := tn.userRoot(t, scopes)
	mid, wimseA := tn.exchange(t, policyID, uid("hrd-dg-a"), scopes, root)
	leaf, _ := tn.exchange(t, policyID, uid("hrd-dg-b"), scopes, mid["access_token"].(string))

	jti := decodeJWTPayload(t, leaf["access_token"].(string))["jti"].(string)
	var delegatedBy string
	err := testDB.NewSelect().Table("issued_credentials").Column("delegated_by_wimse_uri").
		Where("jti = ?", jti).Scan(context.Background(), &delegatedBy)
	require.NoError(t, err)
	assert.Equal(t, wimseA, delegatedBy, "the delegating agent is A, not the person")
}

// TestChainSubject_SurvivesRefresh: a refresh is continuity of the same grant,
// so the refreshed token keeps the principal and its issuer — across more than
// one rotation, since the family copies the issuer forward.
func TestChainSubject_SurvivesRefresh(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	user := uid("hrd-rt-user")
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":       "external-principal-assertion",
		"account_id":          tn.account,
		"project_id":          tn.project,
		"user_id":             user,
		"audience":            "codeoid",
		"issue_refresh_token": true,
	}, map[string]string{testTrustedServiceHeader: "trusted-service"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	_ = resp.Body.Close()
	refresh := body["refresh_token"].(string)
	iss := decodeJWTPayload(t, body["access_token"].(string))["iss"].(string)

	for rotation := 1; rotation <= 2; rotation++ {
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": refresh,
			"client_id":     "codeoid",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "rotation %d", rotation)
		rotated := decode(t, resp)
		_ = resp.Body.Close()
		refresh = rotated["refresh_token"].(string)

		claims := decodeJWTPayload(t, rotated["access_token"].(string))
		assert.Equal(t, user, claims["sub"], "rotation %d: sub survives", rotation)
		assert.Equal(t, "user", claims["principal_type"], "rotation %d", rotation)
		assert.Equal(t, iss, claims["user_id_iss"], "rotation %d", rotation)
		assert.Equal(t, principalRow{"user", user, iss}, principalOf(t, rotated["access_token"].(string)), "rotation %d", rotation)
	}

	var familyIssuers []string
	err := testDB.NewSelect().Table("refresh_tokens").Column("principal_iss").
		Where("user_id = ?", user).Scan(context.Background(), &familyIssuers)
	require.NoError(t, err)
	require.Len(t, familyIssuers, 3, "the family: issuance plus two rotations")
	for _, got := range familyIssuers {
		assert.Equal(t, iss, got, "every row in the family records the principal's issuer")
	}
}

// headerTyp returns a compact JWT's JOSE typ header.
func headerTyp(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var hdr map[string]any
	require.NoError(t, json.Unmarshal(raw, &hdr))
	typ, _ := hdr["typ"].(string)
	return typ
}

// policyWith creates a delegation policy in the tenant with extra fields set.
func (tn hrdTenant) policyWith(t *testing.T, scopes []string, extra map[string]any) string {
	t.Helper()
	body := map[string]any{
		"name":                 uid("hrd-policy"),
		"allowed_grant_types":  []string{"client_credentials", "token_exchange"},
		"allowed_scopes":       scopes,
		"max_delegation_depth": 5,
		"max_ttl_seconds":      3600,
	}
	for k, v := range extra {
		body[k] = v
	}
	return createRichCredentialPolicy(t, body, tn.headers)
}

// TestRFC8693_ExchangeResponse is the design's response check: the exchange
// response carries issued_token_type, and the token is typed at+jwt (RFC 9068
// §2.1) by default under the new profile.
func TestRFC8693_ExchangeResponse(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)
	root, _ := tn.workloadRoot(t, policyID, scopes)
	child, _ := tn.exchange(t, policyID, uid("hrd-er"), scopes, root)

	assert.Equal(t, issuedTokenTypeAccessToken, child["issued_token_type"])
	assert.Equal(t, "at+jwt", headerTyp(t, child["access_token"].(string)))
	assert.Equal(t, "at+jwt", headerTyp(t, root), "every token of the tenant, not only exchanges")
}

// TestAccessTokenTyp_PolicyToggle covers D9's resolution of the RFC 9068 vs
// JWT-SVID conflict: at+jwt is the rfc8693 default, a policy can choose JWT so
// an agent's tokens stay valid JWT-SVIDs, and legacy is always JWT.
func TestAccessTokenTyp_PolicyToggle(t *testing.T) {
	scopes := []string{"data:read"}

	t.Run("rfc8693 policy choosing JWT keeps the token a JWT-SVID", func(t *testing.T) {
		tn := newTenant(t, "rfc8693")
		policyID := tn.policyWith(t, scopes, map[string]any{"jwt_typ": "JWT"})
		root, _ := tn.workloadRoot(t, policyID, scopes)
		assert.Equal(t, "JWT", headerTyp(t, root))
		child, _ := tn.exchange(t, policyID, uid("hrd-typ"), scopes, root)
		assert.Equal(t, "JWT", headerTyp(t, child["access_token"].(string)), "the actor's own policy decides its token")
	})

	t.Run("legacy ignores a policy asking for at+jwt", func(t *testing.T) {
		tn := newTenant(t, "")
		policyID := tn.policyWith(t, scopes, map[string]any{"jwt_typ": "at+jwt"})
		root, _ := tn.workloadRoot(t, policyID, scopes)
		assert.Equal(t, "JWT", headerTyp(t, root), "the legacy profile's shape never changes")
	})

	t.Run("an update can reset to the default", func(t *testing.T) {
		tn := newTenant(t, "rfc8693")
		policyID := tn.policyWith(t, scopes, map[string]any{"jwt_typ": "JWT"})
		resp := doRequest(t, http.MethodPatch, adminPath("/credential-policies/"+policyID), map[string]any{"jwt_typ": ""}, tn.headers)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
		root, _ := tn.workloadRoot(t, policyID, scopes)
		assert.Equal(t, "at+jwt", headerTyp(t, root))
	})

	t.Run("an unknown typ is refused", func(t *testing.T) {
		tn := newTenant(t, "rfc8693")
		resp := post(t, adminPath("/credential-policies"), map[string]any{
			"name": uid("hrd-bad-typ"), "jwt_typ": "JOSE",
		}, tn.headers)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusUnprocessableEntity}, resp.StatusCode)
		_ = resp.Body.Close()

		policyID := tn.policy(t, scopes)
		resp = doRequest(t, http.MethodPatch, adminPath("/credential-policies/"+policyID), map[string]any{"jwt_typ": "JOSE"}, tn.headers)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a client error, not a server fault")
		_ = resp.Body.Close()
	})
}
