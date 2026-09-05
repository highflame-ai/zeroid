package integration_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// PROBE FILE — not regression coverage. These tests characterise the CURRENT
// behaviour of the scope-ceiling chain so the findings in
// highflame-ai/highflame-sdk#143 can be confirmed or rejected from evidence
// rather than from reading. Each test asserts what the platform does TODAY and
// says in its name whether that is the reported bug.
//
// Delete this file once the findings are dispositioned.
// ─────────────────────────────────────────────────────────────────────────────

// tokenScopes mints a token via the api_key grant and returns the `scopes`
// claim off the server-signed JWT (not a client-side echo).
func tokenScopes(t *testing.T, apiKey, scope string) (int, []string, map[string]any) {
	t.Helper()
	body := map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
	}
	if scope != "" {
		body["scope"] = scope
	}
	resp := post(t, "/oauth2/token", body, nil)
	raw := decode(t, resp)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, raw
	}
	tok, ok := raw["access_token"].(string)
	require.True(t, ok, "no access_token in response: %v", raw)
	return resp.StatusCode, jwtScopes(t, tok), raw
}

// jwtScopes decodes the JWT payload and returns the `scopes` claim.
func jwtScopes(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "not a JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	rawScopes, ok := claims["scopes"]
	if !ok || rawScopes == nil {
		return nil
	}
	arr, ok := rawScopes.([]any)
	require.True(t, ok, "scopes claim is not an array: %T", rawScopes)
	out := make([]string, 0, len(arr))
	for _, s := range arr {
		out = append(out, s.(string))
	}
	return out
}

// createAPIKey creates a service key and returns the secret.
func createAPIKey(t *testing.T, body map[string]any, headers map[string]string) string {
	t.Helper()
	resp := post(t, adminPath("/api-keys"), body, headers)
	raw := decode(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create api key: %v", raw)
	key, ok := raw["key"].(string)
	require.True(t, ok, "response missing key: %v", raw)
	return key
}

// P1 — authn#180 repro. A registered agent's key, with no scope ceiling
// anywhere in the chain, is granted a scope nobody ever authorised.
// Confirms zeroid#301 D3 + zeroid#300.
func TestProbe_P1_UnboundedAgentGetsArbitraryScope(t *testing.T) {
	agent := registerAgent(t, uid("probe-p1"))

	// Baseline: no scope requested.
	code, base, _ := tokenScopes(t, agent.APIKey, "")
	require.Equal(t, http.StatusOK, code)
	t.Logf("no scope requested -> %v", base)

	// Now ask for something invented.
	code, scopes, raw := tokenScopes(t, agent.APIKey, "acme:nonsense tools:execute")
	t.Logf("requested 'acme:nonsense tools:execute' -> status=%d scopes=%v raw_err=%v", code, scopes, raw["error"])

	assert.Equal(t, http.StatusOK, code, "FINDING: mint succeeds for an unheld scope")
	assert.Contains(t, scopes, "acme:nonsense",
		"FINDING CONFIRMED: token asserts a scope no policy or identity ever granted")
}

// P2a — NOT in any filed issue. POST /api-keys with neither identity_id nor
// product 500s: domain.APIKey.IdentityID is `type:uuid` with no `nullzero`
// (unlike the sibling ReplacedBy field), so bun writes ” into a nullable UUID
// column. This is the reachability question for zeroid#299 — the "unlinked
// key" state cannot be created through the public admin API at all.
func TestProbe_P2a_UnlinkedKeyCreation500s(t *testing.T) {
	h := tenantHeaders(uid("acct-p2a"), uid("proj-p2a"))

	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name": "p2a-no-identity-no-product",
	}, h)
	body := decode(t, resp)
	t.Logf("POST /api-keys with no identity_id and no product -> status=%d body=%v", resp.StatusCode, body)

	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode,
		"FINDING: creating an API key without identity_id or product 500s on a UUID cast")
}

// P2b — zeroid#299 proper. Seeds the unlinked state DIRECTLY in the DB (the
// only way to reach it, per P2a), then mints. Answers whether the synthetic
// identity really escapes every ceiling, or only the identity-policy layer.
func TestProbe_P2b_UnlinkedKeySkipsIdentityPolicyOnly(t *testing.T) {
	h := tenantHeaders(uid("acct-p2b"), uid("proj-p2b"))
	acct, proj := h["X-Account-ID"], h["X-Project-ID"]

	// A key policy WITH a real scope ceiling.
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                "p2b-ceiling",
		"max_ttl_seconds":     3600,
		"allowed_scopes":      []string{"data:read"},
		"allowed_grant_types": []string{"api_key", "client_credentials"},
	}, h)

	// Seed a service_keys row with identity_id NULL — unreachable via the API.
	secret := "zid_sk_" + strings.ReplaceAll(uid("p2bkey"), "-", "")
	sum := sha256.Sum256([]byte(secret))
	_, err := testDB.NewRaw(
		`INSERT INTO service_keys (id, name, description, key_prefix, key_hash, key_version,
		     account_id, project_id, identity_id, created_by, scopes, product, environment,
		     state, usage_count, credential_policy_id)
		 VALUES (gen_random_uuid(), 'p2b-unlinked', '', ?, ?, 1, ?, ?, NULL, 'test-user',
		     '{}', '', 'live', 'active', 0, ?)`,
		secret[:16], hex.EncodeToString(sum[:]), acct, proj, policyID,
	).Exec(t.Context())
	require.NoError(t, err, "seed unlinked service key")

	code, scopes, raw := tokenScopes(t, secret, "acme:nonsense")
	t.Logf("UNLINKED key, key-policy ceiling [data:read], requested 'acme:nonsense' -> status=%d scopes=%v err=%v", code, scopes, raw["error"])
	assert.NotContains(t, scopes, "acme:nonsense",
		"the key's OWN policy ceiling still binds even with no linked identity")
}

// P3 — NOT in any filed issue. Chained intersectScopes calls re-widen: an
// emptied intersection is re-read by the next layer as "no scope requested",
// which per RFC 6749 §3.3 grants that layer's FULL allow-list. Requesting a
// scope you are forbidden therefore yields MORE than requesting a legal one.
func TestProbe_P3_EmptiedIntersectionReWidensAtNextLayer(t *testing.T) {
	h := tenantHeaders(uid("acct-p3"), uid("proj-p3"))

	// Key policy allows two scopes.
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                "p3-policy",
		"max_ttl_seconds":     3600,
		"allowed_scopes":      []string{"data:read", "data:write"},
		"allowed_grant_types": []string{"api_key", "client_credentials"},
	}, h)

	// The KEY itself is restricted to just one of them. `product` makes the
	// service auto-provision a linked identity (required — see P2a).
	key := createAPIKey(t, map[string]any{
		"name":                 "p3-narrow-key",
		"product":              "p3probe",
		"credential_policy_id": policyID,
		"scopes":               []string{"data:read"},
	}, h)

	// Legal request — inside the key's own scope list.
	code, legal, _ := tokenScopes(t, key, "data:read")
	t.Logf("requested 'data:read' (key holds it)      -> status=%d scopes=%v", code, legal)

	// Illegal request — NOT in the key's scope list, but in the policy's.
	code2, illegal, raw := tokenScopes(t, key, "data:write")
	t.Logf("requested 'data:write' (key does NOT hold it) -> status=%d scopes=%v raw_err=%v", code2, illegal, raw["error"])

	assert.NotContains(t, illegal, "data:write",
		"FINDING: requesting a scope outside the key's own scopes[] re-widens to the policy's full allow-list")
	assert.LessOrEqual(t, len(illegal), len(legal),
		"FINDING: an illegal request yielded a BROADER token than a legal one")
}

// P4 — zeroid#302. The three causes of an empty delegation intersection are
// indistinguishable in the error_description.
func TestProbe_P4_DelegationErrorCannotNameTheEmptyTerm(t *testing.T) {
	orch := registerAgent(t, uid("probe-p4-orch"))

	subKey := generateKey(t)
	sub := registerIdentity(t, uid("probe-p4-sub"), []string{"data:read"}, ecPublicKeyPEM(t, subKey))

	// Mint an orchestrator token holding nothing in particular.
	code, orchScopes, raw := tokenScopes(t, orch.APIKey, "")
	require.Equal(t, http.StatusOK, code, "%v", raw)
	t.Logf("orchestrator token scopes: %v", orchScopes)

	subjectToken := raw["access_token"].(string)
	actorAssertion := buildAssertion(t, subKey, sub.WIMSEURI)

	exchange := func(scope string) (int, string) {
		body := map[string]any{
			"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":        subjectToken,
			"subject_token_type":   "urn:ietf:params:oauth:token-type:jwt",
			"actor_token":          actorAssertion,
			"actor_token_type":     "urn:ietf:params:oauth:token-type:jwt",
			"requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
		}
		if scope != "" {
			body["scope"] = scope
		}
		resp := post(t, "/oauth2/token", body, nil)
		out := decode(t, resp)
		desc, _ := out["error_description"].(string)
		if desc == "" {
			desc, _ = out["detail"].(string)
		}
		return resp.StatusCode, desc
	}

	// Cause A: no scope requested at all.
	cA, dA := exchange("")
	// Cause B: parent does not hold it (sub-agent does).
	cB, dB := exchange("data:read")
	// Cause C: sub-agent was never registered for it.
	cC, dC := exchange("billing:write")

	t.Logf("cause A (nothing requested)       -> %d %q", cA, dA)
	t.Logf("cause B (delegator lacks it)      -> %d %q", cB, dB)
	t.Logf("cause C (sub-agent lacks it)      -> %d %q", cC, dC)

	assert.False(t, dA == dB && dB == dC,
		"FINDING CONFIRMED: all three causes return an identical error_description")
}

// P5 — zeroid#301 D4. The mint silently drops unheld scopes and returns 200,
// and when the intersection empties entirely it issues a token with no
// `scopes` claim — which is exactly the shape Shield's checkScopeCeiling
// treats as "check not applicable".
func TestProbe_P5_MintIssuesScopelessTokenOn200(t *testing.T) {
	h := tenantHeaders(uid("acct-p5"), uid("proj-p5"))

	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                "p5-policy",
		"max_ttl_seconds":     3600,
		"allowed_scopes":      []string{"data:read"},
		"allowed_grant_types": []string{"api_key", "client_credentials"},
	}, h)

	key := createAPIKey(t, map[string]any{
		"name":                 "p5-key",
		"product":              "p5probe",
		"credential_policy_id": policyID,
	}, h)

	code, scopes, raw := tokenScopes(t, key, "billing:write")
	t.Logf("ceiling [data:read], requested 'billing:write' -> status=%d scopes=%v err=%v", code, scopes, raw["error"])

	assert.NotEqual(t, http.StatusOK, code,
		"FINDING: an empty intersection mints a scope-less token on HTTP 200 instead of erroring")
}

// P6 — the LIVE shape of finding A, per the dev1/prod census: no key uses the
// per-key scopes[] field, but 573 dev1 / 198 prod active keys have a key
// policy ceiling AND a distinct identity policy that carries scopes. That is
// the layer-2-empties → layer-3-re-widens path. Does the IssueCredential
// chokepoint catch the re-widened set, or is it an escalation?
func TestProbe_P6_LiveShape_KeyPolicyNarrowerThanIdentityPolicy(t *testing.T) {
	h := tenantHeaders(uid("acct-p6"), uid("proj-p6"))

	// Identity policy — the wide authority ceiling.
	identPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                "p6-identity-policy",
		"max_ttl_seconds":     3600,
		"allowed_scopes":      []string{"data:read", "admin:all"},
		"allowed_grant_types": []string{"api_key", "client_credentials"},
	}, h)

	// Key policy — a strict subset (EnforceSubset requires this).
	keyPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                "p6-key-policy",
		"max_ttl_seconds":     3600,
		"allowed_scopes":      []string{"data:read"},
		"allowed_grant_types": []string{"api_key", "client_credentials"},
	}, h)

	identityID := registerIdentityWithPolicy(t, uid("p6-ident"), identPolicyID, "", nil, h)

	key := createAPIKey(t, map[string]any{
		"name":                 "p6-key",
		"identity_id":          identityID,
		"credential_policy_id": keyPolicyID,
	}, h)

	// Sanity: a legal request stays inside the key policy.
	code, legal, _ := tokenScopes(t, key, "data:read")
	t.Logf("requested 'data:read'    -> status=%d scopes=%v", code, legal)

	// The probe: request something OUTSIDE the key policy. Layer 2 empties,
	// layer 3 re-widens to the identity policy's FULL set [data:read admin:all].
	code2, out, raw := tokenScopes(t, key, "billing:write")
	t.Logf("requested 'billing:write' -> status=%d scopes=%v err=%v desc=%v",
		code2, out, raw["error"], raw["error_description"])

	assert.NotContains(t, out, "admin:all",
		"FINDING: re-widened to the identity policy's full set, escaping the key policy ceiling")
}
