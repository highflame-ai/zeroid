package integration_test

// Federated client assertions (ADR 0042 D8, path P2): an agent authenticates
// on client_credentials with a token its workload issuer signed for it (here
// a Kubernetes service account token from the mock IdP), resolved to its
// identity through a binding, with no secret and no registered client.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/internal/mockidp"
)

type workloadFed struct {
	f      *dbFederation
	tn     tiTenant
	rowID  string
	agent  string // identity id
	wimse  string
	sub    string // the service account the binding maps
	policy string
}

func newWorkloadFed(t *testing.T) *workloadFed {
	t.Helper()
	w := &workloadFed{f: newDBFederation(t), tn: newTITenant(t)}
	w.policy = createRichCredentialPolicy(t, map[string]any{
		"name":                uid("wl-policy"),
		"allowed_grant_types": []string{"client_credentials"},
		"allowed_scopes":      []string{"tools:read"},
		"max_ttl_seconds":     3600,
	}, w.tn.headers)
	resp := post(t, adminPath("/identities"), map[string]any{
		"external_id":          uid("wl-agent"),
		"identity_type":        "agent",
		"trust_level":          "unverified",
		"owner_user_id":        "user-test-owner",
		"credential_policy_id": w.policy,
	}, w.tn.headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	got := decode(t, resp)
	_ = resp.Body.Close()
	w.agent, w.wimse = got["id"].(string), got["wimse_uri"].(string)

	status, body := w.f.call(t, http.MethodPost, "/external-issuers", map[string]any{
		"kind": "workload", "display_name": "Mock cluster", "issuer": w.f.idp.K8sIssuer(),
		"audiences": []string{federationIssuer},
	}, w.tn.headers)
	require.Equal(t, http.StatusCreated, status, "create workload row: %v", body)
	w.rowID = body["id"].(string)

	w.sub = "system:serviceaccount:agents:" + uid("sa")
	status, body = w.f.bind(t, w.tn, w.rowID, w.sub, w.agent, false)
	require.Equal(t, http.StatusCreated, status, "bind: %v", body)
	require.Equal(t, true, body["enabled"])
	return w
}

// assertion mints a service account token for w.sub, aud = ZeroID, with a
// fresh jti, then applies overrides.
func (w *workloadFed) assertion(t *testing.T, overrides map[string]any) string {
	t.Helper()
	claims := map[string]any{"sub": w.sub, "aud": federationIssuer, "jti": uid("jti")}
	for k, v := range overrides {
		claims[k] = v
	}
	return w.f.mint(t, mockidp.ProfileK8sServiceAccount, claims)
}

func (w *workloadFed) clientCredentials(t *testing.T, assertion string, extra map[string]any) tokenResponse {
	t.Helper()
	return postFederation(t, w.f.http.URL, merged(map[string]any{
		"grant_type":            "client_credentials",
		"scope":                 "tools:read",
		"client_assertion":      assertion,
		"client_assertion_type": clientAssertionType,
	}, extra))
}

func TestFederatedClientAssertion(t *testing.T) {
	w := newWorkloadFed(t)

	t.Run("mints a token for the bound agent, with no secret and no registered client", func(t *testing.T) {
		resp := w.clientCredentials(t, w.assertion(t, nil), nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		claims := decodeJWTPayload(t, resp.AccessToken)
		assert.Equal(t, w.wimse, claims["sub"], "the token is the bound agent's")
		// The client is the (issuer, subject) pair: a Kubernetes subject
		// repeats across clusters, and any tenant can bind any subject string.
		assert.Equal(t, w.f.idp.K8sIssuer()+"#"+w.sub, claims["client_id"])
		assert.Equal(t, "client_credentials", claims["grant_type"])
		assert.Equal(t, "federated_assertion", claims["client_auth"])
		assert.Equal(t, w.tn.account, claims["account_id"], "the tenant comes from the binding (D5)")
		assert.Equal(t, w.tn.project, claims["project_id"])
	})

	t.Run("a client_id equal to the sub or to <iss>#<sub> is accepted", func(t *testing.T) {
		for _, id := range []string{w.sub, w.f.idp.K8sIssuer() + "#" + w.sub} {
			resp := w.clientCredentials(t, w.assertion(t, nil), map[string]any{"client_id": id})
			assert.Equal(t, http.StatusOK, resp.StatusCode, "client_id %q: %s", id, resp.RawBody)
		}
	})

	t.Run("an aud naming this server's token endpoint is accepted", func(t *testing.T) {
		resp := w.clientCredentials(t, w.assertion(t, map[string]any{"aud": federationIssuer + "/oauth2/token"}), nil)
		// The row must list it too; it lists only the issuer, so this is the
		// row's refusal, after verification, not the server-audience one.
		requireRefused(t, resp, "invalid_client")
		status, _ := w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID,
			map[string]any{"audiences": []string{federationIssuer, federationIssuer + "/oauth2/token"}}, w.tn.headers)
		require.Equal(t, http.StatusOK, status)
		t.Cleanup(func() {
			_, _ = w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID,
				map[string]any{"audiences": []string{federationIssuer}}, w.tn.headers)
		})
		resp = w.clientCredentials(t, w.assertion(t, map[string]any{"aud": federationIssuer + "/oauth2/token"}), nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	})

	t.Run("the replay key names the subject, not the jti alone", func(t *testing.T) {
		other := "system:serviceaccount:agents:" + uid("sa")
		status, body := w.f.bind(t, w.tn, w.rowID, other, w.agent, false)
		require.Equal(t, http.StatusCreated, status, "bind: %v", body)
		jti := uid("jti")
		for _, sub := range []string{w.sub, other} {
			resp := w.clientCredentials(t, w.assertion(t, map[string]any{"sub": sub, "jti": jti}), nil)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "jti %q under %q: %s", jti, sub, resp.RawBody)
		}
	})

	t.Run("a registered private_key_jwt client still takes the registered path", func(t *testing.T) {
		// Its assertion's iss is its own client_id, which names no workload
		// row, so the workload row on this server must not catch it.
		clientID := uid("pkjwt-cc")
		key := generateKey(t)
		reg := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id":                  clientID,
			"name":                       clientID,
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       clientJWKS(t, key),
			"grant_types":                []string{"client_credentials"},
			"scopes":                     []string{"tools:read"},
			"identity_id":                w.agent,
		}, w.tn.headers)
		require.Equal(t, http.StatusCreated, reg.StatusCode)
		_ = reg.Body.Close()
		resp := postFederation(t, w.f.http.URL, merged(map[string]any{
			"grant_type": "client_credentials", "scope": "tools:read",
		}, clientCreds(t, clientID, key)))
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		claims := decodeJWTPayload(t, resp.AccessToken)
		assert.Equal(t, clientID, claims["client_id"])
		assert.Nil(t, claims["client_auth"])
	})

	t.Run("claim constraints the assertion does not meet get the generic refusal", func(t *testing.T) {
		status, body := w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID,
			map[string]any{"claim_constraints": map[string][]string{"team": {"payments"}}}, w.tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		t.Cleanup(func() {
			_, _ = w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID,
				map[string]any{"claim_constraints": map[string][]string{}}, w.tn.headers)
		})
		resp := w.clientCredentials(t, w.assertion(t, nil), nil)
		requireRefused(t, resp, "invalid_client")
		assert.Contains(t, resp.RawBody, "invalid client credentials")
		assert.NotContains(t, resp.RawBody, "constraint")
		resp = w.clientCredentials(t, w.assertion(t, map[string]any{"team": "payments"}), nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "an assertion that meets them: %s", resp.RawBody)
	})

	t.Run("the agent cannot revoke its own token: there is no client to authenticate as", func(t *testing.T) {
		token := w.clientCredentials(t, w.assertion(t, nil), nil).AccessToken
		require.NotEmpty(t, token)
		call := func(path string, body map[string]any) (int, map[string]any) {
			b, err := json.Marshal(body)
			require.NoError(t, err)
			resp, err := http.Post(w.f.http.URL+path, "application/json", bytes.NewReader(b))
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			var out map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&out)
			return resp.StatusCode, out
		}
		for name, auth := range map[string]map[string]any{
			"a federated assertion": {"client_assertion": w.assertion(t, nil), "client_assertion_type": clientAssertionType},
			"<iss>#<sub>":           {"client_id": w.f.idp.K8sIssuer() + "#" + w.sub},
			// This server requires authentication on token inspection, as
			// production always does.
			"no client authentication": {},
		} {
			status, body := call("/oauth2/token/revoke", merged(map[string]any{"token": token}, auth))
			assert.Equal(t, http.StatusUnauthorized, status, "%s: %v", name, body)
			assert.Equal(t, "invalid_client", body["error"], name)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		replayed := w.assertion(t, nil)
		require.Equal(t, http.StatusOK, w.clientCredentials(t, replayed, nil).StatusCode)

		cases := []struct {
			name      string
			assertion string
			extra     map[string]any
			code      string
			contains  string
		}{
			{"a replayed assertion", replayed, nil, "invalid_client", "replay"},
			{"several audiences", w.assertion(t, map[string]any{"aud": []string{federationIssuer, "https://elsewhere.example"}}), nil, "invalid_client", "exactly one audience"},
			{"an audience the row does not trust", w.assertion(t, map[string]any{"aud": "https://elsewhere.example"}), nil, "invalid_client", "invalid client credentials"},
			{"no jti", w.assertion(t, map[string]any{"jti": nil}), nil, "invalid_client", "jti"},
			{"a client_id that is not the sub", w.assertion(t, nil), map[string]any{"client_id": "someone-else"}, "invalid_client", "client_id"},
			{"a subject with no binding", w.assertion(t, map[string]any{"sub": "system:serviceaccount:agents:unbound"}), nil, "invalid_grant", "no enabled binding"},
			{"another tenant named in the request", w.assertion(t, nil), map[string]any{"account_id": uid("other"), "project_id": "p"}, "invalid_grant", "tenant"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				resp := w.clientCredentials(t, tc.assertion, tc.extra)
				requireRefused(t, resp, tc.code)
				assert.Contains(t, resp.RawBody, tc.contains)
			})
		}
	})

	t.Run("the jti is spent before the binding is read", func(t *testing.T) {
		unbound := w.assertion(t, map[string]any{"sub": "system:serviceaccount:agents:" + uid("unbound")})
		requireRefused(t, w.clientCredentials(t, unbound, nil), "invalid_grant")
		resp := w.clientCredentials(t, unbound, nil)
		requireRefused(t, resp, "invalid_client")
		assert.Contains(t, resp.RawBody, "replay")
	})

	t.Run("lifetime is capped by the row's max token age, not by time left", func(t *testing.T) {
		mint := func(ttl int) string {
			tok, _, err := w.f.idp.Mint(mockidp.MintRequest{
				Profile: mockidp.ProfileK8sServiceAccount, TTLSeconds: ttl,
				Claims: map[string]any{"sub": w.sub, "aud": federationIssuer, "jti": uid("jti")},
			})
			require.NoError(t, err)
			return tok
		}
		// The Kubernetes TokenRequest API issues nothing shorter than 600 s.
		resp := w.clientCredentials(t, mint(600), nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "a fresh 600 s service account token: %s", resp.RawBody)
		resp = w.clientCredentials(t, mint(1200), nil)
		requireRefused(t, resp, "invalid_client")
		assert.Contains(t, resp.RawBody, "lifetime")
	})

	t.Run("an audience the row lists but that is not this server", func(t *testing.T) {
		const broad = "https://kubernetes.default.svc"
		status, _ := w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID,
			map[string]any{"audiences": []string{federationIssuer, broad}}, w.tn.headers)
		require.Equal(t, http.StatusOK, status)
		t.Cleanup(func() {
			_, _ = w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID,
				map[string]any{"audiences": []string{federationIssuer}}, w.tn.headers)
		})
		resp := w.clientCredentials(t, w.assertion(t, map[string]any{"aud": broad}), nil)
		requireRefused(t, resp, "invalid_client")
		assert.Contains(t, resp.RawBody, "this server's issuer or token endpoint")
	})

	// Until the signature verifies, every refusal is the one an unknown client
	// gets: an unsigned probe learns nothing about which issuers, claims or
	// rows this server trusts.
	requireGeneric := func(t *testing.T, resp tokenResponse) {
		t.Helper()
		requireRefused(t, resp, "invalid_client")
		assert.Contains(t, resp.RawBody, "invalid client credentials")
	}

	t.Run("a signature from another issuer's key", func(t *testing.T) {
		forged, _, err := w.f.idp.Mint(mockidp.MintRequest{
			Profile: mockidp.ProfileEntraAppOnly,
			Claims:  map[string]any{"iss": w.f.idp.K8sIssuer(), "sub": w.sub, "aud": federationIssuer, "jti": uid("jti")},
		})
		require.NoError(t, err)
		requireGeneric(t, w.clientCredentials(t, forged, nil))
	})

	t.Run("an unsigned probe", func(t *testing.T) {
		payload, err := json.Marshal(map[string]any{"iss": w.f.idp.K8sIssuer(), "sub": w.sub, "aud": federationIssuer,
			"jti": uid("jti"), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()})
		require.NoError(t, err)
		probe := craftUnsignedJWT("none", string(payload))
		resp := w.clientCredentials(t, probe, nil)
		requireGeneric(t, resp)
		assert.NotContains(t, resp.RawBody, "alg")
	})

	t.Run("a client_secret alongside the assertion", func(t *testing.T) {
		requireGeneric(t, w.clientCredentials(t, w.assertion(t, nil), map[string]any{"client_secret": "s3cret"}))
	})

	t.Run("not yet valid", func(t *testing.T) {
		future := time.Now().Add(10 * time.Minute).Unix()
		requireRefused(t, w.clientCredentials(t, w.assertion(t, map[string]any{"nbf": future}), nil), "invalid_client")
	})

	t.Run("no iat", func(t *testing.T) {
		requireGeneric(t, w.clientCredentials(t, w.assertion(t, map[string]any{"iat": nil}), nil))
	})

	t.Run("the wrong client_assertion_type", func(t *testing.T) {
		requireGeneric(t, w.clientCredentials(t, w.assertion(t, nil), map[string]any{"client_assertion_type": "urn:example:other"}))
	})

	t.Run("an agent that is not adopted gets nothing, and the refusal names its state", func(t *testing.T) {
		discovered := w.tn.discoveredAgent(t)
		sub := "system:serviceaccount:agents:" + uid("unadopted")
		status, body := w.f.bind(t, w.tn, w.rowID, sub, discovered, false)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		resp := w.clientCredentials(t, w.assertion(t, map[string]any{"sub": sub}), nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "discovered")
	})

	t.Run("a disabled issuer row authenticates no one", func(t *testing.T) {
		status, _ := w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID, map[string]any{"enabled": false}, w.tn.headers)
		require.Equal(t, http.StatusOK, status)
		t.Cleanup(func() {
			_, _ = w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID, map[string]any{"enabled": true}, w.tn.headers)
		})
		resp := w.clientCredentials(t, w.assertion(t, nil), nil)
		requireRefused(t, resp, "invalid_client")
		// The assertion is not verified yet, so the refusal says nothing about
		// which issuers this server trusts.
		assert.Contains(t, resp.RawBody, "invalid client credentials")
		assert.NotContains(t, resp.RawBody, "disabled")
	})
}

// A token minted from a federated client assertion is held by whatever runs
// the agent's credential provider, so it cannot enroll a durable key on an
// agent that was meant to hold no secret.
// A federated token lives 15 minutes (ADR 0042 D9), however long the
// identity's policy would allow, and no longer than a stricter policy allows.
func TestFederatedClientAssertion_TokenLifetime(t *testing.T) {
	lifetime := func(t *testing.T, resp tokenResponse) float64 {
		t.Helper()
		require.Equal(t, http.StatusOK, resp.StatusCode, resp.RawBody)
		claims := decodeJWTPayload(t, resp.AccessToken)

		return claims["exp"].(float64) - claims["iat"].(float64)
	}

	w := newWorkloadFed(t) // policy max_ttl_seconds 3600
	assert.InDelta(t, 900, lifetime(t, w.clientCredentials(t, w.assertion(t, nil), nil)), 1,
		"15 minutes, not the policy's hour")

	resp := doRequest(t, http.MethodPatch, adminPath("/credential-policies/"+w.policy),
		map[string]any{"max_ttl_seconds": 300}, w.tn.headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	assert.InDelta(t, 300, lifetime(t, w.clientCredentials(t, w.assertion(t, nil), nil)), 1,
		"a stricter policy shortens it instead of refusing the mint")
}

func TestFederatedClientAssertion_TokenCannotEnrollAKey(t *testing.T) {
	w := newWorkloadFed(t)
	resp := w.clientCredentials(t, w.assertion(t, nil), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)

	key := generateKey(t)
	raw, err := json.Marshal(map[string]any{
		"new_public_key_pem": ecPublicKeyPEM(t, key),
		"new_key_proof":      "not-checked-before-the-token",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, w.f.http.URL+"/agents/self/public-key", bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	enroll, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = enroll.Body.Close() }()
	body := decode(t, enroll)
	assert.Equal(t, http.StatusForbidden, enroll.StatusCode, "%v", body)
	assert.Contains(t, body["detail"], "federated client assertion")
}

// The replay ledger is keyed on (iss, sub, jti): the same subject and jti
// from two issuers are two assertions, not a replay.
func TestFederatedClientAssertion_ReplayKeyNamesTheIssuer(t *testing.T) {
	a, b := newWorkloadFed(t), newWorkloadFed(t)
	status, body := b.f.bind(t, b.tn, b.rowID, a.sub, b.agent, false)
	require.Equal(t, http.StatusCreated, status, "bind: %v", body)
	jti := uid("jti")
	resp := a.clientCredentials(t, a.assertion(t, map[string]any{"jti": jti}), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	resp = b.clientCredentials(t, b.assertion(t, map[string]any{"sub": a.sub, "jti": jti}), nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the same sub and jti under another issuer: %s", resp.RawBody)
}

// '#' is reserved for federated client ids (<iss>#<sub>), so no registered
// client can carry one, by whichever route it is registered.
func TestRegisteredClientIDCannotContainHash(t *testing.T) {
	t.Run("admin registration", func(t *testing.T) {
		resp := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id": "https://cluster.example#system:serviceaccount:agents:" + uid("sa"),
			"name":      "lookalike",
		}, nil)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, decode(t, resp)["detail"], "'#'")
	})

	t.Run("a binding's presenting client", func(t *testing.T) {
		f := newDBFederation(t)
		tn := newTITenant(t)
		tid := uid("hash-tid")
		rowID := f.entraRow(t, tn, tid, nil)["id"].(string)
		status, body := f.bind(t, tn, rowID, uid("app")+"#1", tn.agent(t).id, true)
		require.Equal(t, http.StatusBadRequest, status, "%v", body)
		assert.Equal(t, "invalid_request", body["code"])
	})
}
