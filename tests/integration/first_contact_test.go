package integration_test

// First contact: a credential that verified in full under an enabled issuer
// row, naming an agent no binding maps yet, registers that agent as the
// row's first_contact says (docs/external-issuers.md, "First contact").
// discover registers it unadopted and refuses; adopt registers it adopted
// under the row's mapping and mints. Both triggers are covered: a federated
// client assertion under a workload row, and an ID-JAG under a person row.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/internal/mockidp"
)

const (
	fcOwner         = "user-fc-owner"
	fcActor         = "system:first_contact"
	fcLabelFilter   = "discovered_via:first_contact"
	fcJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	fcTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// fcTenant is a tenant plus the project first contact registers into.
type fcTenant struct {
	tiTenant
	mapped        string
	mappedHeaders map[string]string
}

func newFCTenant(t *testing.T) fcTenant {
	t.Helper()
	tn := fcTenant{tiTenant: newTITenant(t), mapped: uid("fc-proj")}
	tn.mappedHeaders = map[string]string{"X-Account-ID": tn.account, "X-Project-ID": tn.mapped, "X-User-ID": "admin@" + tn.account}
	return tn
}

// defaultPolicy gives the mapped project a default credential policy that an
// adopted agent can mint under: the identities first contact registers take
// their project's default policy.
func (tn fcTenant) defaultPolicy(t *testing.T) {
	t.Helper()
	createRichCredentialPolicy(t, map[string]any{
		"name":                "default",
		"allowed_grant_types": []string{"client_credentials", "jwt_bearer", "token_exchange"},
		"allowed_scopes":      []string{"tools:read"},
		"user_grant_scopes":   []string{"tools:read"},
		"max_ttl_seconds":     3600,
	}, tn.mappedHeaders)
}

// identity reads an identity in the mapped project.
func (tn fcTenant) identity(t *testing.T, id string) map[string]any {
	t.Helper()
	resp := get(t, adminPath("/identities/"+id), tn.mappedHeaders)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decode(t, resp)
}

// firstContactIdentities lists the mapped project's identities first contact
// registered, through the label filter, in every status (a list leaves
// discovered identities out unless asked for them).
func (tn fcTenant) firstContactIdentities(t *testing.T) []map[string]any {
	t.Helper()
	resp := get(t, adminPath("/identities?status=discovered,pending,active,suspended,deactivated,expired&label="+
		url.QueryEscape(fcLabelFilter)), tn.mappedHeaders)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	var out []map[string]any
	items, _ := body["identities"].([]any)
	for _, it := range items {
		out = append(out, it.(map[string]any))
	}
	return out
}

// bindingsFor returns the row's bindings for subjectKey.
func bindingsFor(t *testing.T, f *dbFederation, tn tiTenant, rowID, subjectKey string) []map[string]any {
	t.Helper()
	status, body := f.call(t, http.MethodGet, "/external-issuers/"+rowID+"/bindings", nil, tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)
	var out []map[string]any
	for _, it := range body["items"].([]any) {
		b := it.(map[string]any)
		if b["subject_key"] == subjectKey {
			out = append(out, b)
		}
	}
	return out
}

// fcWorkload is a workload row (the mock cluster) with first contact set.
type fcWorkload struct {
	f     *dbFederation
	tn    fcTenant
	rowID string
}

func newFCWorkload(t *testing.T, bounds zeroid.FirstContactConfig, settings map[string]any) *fcWorkload {
	t.Helper()
	w := &fcWorkload{
		f:  newDBFederationWith(t, func(c *zeroid.Config) { c.Federation.FirstContact = bounds }),
		tn: newFCTenant(t),
	}
	w.tn.defaultPolicy(t)
	body := map[string]any{
		"kind": "workload", "display_name": "Mock cluster", "issuer": w.f.idp.K8sIssuer(),
		"audiences": []string{federationIssuer},
	}
	for k, v := range settings {
		body[k] = v
	}
	status, got := w.f.call(t, http.MethodPost, "/external-issuers", body, w.tn.headers)
	require.Equal(t, http.StatusCreated, status, "create workload row: %v", got)
	w.rowID = got["id"].(string)
	return w
}

func (w *fcWorkload) set(t *testing.T, patch map[string]any) {
	t.Helper()
	status, body := w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID, patch, w.tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)
}

func (w *fcWorkload) assertion(t *testing.T, sub string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{"sub": sub, "aud": federationIssuer, "jti": uid("jti")}
	for k, v := range extra {
		claims[k] = v
	}
	return w.f.mint(t, mockidp.ProfileK8sServiceAccount, claims)
}

func (w *fcWorkload) clientCredentials(t *testing.T, sub string, extra map[string]any) tokenResponse {
	t.Helper()
	return postFederation(t, w.f.http.URL, map[string]any{
		"grant_type":            "client_credentials",
		"scope":                 "tools:read",
		"client_assertion":      w.assertion(t, sub, extra),
		"client_assertion_type": clientAssertionType,
	})
}

func newSA() string { return "system:serviceaccount:agents:" + uid("sa") }

func discoverSettings(tn fcTenant) map[string]any {
	return map[string]any{"first_contact": "discover", "first_contact_project_id": tn.mapped}
}

func adoptSettings(tn fcTenant) map[string]any {
	return map[string]any{"first_contact": "adopt", "first_contact_project_id": tn.mapped, "first_contact_owner_user_id": fcOwner}
}

func TestFirstContact_IssuerAPI(t *testing.T) {
	f := newDBFederation(t)
	tn := newFCTenant(t)
	create := func(t *testing.T, extra map[string]any) (int, map[string]any) {
		t.Helper()
		body := map[string]any{
			"kind": "workload", "issuer": f.idp.K8sIssuer(), "audiences": []string{federationIssuer},
		}
		for k, v := range extra {
			body[k] = v
		}
		return f.call(t, http.MethodPost, "/external-issuers", body, tn.headers)
	}

	t.Run("create refuses a mode without its mapping", func(t *testing.T) {
		for name, extra := range map[string]map[string]any{
			"discover without a project": {"first_contact": "discover"},
			"adopt without an owner":     {"first_contact": "adopt", "first_contact_project_id": tn.mapped},
			"adopt without a project":    {"first_contact": "adopt", "first_contact_owner_user_id": fcOwner},
		} {
			status, body := create(t, extra)
			assert.Equal(t, http.StatusBadRequest, status, "%s: %v", name, body)
			assert.Equal(t, "first_contact_mapping_required", body["code"], name)
		}
	})

	t.Run("create refuses a malformed mapping or mode", func(t *testing.T) {
		status, body := create(t, map[string]any{"first_contact": "discover", "first_contact_project_id": "a/b"})
		assert.Equal(t, http.StatusBadRequest, status, "%v", body)
		assert.Equal(t, "invalid_first_contact", body["code"])
		status, _ = create(t, map[string]any{"first_contact": "sometimes", "first_contact_project_id": tn.mapped})
		assert.GreaterOrEqual(t, status, http.StatusBadRequest)
		assert.Less(t, status, http.StatusInternalServerError)
	})

	var rowID string
	t.Run("create stores the settings, and they read back", func(t *testing.T) {
		status, body := create(t, discoverSettings(tn))
		require.Equal(t, http.StatusCreated, status, "%v", body)
		rowID = body["id"].(string)
		assert.Equal(t, "discover", body["first_contact"])
		assert.Equal(t, tn.mapped, body["first_contact_project_id"])
		assert.Equal(t, "", body["first_contact_owner_user_id"])
		status, body = f.call(t, http.MethodGet, "/external-issuers/"+rowID, nil, tn.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, "discover", body["first_contact"])
	})

	t.Run("a row created without first contact is off", func(t *testing.T) {
		other := newFCTenant(t)
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": f.idp.OktaIssuer(), "claim_mapping": map[string]string{"user_id": "sub"},
		}, other.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		assert.Equal(t, "off", body["first_contact"])
	})

	t.Run("patch checks the mode against the stored mapping", func(t *testing.T) {
		status, body := f.call(t, http.MethodPatch, "/external-issuers/"+rowID, map[string]any{"first_contact": "adopt"}, tn.headers)
		assert.Equal(t, http.StatusBadRequest, status, "%v", body)
		assert.Equal(t, "first_contact_mapping_required", body["code"])

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact": "adopt", "first_contact_owner_user_id": fcOwner}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, "adopt", body["first_contact"])
		assert.Equal(t, fcOwner, body["first_contact_owner_user_id"])

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID, map[string]any{"first_contact_project_id": ""}, tn.headers)
		assert.Equal(t, http.StatusBadRequest, status, "clearing the project of an adopt row: %v", body)
		assert.Equal(t, "first_contact_mapping_required", body["code"])

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID, map[string]any{"first_contact": "off"}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, "off", body["first_contact"])
		assert.Equal(t, tn.mapped, body["first_contact_project_id"], "switching off keeps the mapping")
	})

	t.Run("a disabled row stores first contact", func(t *testing.T) {
		status, body := f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"enabled": false, "first_contact": "adopt"}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, false, body["enabled"])
		assert.Equal(t, "adopt", body["first_contact"])
	})

	t.Run("an unknown field is refused, as before", func(t *testing.T) {
		status, _ := f.call(t, http.MethodPatch, "/external-issuers/"+rowID, map[string]any{"first_contact_mode": "adopt"}, tn.headers)
		assert.GreaterOrEqual(t, status, http.StatusBadRequest)
	})
}

func TestFirstContact_Workload(t *testing.T) {
	t.Run("off: refused as without a binding, and nothing is registered", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		sub := newSA()
		resp := w.clientCredentials(t, sub, nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
		assert.Empty(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub))
		assert.Empty(t, w.tn.firstContactIdentities(t))
	})

	t.Run("discover: registers a discovered agent with a disabled binding, then refuses naming its state", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		w.set(t, discoverSettings(w.tn))
		sub := newSA()

		resp := w.clientCredentials(t, sub, nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "agent identity is discovered")

		bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
		require.Len(t, bindings, 1)
		b := bindings[0]
		assert.Equal(t, false, b["enabled"])
		assert.Equal(t, false, b["explicitly_disabled"], "adoption enables it")
		assert.Equal(t, fcActor, b["created_by"])

		id := w.tn.identity(t, b["identity_id"].(string))
		assert.Equal(t, "discovered", id["status"])
		assert.Equal(t, "first_contact", id["origin"])
		assert.Equal(t, w.tn.account, id["account_id"])
		assert.Equal(t, w.tn.mapped, id["project_id"])
		assert.Equal(t, "unverified", id["trust_level"])
		assert.Equal(t, sub, id["name"])
		assert.Equal(t, "first_contact", id["labels"].(map[string]any)["discovered_via"])
		record := id["metadata"].(map[string]any)["first_contact"].(map[string]any)
		assert.Equal(t, w.f.idp.K8sIssuer(), record["issuer"])
		assert.Equal(t, w.rowID, record["issuer_id"])
		assert.Equal(t, sub, record["subject_key"])
		assert.Equal(t, "client_credentials", record["grant_type"])
		assert.Equal(t, "discover", record["mode"])
		assert.NotEmpty(t, record["first_seen_at"])
		assert.Nil(t, record["aws"], "no AWS claims on a cluster token")

		listed := w.tn.firstContactIdentities(t)
		require.Len(t, listed, 1, "the label filter lists it")
		assert.Equal(t, id["id"], listed[0]["id"])

		t.Run("a second contact registers nothing more", func(t *testing.T) {
			resp := w.clientCredentials(t, sub, nil)
			requireRefused(t, resp, "invalid_grant")
			assert.Contains(t, resp.RawBody, "agent identity is discovered")
			assert.Len(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub), 1)
			assert.Len(t, w.tn.firstContactIdentities(t), 1)
		})

		t.Run("a dismissed agent is never registered again", func(t *testing.T) {
			resp := post(t, adminPath("/identities/"+id["id"].(string)+"/dismiss"), nil, w.tn.mappedHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_ = resp.Body.Close()
			tr := w.clientCredentials(t, sub, nil)
			requireRefused(t, tr, "invalid_grant")
			assert.Contains(t, tr.RawBody, "deactivated")
			assert.Len(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub), 1)
		})
	})

	t.Run("adopt: registers an adopted agent under the mapping and mints for it", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		w.set(t, adoptSettings(w.tn))
		sub := newSA()

		resp := w.clientCredentials(t, sub, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		claims := decodeJWTPayload(t, resp.AccessToken)
		assert.Equal(t, w.tn.account, claims["account_id"])
		assert.Equal(t, w.tn.mapped, claims["project_id"], "the mapped project")
		assert.Equal(t, w.f.idp.K8sIssuer()+"#"+sub, claims["client_id"])

		bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
		require.Len(t, bindings, 1)
		assert.Equal(t, true, bindings[0]["enabled"])
		id := w.tn.identity(t, bindings[0]["identity_id"].(string))
		assert.Equal(t, id["wimse_uri"], claims["sub"], "the token is the registered agent's")
		assert.Equal(t, "active", id["status"])
		assert.Equal(t, fcOwner, id["owner_user_id"], "the mapped owner")
		assert.Equal(t, "verified_third_party", id["trust_level"])
		assert.NotEmpty(t, id["adopted_at"])
		assert.Equal(t, "adopt", id["metadata"].(map[string]any)["first_contact"].(map[string]any)["mode"])

		again := w.clientCredentials(t, sub, nil)
		require.Equal(t, http.StatusOK, again.StatusCode, "body=%s", again.RawBody)
		assert.Equal(t, claims["sub"], decodeJWTPayload(t, again.AccessToken)["sub"], "the same agent")
		assert.Len(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub), 1)
	})

	t.Run("AWS STS claims are kept, request tags are not", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		w.set(t, discoverSettings(w.tn))
		sub := "arn:aws:iam::123456789012:role/" + uid("AgentRuntime")
		resp := w.clientCredentials(t, sub, map[string]any{
			"https://sts.amazonaws.com/": map[string]any{
				"aws_account":    "123456789012",
				"org_id":         "o-abc1234567",
				"ou_path":        []string{"o-abc1234567/r-ab12/ou-ab12-11111111/"},
				"principal_tags": map[string]any{"team": "payments"},
				"request_tags":   map[string]any{"chosen": "by the caller"},
			},
		})
		requireRefused(t, resp, "invalid_grant")
		bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
		require.Len(t, bindings, 1)
		id := w.tn.identity(t, bindings[0]["identity_id"].(string))
		assert.Regexp(t, `^arn_aws_iam__123456789012_role_AgentRuntime.*-[0-9a-f]{20}$`, id["external_id"],
			"an ARN is no path segment, so the external_id is its readable form and a hash")
		record := id["metadata"].(map[string]any)["first_contact"].(map[string]any)
		assert.Equal(t, sub, record["subject_key"])
		assert.Equal(t, map[string]any{
			"account":        "123456789012",
			"org_id":         "o-abc1234567",
			"ou_path":        []any{"o-abc1234567/r-ab12/ou-ab12-11111111/"},
			"principal_tags": map[string]any{"team": "payments"},
		}, record["aws"])
	})

	t.Run("a disabled binding keeps today's refusal", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		w.set(t, adoptSettings(w.tn))
		agent := w.tn.agent(t)
		sub := newSA()
		status, body := w.f.call(t, http.MethodPost, "/external-issuers/"+w.rowID+"/bindings",
			map[string]any{"subject_key": sub, "identity_id": agent.id, "enabled": false}, w.tn.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)

		resp := w.clientCredentials(t, sub, nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
		assert.Len(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub), 1, "no second binding")
		assert.Empty(t, w.tn.firstContactIdentities(t))
	})

	t.Run("a disabled row registers nothing", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		w.set(t, adoptSettings(w.tn))
		w.set(t, map[string]any{"enabled": false})
		sub := newSA()
		requireRefused(t, w.clientCredentials(t, sub, nil), "invalid_client")
		assert.Empty(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub))
		assert.Empty(t, w.tn.firstContactIdentities(t))
	})

	t.Run("a refused assertion registers nothing", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		w.set(t, adoptSettings(w.tn))
		sub := newSA()
		// Verified, but addressed to several audiences.
		resp := w.clientCredentials(t, sub, map[string]any{"aud": []string{federationIssuer, "https://elsewhere.example"}})
		requireRefused(t, resp, "invalid_client")
		assert.Empty(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub))
	})
}

func TestFirstContact_Bounds(t *testing.T) {
	t.Run("past the per-row rate, the plain refusal", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{RatePerMinute: 2}, nil)
		w.set(t, discoverSettings(w.tn))
		for i := 0; i < 2; i++ {
			resp := w.clientCredentials(t, newSA(), nil)
			assert.Contains(t, resp.RawBody, "agent identity is discovered", "registration %d", i+1)
		}
		sub := newSA()
		resp := w.clientCredentials(t, sub, nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
		assert.Empty(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub))
		assert.Len(t, w.tn.firstContactIdentities(t), 2)
	})

	t.Run("past the account's cap on unadopted agents, the plain refusal", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{MaxDiscoveredPerAccount: 1}, nil)
		w.set(t, discoverSettings(w.tn))
		first := w.clientCredentials(t, newSA(), nil)
		assert.Contains(t, first.RawBody, "agent identity is discovered")
		sub := newSA()
		resp := w.clientCredentials(t, sub, nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
		assert.Empty(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub))

		t.Run("adopt registers adopted agents, which the cap does not count", func(t *testing.T) {
			w.set(t, adoptSettings(w.tn))
			resp := w.clientCredentials(t, newSA(), nil)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		})
	})
}

// Concurrent first contacts for one subject register one agent and one
// binding: the account's first-contact lock serialises them, and each later
// one finds the first one's binding.
func TestFirstContact_Concurrency(t *testing.T) {
	for _, mode := range []string{"discover", "adopt"} {
		t.Run(mode, func(t *testing.T) {
			w := newFCWorkload(t, zeroid.FirstContactConfig{RatePerMinute: 100}, nil)
			if mode == "adopt" {
				w.set(t, adoptSettings(w.tn))
			} else {
				w.set(t, discoverSettings(w.tn))
			}
			sub := newSA()
			const n = 8
			assertions := make([]string, n)
			for i := range assertions {
				assertions[i] = w.assertion(t, sub, nil)
			}
			statuses := make([]int, n)
			bodies := make([]string, n)
			var wg sync.WaitGroup
			for i := range assertions {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					raw, _ := json.Marshal(map[string]any{
						"grant_type": "client_credentials", "scope": "tools:read",
						"client_assertion": assertions[i], "client_assertion_type": clientAssertionType,
					})
					resp, err := http.Post(w.f.http.URL+"/oauth2/token", "application/json", bytes.NewReader(raw))
					if err != nil {
						bodies[i] = err.Error()
						return
					}
					defer func() { _ = resp.Body.Close() }()
					b, _ := io.ReadAll(resp.Body)
					statuses[i], bodies[i] = resp.StatusCode, string(b)
				}(i)
			}
			wg.Wait()
			for i := range statuses {
				if mode == "adopt" {
					assert.Equal(t, http.StatusOK, statuses[i], "request %d: %s", i, bodies[i])
				} else {
					assert.Equal(t, http.StatusBadRequest, statuses[i], "request %d: %s", i, bodies[i])
					assert.Contains(t, bodies[i], "agent identity is discovered", "request %d", i)
				}
			}
			assert.Len(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub), 1, "one binding")
			assert.Len(t, w.tn.firstContactIdentities(t), 1, "one identity")
		})
	}
}

// fcIDJAG is a person row (the mock Okta org) with first contact set, and a
// CIMD client the IdP issues ID-JAGs to.
type fcIDJAG struct {
	f        *dbFederation
	tn       fcTenant
	rowID    string
	clientID string
	aliceSub string
	keyed    oauthClientResp
}

func newFCIDJAG(t *testing.T, settings map[string]any) *fcIDJAG {
	t.Helper()
	key := generateKey(t)
	base, docClient := newCIMDDocumentsOrigin(t, map[string]string{
		"/agent.json": idJAGCIMDDoc(t, "private_key_jwt", key, []string{"authorization_code", fcJWTBearer, fcTokenExchange}, nil),
	})
	p := &fcIDJAG{
		f: newDBFederationWith(t, func(c *zeroid.Config) { c.CIMD = zeroid.CIMDConfig{Enabled: true} },
			zeroid.WithCIMDHTTPClient(docClient)),
		tn:       newFCTenant(t),
		aliceSub: uid("00u-alice"),
	}
	p.clientID = base + "/agent.json"
	p.keyed = oauthClientResp{ClientID: p.clientID, Key: key}
	p.tn.defaultPolicy(t)
	body := map[string]any{
		"kind": "person", "issuer": p.f.idp.OktaIssuer(),
		"claim_mapping": map[string]string{"user_id": "sub", "email": "email", "email_verified": "email_verified"},
	}
	for k, v := range settings {
		body[k] = v
	}
	status, got := p.f.call(t, http.MethodPost, "/external-issuers", body, p.tn.headers)
	require.Equal(t, http.StatusCreated, status, "create okta row: %v", got)
	p.rowID = got["id"].(string)
	p.f.member(p.f.idp.OktaIssuer(), p.aliceSub, "user_hf_alice")
	return p
}

func (p *fcIDJAG) idJAG(t *testing.T, clientID, agent, person string) string {
	t.Helper()
	return p.f.mint(t, mockidp.ProfileOktaIDJAG, map[string]any{
		"aud": federationIssuer, "sub": person, "client_id": clientID,
		"act":      map[string]any{"sub": agent, "sub_profile": "ai_agent"},
		"resource": "https://gateway.example/mcp/github", "scope": "tools:read", "jti": uid("jti"),
	})
}

func (p *fcIDJAG) redeem(t *testing.T, assertion string, client oauthClientResp) tokenResponse {
	t.Helper()
	return postFederation(t, p.f.http.URL, map[string]any{
		"grant_type":            fcJWTBearer,
		"assertion":             assertion,
		"client_id":             client.ClientID,
		"client_assertion":      rpAssertion(t, client),
		"client_assertion_type": clientAssertionType,
	})
}

func TestFirstContact_IDJAG(t *testing.T) {
	p := newFCIDJAG(t, nil)
	set := func(t *testing.T, patch map[string]any) {
		t.Helper()
		status, body := p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, patch, p.tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
	}

	t.Run("off: refused as without a binding", func(t *testing.T) {
		agent := uid("0oa-agent")
		resp := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
		assert.Empty(t, bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent))
	})

	t.Run("discover: registers the agent named in act.sub, then refuses naming its state", func(t *testing.T) {
		set(t, discoverSettings(p.tn))
		agent := uid("0oa-agent")
		assertion := p.idJAG(t, p.clientID, agent, p.aliceSub)
		resp := p.redeem(t, assertion, p.keyed)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "agent identity is discovered")

		bindings := bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent)
		require.Len(t, bindings, 1)
		assert.Equal(t, false, bindings[0]["enabled"])
		id := p.tn.identity(t, bindings[0]["identity_id"].(string))
		assert.Equal(t, "discovered", id["status"])
		assert.Equal(t, agent, id["external_id"], "an opaque client id is the external_id")
		record := id["metadata"].(map[string]any)["first_contact"].(map[string]any)
		assert.Equal(t, p.f.idp.OktaIssuer(), record["issuer"])
		assert.Equal(t, agent, record["subject_key"])
		assert.Equal(t, "id_jag", record["grant_type"])
		assert.NotContains(t, fmt.Sprint(id["metadata"]), p.aliceSub, "the person is not recorded on the agent")

		// The jti was spent before the agent was registered, so this ID-JAG can
		// never be redeemed later, once the agent is adopted.
		n, err := testDB.NewSelect().Table("id_jag_jti").Where("jti = ?", decodeJWTPayload(t, assertion)["jti"]).Count(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 1, n, "the jti is spent")
		replay := p.redeem(t, assertion, p.keyed)
		requireRefused(t, replay, "invalid_grant")
		assert.Len(t, bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent), 1, "a replay registers nothing")
	})

	// The person is resolved before anything is registered, so a person the
	// resolver refuses leaves no identity or binding behind, and the ID-JAG
	// is not spent: it redeems once the person is a member.
	for _, mode := range []string{"discover", "adopt"} {
		t.Run(mode+": a person the resolver refuses registers nothing", func(t *testing.T) {
			if mode == "adopt" {
				set(t, adoptSettings(p.tn))
			} else {
				set(t, discoverSettings(p.tn))
			}
			agent, stranger := uid("0oa-agent"), uid("00u-stranger")
			assertion := p.idJAG(t, p.clientID, agent, stranger)
			resp := p.redeem(t, assertion, p.keyed)
			requireRefused(t, resp, "invalid_grant")
			assert.Contains(t, resp.RawBody, "not a member")
			assert.Empty(t, bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent), "no binding")
			for _, id := range p.tn.firstContactIdentities(t) {
				assert.NotEqual(t, agent, id["external_id"], "no identity")
			}

			p.f.member(p.f.idp.OktaIssuer(), stranger, "user_hf_"+stranger)
			resp = p.redeem(t, assertion, p.keyed)
			if mode == "adopt" {
				assert.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
			} else {
				assert.Contains(t, resp.RawBody, "agent identity is discovered")
			}
			assert.Len(t, bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent), 1)
		})
	}

	t.Run("adopt: registers the agent adopted and mints with the person as subject", func(t *testing.T) {
		set(t, adoptSettings(p.tn))
		agent := uid("0oa-agent")
		resp := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		claims := decodeIssuedTokenClaims(t, resp.AccessToken)
		assert.Equal(t, "user_hf_alice", claims["sub"])
		assert.Equal(t, p.tn.account, claims["account_id"])
		assert.Equal(t, p.tn.mapped, claims["project_id"])

		bindings := bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent)
		require.Len(t, bindings, 1)
		assert.Equal(t, true, bindings[0]["enabled"])
		id := p.tn.identity(t, bindings[0]["identity_id"].(string))
		assert.Equal(t, "active", id["status"])
		assert.Equal(t, fcOwner, id["owner_user_id"])
		assert.Equal(t, []string{id["wimse_uri"].(string)}, actChain(t, claims), "the registered agent is the current actor")

		again := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
		require.Equal(t, http.StatusOK, again.StatusCode, "body=%s", again.RawBody)
		assert.Len(t, bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent), 1)
	})

	t.Run("adopt: the ID-JAG that registered the agent stays single use", func(t *testing.T) {
		set(t, adoptSettings(p.tn))
		assertion := p.idJAG(t, p.clientID, uid("0oa-agent"), p.aliceSub)
		require.Equal(t, http.StatusOK, p.redeem(t, assertion, p.keyed).StatusCode)
		replay := p.redeem(t, assertion, p.keyed)
		requireRefused(t, replay, "invalid_grant")
		assert.Contains(t, replay.RawBody, "already been redeemed")
	})

	t.Run("a registered client registers nothing, and keeps its ID-JAG redeemable", func(t *testing.T) {
		set(t, adoptSettings(p.tn))
		clientID := uid("registered-client")
		key := keyClient(t, p.tn.tiTenant, clientID, "")
		client := oauthClientResp{ClientID: clientID, Key: key}
		agent := uid("0oa-agent")
		assertion := p.idJAG(t, clientID, agent, p.aliceSub)
		for i := 0; i < 2; i++ {
			resp := p.redeem(t, assertion, client)
			requireRefused(t, resp, "invalid_grant")
			assert.Contains(t, resp.RawBody, "no enabled binding", "attempt %d", i+1)
		}
		assert.Empty(t, bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent))
	})

	t.Run("an external_id another identity holds is never taken over", func(t *testing.T) {
		set(t, discoverSettings(p.tn))
		agent := uid("0oa-agent")
		resp := post(t, adminPath("/identities"), map[string]any{
			"external_id": agent, "identity_type": "agent", "owner_user_id": "someone",
		}, p.tn.mappedHeaders)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		_ = resp.Body.Close()

		tr := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
		requireRefused(t, tr, "invalid_grant")
		assert.Contains(t, tr.RawBody, "no enabled binding")
		assert.Empty(t, bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent))
	})
}

// An inventory sync that names the same issuer row and subject key merges
// into the first-contact identity instead of adding a second one.
func TestFirstContact_DiscoveryMerge(t *testing.T) {
	w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
	w.set(t, discoverSettings(w.tn))
	sub := newSA()
	requireRefused(t, w.clientCredentials(t, sub, nil), "invalid_grant")
	bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
	require.Len(t, bindings, 1)
	fcID := bindings[0]["identity_id"].(string)

	ingest := func(t *testing.T, headers map[string]string, extra map[string]any) map[string]any {
		t.Helper()
		body := map[string]any{
			"external_id": uid("runtime"), "origin": "aws_agentcore", "name": "Payments runtime",
			"labels":   map[string]any{"team": "payments"},
			"metadata": map[string]any{"runtime_arn": "arn:aws:bedrock-agentcore:runtime/x", "issuer_binding": map[string]any{"issuer_id": w.rowID, "subject_key": sub}},
		}
		for k, v := range extra {
			body[k] = v
		}
		resp := post(t, adminPath("/identities/discovered"), body, headers)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return decode(t, resp)
	}

	t.Run("the same tenant merges", func(t *testing.T) {
		out := ingest(t, w.tn.mappedHeaders, nil)
		assert.Equal(t, false, out["created"])
		got := out["identity"].(map[string]any)
		assert.Equal(t, fcID, got["id"])
		assert.Equal(t, "Payments runtime", got["name"])
		labels := got["labels"].(map[string]any)
		assert.Equal(t, "payments", labels["team"])
		assert.Equal(t, "first_contact", labels["discovered_via"], "the marker stays")
		metadata := got["metadata"].(map[string]any)
		assert.Equal(t, "arn:aws:bedrock-agentcore:runtime/x", metadata["runtime_arn"])
		assert.Equal(t, sub, metadata["first_contact"].(map[string]any)["subject_key"], "the arrival record stays")
		assert.Len(t, w.tn.firstContactIdentities(t), 1)
	})

	t.Run("by the issuer URL too", func(t *testing.T) {
		out := ingest(t, w.tn.mappedHeaders, map[string]any{
			"metadata": map[string]any{"issuer_binding": map[string]any{"issuer": w.f.idp.K8sIssuer(), "subject_key": sub}},
		})
		assert.Equal(t, fcID, out["identity"].(map[string]any)["id"])
	})

	t.Run("another project never merges", func(t *testing.T) {
		out := ingest(t, w.tn.headers, nil)
		assert.Equal(t, true, out["created"])
		assert.NotEqual(t, fcID, out["identity"].(map[string]any)["id"])
	})

	t.Run("the first_contact origin is reserved", func(t *testing.T) {
		resp := post(t, adminPath("/identities/discovered"), map[string]any{
			"external_id": uid("spoof"), "origin": "first_contact",
		}, w.tn.mappedHeaders)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// The registration's audit rows name first contact as the actor.
func TestFirstContact_Audited(t *testing.T) {
	w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
	w.set(t, discoverSettings(w.tn))
	sub := newSA()
	requireRefused(t, w.clientCredentials(t, sub, nil), "invalid_grant")
	bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
	require.Len(t, bindings, 1)
	var actors []string
	err := testDB.NewSelect().Table("identity_audit_logs").Column("caller_user_id").
		Where("identity_id = ?", bindings[0]["identity_id"]).Scan(context.Background(), &actors)
	require.NoError(t, err)
	require.NotEmpty(t, actors)
	for _, a := range actors {
		assert.Equal(t, fcActor, a)
	}
}
