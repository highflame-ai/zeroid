package integration_test

// First contact: a credential that verified in full under an enabled issuer
// row, naming an agent no enabled binding maps, is handled as the row's
// first_contact says (docs/external-issuers.md, "First contact"). With no
// binding, discover registers the agent unadopted and refuses; adopt
// registers it adopted under the row's mapping and mints. With only a
// disabled binding, as an inventory sync leaves one, adopt applies the same
// mapping to the existing discovered identity (standing adoption). Both
// triggers are covered: a federated client assertion under a workload row,
// and an ID-JAG under a person row.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
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
	fcOwner           = "user-fc-owner"
	fcActor           = "system:first_contact"
	fcLabelFilter     = "discovered_via:first_contact"
	fcAdoptedFilter   = "adopted_via:first_contact"
	fcJWTBearer       = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	fcTokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	fcInventoryOrigin = "inventory"
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
	return tn.labelled(t, fcLabelFilter)
}

// labelled lists the mapped project's identities with label, in every status.
func (tn fcTenant) labelled(t *testing.T, label string) []map[string]any {
	t.Helper()
	resp := get(t, adminPath("/identities?status=discovered,pending,active,suspended,deactivated,expired&label="+
		url.QueryEscape(label)), tn.mappedHeaders)
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
		assert.Equal(t, "admin@"+tn.account, body["first_contact_updated_by"], "who set the mapping")
		assert.NotEmpty(t, body["first_contact_updated_at"])
		status, body = f.call(t, http.MethodGet, "/external-issuers/"+rowID, nil, tn.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, "discover", body["first_contact"])
		assert.Equal(t, "admin@"+tn.account, body["first_contact_updated_by"])
	})

	t.Run("a row created without first contact is off", func(t *testing.T) {
		other := newFCTenant(t)
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": f.idp.OktaIssuer(), "claim_mapping": map[string]string{"user_id": "sub"},
		}, other.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		assert.Equal(t, "off", body["first_contact"])
		assert.Equal(t, "", body["first_contact_updated_by"], "nobody set a mapping")
		assert.Nil(t, body["first_contact_updated_at"])
	})

	t.Run("only a change to the mode or the mapping names who made it", func(t *testing.T) {
		before := map[string]any{}
		status, body := f.call(t, http.MethodGet, "/external-issuers/"+rowID, nil, tn.headers)
		require.Equal(t, http.StatusOK, status)
		before["by"], before["at"] = body["first_contact_updated_by"], body["first_contact_updated_at"]

		renamer := maps.Clone(tn.headers)
		renamer["X-User-ID"] = "renamer@" + tn.account
		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"display_name": "Renamed", "first_contact": "discover"}, renamer)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, before["by"], body["first_contact_updated_by"], "a rename, and a mode set to what it was, change nothing")
		assert.Equal(t, before["at"], body["first_contact_updated_at"])
		assert.Equal(t, "renamer@"+tn.account, body["updated_by"])

		mapper := maps.Clone(tn.headers)
		mapper["X-User-ID"] = "mapper@" + tn.account
		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact_owner_user_id": "someone"}, mapper)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, "mapper@"+tn.account, body["first_contact_updated_by"])
		assert.NotEqual(t, before["at"], body["first_contact_updated_at"])

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact_owner_user_id": ""}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, "admin@"+tn.account, body["first_contact_updated_by"])
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
		assert.Equal(t, map[string]any{"discovered_via": "first_contact", "adopted_via": "first_contact"}, id["labels"],
			"registered by first contact, and adopted by the row's standing mapping")
		adoption := id["metadata"].(map[string]any)["first_contact_adoption"].(map[string]any)
		assert.Equal(t, w.rowID, adoption["issuer_id"])
		assert.Equal(t, sub, adoption["subject_key"])
		assert.Equal(t, "client_credentials", adoption["grant_type"])
		assert.Equal(t, "admin@"+w.tn.account, adoption["mapping_updated_by"], "who set the mapping that adopted it")
		assert.NotEmpty(t, adoption["mapping_updated_at"])
		listed := w.tn.labelled(t, fcAdoptedFilter)
		require.Len(t, listed, 1, "the adopted_via label lists it")
		assert.Equal(t, id["id"], listed[0]["id"])

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
		assert.Regexp(t, `^first_contact\.arn_aws_iam__123456789012_role_AgentRuntime.*-[0-9a-f]{20}$`, id["external_id"],
			"an ARN is no path segment, so the external_id is its readable form and a hash, in the reserved namespace")
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
		assert.Equal(t, "first_contact."+agent, id["external_id"], "an opaque client id keeps its form, in the reserved namespace")
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

	t.Run("an identity that holds the agent's external_id is never taken over", func(t *testing.T) {
		set(t, discoverSettings(p.tn))
		agent := uid("0oa-agent")
		requireRefused(t, p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed), "invalid_grant")
		bindings := bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent)
		require.Len(t, bindings, 1)
		// A person removes the binding; the identity keeps its external_id.
		status, _ := p.f.call(t, http.MethodDelete, "/external-issuers/"+p.rowID+"/bindings/"+bindings[0]["id"].(string), nil, p.tn.headers)
		require.Equal(t, http.StatusNoContent, status)

		tr := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
		requireRefused(t, tr, "invalid_grant")
		assert.Contains(t, tr.RawBody, "no enabled binding")
		assert.Empty(t, bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent), "nothing bound to the identity that holds it")
		var held int
		for _, id := range p.tn.firstContactIdentities(t) {
			if id["external_id"] == "first_contact."+agent {
				held++
			}
		}
		assert.Equal(t, 1, held, "no second identity")
	})

	t.Run("no caller can take an external_id in first contact's namespace", func(t *testing.T) {
		resp := post(t, adminPath("/identities"), map[string]any{
			"external_id": "first_contact." + uid("0oa-agent"), "identity_type": "agent", "owner_user_id": "someone",
		}, p.tn.mappedHeaders)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		_ = resp.Body.Close()
		resp = post(t, adminPath("/identities/discovered"), map[string]any{
			"external_id": "first_contact." + uid("0oa-agent"), "origin": fcInventoryOrigin,
		}, p.tn.mappedHeaders)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		_ = resp.Body.Close()
	})

	// An IdP can let an agent use an existing app as its OAuth client, and an
	// inventory sync ingests that app under its own id, which is the agent's
	// client id: the subject key first contact saw. The app and the agent stay
	// two identities, whichever arrives first.
	t.Run("an inventory record whose id is the agent's client id is a separate identity", func(t *testing.T) {
		set(t, discoverSettings(p.tn))
		ingestApp := func(t *testing.T, appID, name string) map[string]any {
			t.Helper()
			resp := post(t, adminPath("/identities/discovered"), map[string]any{
				"external_id": appID, "origin": fcInventoryOrigin, "identity_type": "application", "name": name,
				"labels": map[string]any{"kind": "oauth_app"}, "metadata": map[string]any{"app_id": appID},
			}, p.tn.mappedHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			return decode(t, resp)
		}

		t.Run("after first contact", func(t *testing.T) {
			agent := uid("0oa-agent")
			requireRefused(t, p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed), "invalid_grant")
			bindings := bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent)
			require.Len(t, bindings, 1)
			fcID := bindings[0]["identity_id"].(string)

			out := ingestApp(t, agent, "OAuth app")
			assert.Equal(t, true, out["created"], "a new identity, not a merge into the agent")
			app := out["identity"].(map[string]any)
			assert.NotEqual(t, fcID, app["id"])
			assert.Equal(t, agent, app["external_id"])

			// The agent's own inventory record names the subject, and merges.
			resp := post(t, adminPath("/identities/discovered"), map[string]any{
				"external_id": uid("agent-record"), "origin": fcInventoryOrigin, "name": "Inventoried agent",
				"metadata": map[string]any{"issuer_binding": map[string]any{"issuer_id": p.rowID, "subject_key": agent}},
			}, p.tn.mappedHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			merged := decode(t, resp)
			assert.Equal(t, false, merged["created"])
			assert.Equal(t, fcID, merged["identity"].(map[string]any)["id"])

			// A re-sync of the app reconciles into the app, never the agent.
			again := ingestApp(t, agent, "OAuth app, renamed")
			assert.Equal(t, app["id"], again["identity"].(map[string]any)["id"])

			fc := p.tn.identity(t, fcID)
			assert.Equal(t, "Inventoried agent", fc["name"], "the agent keeps the agent's data, not the app's")
			assert.NotContains(t, fc["labels"], "kind")
			assert.NotContains(t, fc["metadata"], "app_id")
			assert.Equal(t, "first_contact."+agent, fc["external_id"])
			assert.Equal(t, "first_contact", fc["origin"])
		})

		t.Run("before first contact", func(t *testing.T) {
			agent := uid("0oa-agent")
			app := ingestApp(t, agent, "OAuth app")["identity"].(map[string]any)

			tr := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
			requireRefused(t, tr, "invalid_grant")
			assert.Contains(t, tr.RawBody, "agent identity is discovered", "registered: the app's id does not block it")
			bindings := bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent)
			require.Len(t, bindings, 1)
			assert.NotEqual(t, app["id"], bindings[0]["identity_id"])
			assert.Equal(t, "first_contact."+agent, p.tn.identity(t, bindings[0]["identity_id"].(string))["external_id"])
		})

		// An identity first contact registered before its external_ids moved
		// into the reserved namespace holds the bare subject key. The ingest
		// lookup is scoped away from first-contact identities, so the app's
		// record is refused as a conflict rather than merged into the agent.
		t.Run("an agent registered with the bare subject key", func(t *testing.T) {
			agent := uid("0oa-agent")
			requireRefused(t, p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed), "invalid_grant")
			bindings := bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent)
			require.Len(t, bindings, 1)
			fcID := bindings[0]["identity_id"].(string)
			_, err := testDB.NewUpdate().Table("identities").Set("external_id = ?", agent).
				Where("id = ?", fcID).Exec(context.Background())
			require.NoError(t, err)
			before := p.tn.identity(t, fcID)

			resp := post(t, adminPath("/identities/discovered"), map[string]any{
				"external_id": agent, "origin": fcInventoryOrigin, "identity_type": "application", "name": "OAuth app",
				"labels": map[string]any{"kind": "oauth_app"}, "metadata": map[string]any{"app_id": agent},
			}, p.tn.mappedHeaders)
			assert.Equal(t, http.StatusConflict, resp.StatusCode)
			assert.Contains(t, decode(t, resp)["detail"], "issuer_binding")

			fc := p.tn.identity(t, fcID)
			assert.Equal(t, before["name"], fc["name"], "the agent is not renamed by the app's record")
			assert.Equal(t, before["identity_type"], fc["identity_type"])
			assert.NotContains(t, fc["labels"], "kind")
			assert.NotContains(t, fc["metadata"], "app_id")
			assert.Equal(t, "first_contact", fc["origin"])

			// The agent's own inventory record still merges through issuer_binding.
			resp = post(t, adminPath("/identities/discovered"), map[string]any{
				"external_id": uid("agent-record"), "origin": fcInventoryOrigin, "name": "Inventoried agent",
				"metadata": map[string]any{"issuer_binding": map[string]any{"issuer_id": p.rowID, "subject_key": agent}},
			}, p.tn.mappedHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			merged := decode(t, resp)
			assert.Equal(t, false, merged["created"])
			assert.Equal(t, fcID, merged["identity"].(map[string]any)["id"])
		})
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

// ── Standing adoption ────────────────────────────────────────────────────────
//
// An inventory sync usually reaches ZeroID before an agent's first call: it
// ingests the agent as discovered, and binds its runtime subject under the
// issuer row with a binding that starts disabled. Under an adopt row, that
// agent's first verified call applies the row's standing mapping to the
// existing identity instead of being refused until a person adopts it.

// fcInventoried is an agent an inventory sync ingested and bound.
type fcInventoried struct {
	id, bindingID string
}

// inventoryAgent ingests a discovered agent into the project headers name,
// and binds subjectKey under rowID to it, as an inventory sync does. The
// binding starts disabled (its identity is not active) and not explicitly.
func inventoryAgent(t *testing.T, f *dbFederation, tn fcTenant, rowID, subjectKey string, headers map[string]string, extra map[string]any) fcInventoried {
	t.Helper()
	body := map[string]any{
		"external_id": uid("inv"), "origin": fcInventoryOrigin, "name": "Inventoried agent",
		"labels":   map[string]any{"team": "payments"},
		"metadata": map[string]any{"source_ref": "inventory-123"},
	}
	maps.Copy(body, extra)
	resp := post(t, adminPath("/identities/discovered"), body, headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decode(t, resp)
	identity := out["identity"].(map[string]any)
	require.Equal(t, "discovered", identity["status"])
	status, b := f.call(t, http.MethodPost, "/external-issuers/"+rowID+"/bindings",
		map[string]any{"subject_key": subjectKey, "identity_id": identity["id"]}, tn.headers)
	require.Equal(t, http.StatusCreated, status, "bind: %v", b)
	require.Equal(t, false, b["enabled"])
	require.Equal(t, false, b["explicitly_disabled"])
	return fcInventoried{id: identity["id"].(string), bindingID: b["id"].(string)}
}

// fcAuditRow is one identity_audit_logs row.
type fcAuditRow struct {
	Caller  string          `bun:"caller_user_id"`
	Table   string          `bun:"table_name"`
	Action  string          `bun:"action"`
	OldData json.RawMessage `bun:"old_data"`
	NewData json.RawMessage `bun:"new_data"`
}

// auditOf returns the audit rows naming an identity, oldest first: its own,
// and its bindings'.
func auditOf(t *testing.T, identityID string) []fcAuditRow {
	t.Helper()
	var rows []fcAuditRow
	err := testDB.NewSelect().Table("identity_audit_logs").
		Column("caller_user_id", "table_name", "action", "old_data", "new_data").
		Where("identity_id = ?", identityID).OrderExpr("seq").Scan(context.Background(), &rows)
	require.NoError(t, err)
	return rows
}

// activations returns the identity's audit rows that moved it from
// discovered to active.
func activations(t *testing.T, rows []fcAuditRow) []fcAuditRow {
	t.Helper()
	var out []fcAuditRow
	for _, r := range rows {
		if r.Table != "identities" || r.Action != "UPDATE" {
			continue
		}
		var before, after map[string]any
		require.NoError(t, json.Unmarshal(r.OldData, &before))
		require.NoError(t, json.Unmarshal(r.NewData, &after))
		if before["status"] == "discovered" && after["status"] == "active" {
			out = append(out, r)
		}
	}
	return out
}

// bindingEnables returns the audit rows that enabled one of the identity's
// bindings.
func bindingEnables(t *testing.T, rows []fcAuditRow) []fcAuditRow {
	t.Helper()
	var out []fcAuditRow
	for _, r := range rows {
		if r.Action != "UPDATE_ISSUER_BINDING" {
			continue
		}
		var before, after map[string]any
		require.NoError(t, json.Unmarshal(r.OldData, &before))
		require.NoError(t, json.Unmarshal(r.NewData, &after))
		if before["enabled"] == false && after["enabled"] == true {
			out = append(out, r)
		}
	}
	return out
}

// requireUntouched checks an inventoried agent is as the inventory left it:
// in status, with no adoption marker, and its binding still disabled.
func requireUntouched(t *testing.T, f *dbFederation, tn fcTenant, headers map[string]string, rowID, subjectKey string, inv fcInventoried, status string) {
	t.Helper()
	resp := get(t, adminPath("/identities/"+inv.id), headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id := decode(t, resp)
	assert.Equal(t, status, id["status"])
	assert.NotContains(t, id["labels"], "adopted_via")
	assert.NotContains(t, id["metadata"], "first_contact_adoption")
	for _, b := range bindingsFor(t, f, tn.tiTenant, rowID, subjectKey) {
		if b["id"] == inv.bindingID {
			assert.Equal(t, false, b["enabled"], "the binding stays disabled")
		}
	}
	assert.Empty(t, activations(t, auditOf(t, inv.id)))
}

func TestFirstContact_StandingAdoption(t *testing.T) {
	t.Run("adopt: an agent an inventory sync bound is adopted on its first call, and mints", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		w.set(t, adoptSettings(w.tn))
		sub := newSA()
		inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
		before := w.tn.identity(t, inv.id)

		resp := w.clientCredentials(t, sub, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		claims := decodeJWTPayload(t, resp.AccessToken)
		assert.Equal(t, before["wimse_uri"], claims["sub"], "the token is the inventoried agent's")
		assert.Equal(t, w.tn.account, claims["account_id"])
		assert.Equal(t, w.tn.mapped, claims["project_id"])

		id := w.tn.identity(t, inv.id)
		assert.Equal(t, "active", id["status"])
		assert.Equal(t, fcOwner, id["owner_user_id"], "the mapped owner")
		assert.Equal(t, "verified_third_party", id["trust_level"])
		assert.NotEmpty(t, id["adopted_at"])
		assert.Equal(t, fcInventoryOrigin, id["origin"], "it keeps its origin")
		assert.Equal(t, before["external_id"], id["external_id"])
		assert.Equal(t, before["credential_policy_id"], id["credential_policy_id"], "it keeps its credential policy")
		assert.Equal(t, map[string]any{"team": "payments", "adopted_via": "first_contact"}, id["labels"],
			"the inventory's labels, and the adoption marker; first contact did not register it")
		metadata := id["metadata"].(map[string]any)
		assert.Equal(t, "inventory-123", metadata["source_ref"])
		assert.NotContains(t, metadata, "first_contact")
		adoption := metadata["first_contact_adoption"].(map[string]any)
		assert.Equal(t, w.f.idp.K8sIssuer(), adoption["issuer"])
		assert.Equal(t, w.rowID, adoption["issuer_id"])
		assert.Equal(t, sub, adoption["subject_key"])
		assert.Equal(t, "client_credentials", adoption["grant_type"])
		assert.Equal(t, "admin@"+w.tn.account, adoption["mapping_updated_by"])
		assert.NotEmpty(t, adoption["mapping_updated_at"])

		bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
		require.Len(t, bindings, 1, "the inventory's binding, no second one")
		assert.Equal(t, inv.bindingID, bindings[0]["id"])
		assert.Equal(t, true, bindings[0]["enabled"])
		assert.Equal(t, false, bindings[0]["explicitly_disabled"])
		assert.Equal(t, fcActor, bindings[0]["updated_by"])
		assert.Empty(t, w.tn.firstContactIdentities(t), "nothing registered")

		listed := w.tn.labelled(t, fcAdoptedFilter)
		require.Len(t, listed, 1, "the adopted_via label lists it")
		assert.Equal(t, inv.id, listed[0]["id"])

		again := w.clientCredentials(t, sub, nil)
		require.Equal(t, http.StatusOK, again.StatusCode, "body=%s", again.RawBody)
		assert.Equal(t, claims["sub"], decodeJWTPayload(t, again.AccessToken)["sub"], "the same agent")

		t.Run("the audit trail names the standing mapping and who set it", func(t *testing.T) {
			rows := auditOf(t, inv.id)
			acts := activations(t, rows)
			require.Len(t, acts, 1, "one activation")
			assert.Equal(t, fcActor, acts[0].Caller)
			var after map[string]any
			require.NoError(t, json.Unmarshal(acts[0].NewData, &after))
			recorded := after["metadata"].(map[string]any)["first_contact_adoption"].(map[string]any)
			assert.Equal(t, w.rowID, recorded["issuer_id"])
			assert.Equal(t, "admin@"+w.tn.account, recorded["mapping_updated_by"])
			assert.Equal(t, fcOwner, after["owner_user_id"])

			enables := bindingEnables(t, rows)
			require.Len(t, enables, 1, "one binding enable")
			assert.Equal(t, fcActor, enables[0].Caller)

			// And the row's own trail says when that person set adopt.
			var mapped []fcAuditRow
			err := testDB.NewSelect().Table("identity_audit_logs").
				Column("caller_user_id", "table_name", "action", "old_data", "new_data").
				Where("table_name = 'external_issuers'").Where("new_data->>'id' = ?", w.rowID).
				Where("new_data->>'first_contact' = 'adopt'").Scan(context.Background(), &mapped)
			require.NoError(t, err)
			require.NotEmpty(t, mapped)
			assert.Equal(t, "admin@"+w.tn.account, mapped[0].Caller)
		})

		t.Run("an inventory sync keeps the markers, and cannot add them elsewhere", func(t *testing.T) {
			resp := post(t, adminPath("/identities/discovered"), map[string]any{
				"external_id": before["external_id"], "origin": fcInventoryOrigin, "name": "Renamed by the inventory",
				"labels":   map[string]any{"team": "risk"},
				"metadata": map[string]any{"source_ref": "inventory-456"},
			}, w.tn.mappedHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			got := decode(t, resp)["identity"].(map[string]any)
			assert.Equal(t, "Renamed by the inventory", got["name"])
			assert.Equal(t, map[string]any{"team": "risk", "adopted_via": "first_contact"}, got["labels"])
			metadata := got["metadata"].(map[string]any)
			assert.Equal(t, "inventory-456", metadata["source_ref"])
			assert.Equal(t, w.rowID, metadata["first_contact_adoption"].(map[string]any)["issuer_id"])

			resp = post(t, adminPath("/identities/discovered"), map[string]any{
				"external_id": uid("inv"), "origin": fcInventoryOrigin,
				"labels":   map[string]any{"adopted_via": "first_contact"},
				"metadata": map[string]any{"first_contact_adoption": map[string]any{"issuer_id": "forged"}},
			}, w.tn.mappedHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			forged := decode(t, resp)["identity"].(map[string]any)
			assert.NotContains(t, forged["labels"], "adopted_via")
			assert.NotContains(t, forged["metadata"], "first_contact_adoption")
			assert.Len(t, w.tn.labelled(t, fcAdoptedFilter), 1)
		})
	})

	t.Run("a discover row it registered is adopted once the row is switched to adopt", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		w.set(t, discoverSettings(w.tn))
		sub := newSA()
		requireRefused(t, w.clientCredentials(t, sub, nil), "invalid_grant")
		bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
		require.Len(t, bindings, 1)

		w.set(t, adoptSettings(w.tn))
		resp := w.clientCredentials(t, sub, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		id := w.tn.identity(t, bindings[0]["identity_id"].(string))
		assert.Equal(t, "active", id["status"])
		assert.Equal(t, map[string]any{"discovered_via": "first_contact", "adopted_via": "first_contact"}, id["labels"])
		metadata := id["metadata"].(map[string]any)
		assert.Equal(t, "discover", metadata["first_contact"].(map[string]any)["mode"], "how it first arrived is kept")
		assert.Equal(t, w.rowID, metadata["first_contact_adoption"].(map[string]any)["issuer_id"])
	})

	// Each guard keeps today's refusal and leaves the agent as it was.
	t.Run("guards", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{RatePerMinute: 100}, nil)
		w.set(t, adoptSettings(w.tn))

		t.Run("an explicitly disabled binding: a person's decision wins", func(t *testing.T) {
			sub := newSA()
			inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
			status, body := w.f.call(t, http.MethodPatch, "/external-issuers/"+w.rowID+"/bindings/"+inv.bindingID,
				map[string]any{"enabled": false}, w.tn.headers)
			require.Equal(t, http.StatusOK, status, "%v", body)
			require.Equal(t, true, body["explicitly_disabled"])

			resp := w.clientCredentials(t, sub, nil)
			requireRefused(t, resp, "invalid_grant")
			assert.Contains(t, resp.RawBody, "agent identity is discovered")
			requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, sub, inv, "discovered")
		})

		t.Run("an agent a person is adopting (pending)", func(t *testing.T) {
			sub := newSA()
			inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
			resp := post(t, adminPath("/identities/"+inv.id+"/adopt"), map[string]any{"owner_user_id": "someone"}, w.tn.mappedHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_ = resp.Body.Close()

			tr := w.clientCredentials(t, sub, nil)
			requireRefused(t, tr, "invalid_grant")
			assert.Contains(t, tr.RawBody, "agent identity is pending")
			requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, sub, inv, "pending")
			assert.Equal(t, "someone", w.tn.identity(t, inv.id)["owner_user_id"], "the person's owner stands")
		})

		t.Run("a dismissed agent", func(t *testing.T) {
			sub := newSA()
			inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
			resp := post(t, adminPath("/identities/"+inv.id+"/dismiss"), nil, w.tn.mappedHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_ = resp.Body.Close()

			tr := w.clientCredentials(t, sub, nil)
			requireRefused(t, tr, "invalid_grant")
			assert.Contains(t, tr.RawBody, "deactivated")
			requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, sub, inv, "deactivated")
		})

		t.Run("an active agent whose binding is disabled", func(t *testing.T) {
			sub := newSA()
			inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
			resp := doRequest(t, http.MethodPatch, adminPath("/identities/"+inv.id),
				map[string]any{"status": "active", "owner_user_id": "someone"}, w.tn.mappedHeaders)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_ = resp.Body.Close()

			tr := w.clientCredentials(t, sub, nil)
			requireRefused(t, tr, "invalid_grant")
			assert.Contains(t, tr.RawBody, "no enabled binding")
			id := w.tn.identity(t, inv.id)
			assert.Equal(t, "someone", id["owner_user_id"])
			assert.NotContains(t, id["labels"], "adopted_via")
			assert.Equal(t, false, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)[0]["enabled"])
		})

		t.Run("an agent in another project", func(t *testing.T) {
			sub := newSA()
			inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.headers, nil)
			tr := w.clientCredentials(t, sub, nil)
			requireRefused(t, tr, "invalid_grant")
			assert.Contains(t, tr.RawBody, "agent identity is discovered")
			requireUntouched(t, w.f, w.tn, w.tn.headers, w.rowID, sub, inv, "discovered")
		})

		t.Run("an approval channel", func(t *testing.T) {
			sub := newSA()
			inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
			// A trusted write makes the discovered agent an approval channel: its
			// credential policy lists ciba:approve.
			trusted := maps.Clone(w.tn.mappedHeaders)
			trusted[testApprovalChannelWriteHeader] = "1"
			policyID := createRichCredentialPolicy(t, map[string]any{
				"name": uid("approver"), "max_ttl_seconds": 3600,
				"allowed_grant_types": []string{"client_credentials"}, "allowed_scopes": []string{"ciba:approve"},
			}, trusted)
			resp := doRequest(t, http.MethodPatch, adminPath("/identities/"+inv.id), map[string]any{"credential_policy_id": policyID}, trusted)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_ = resp.Body.Close()

			tr := w.clientCredentials(t, sub, nil)
			requireRefused(t, tr, "invalid_grant")
			assert.Contains(t, tr.RawBody, "agent identity is discovered")
			requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, sub, inv, "discovered")
		})

		t.Run("two bindings for one subject leave the choice to a person", func(t *testing.T) {
			sub := newSA()
			first := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
			second := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
			tr := w.clientCredentials(t, sub, nil)
			requireRefused(t, tr, "invalid_grant")
			assert.Contains(t, tr.RawBody, "agent identity is discovered")
			requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, sub, first, "discovered")
			requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, sub, second, "discovered")
		})
	})

	t.Run("discover and off leave an inventoried agent in the queue", func(t *testing.T) {
		for _, mode := range []string{"off", "discover"} {
			w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
			if mode == "discover" {
				w.set(t, discoverSettings(w.tn))
			}
			sub := newSA()
			inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
			tr := w.clientCredentials(t, sub, nil)
			requireRefused(t, tr, "invalid_grant")
			assert.Contains(t, tr.RawBody, "agent identity is discovered")
			requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, sub, inv, "discovered")
			assert.Empty(t, w.tn.firstContactIdentities(t), "nothing registered")
			assert.Len(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub), 1)
		}
	})

	t.Run("a disabled row adopts nothing", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		w.set(t, adoptSettings(w.tn))
		sub := newSA()
		inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
		w.set(t, map[string]any{"enabled": false})
		requireRefused(t, w.clientCredentials(t, sub, nil), "invalid_client")
		requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, sub, inv, "discovered")
	})

	t.Run("the per-row rate covers standing adoptions", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{RatePerMinute: 1}, nil)
		w.set(t, adoptSettings(w.tn))
		firstSub, secondSub := newSA(), newSA()
		inventoryAgent(t, w.f, w.tn, w.rowID, firstSub, w.tn.mappedHeaders, nil)
		second := inventoryAgent(t, w.f, w.tn, w.rowID, secondSub, w.tn.mappedHeaders, nil)

		first := w.clientCredentials(t, firstSub, nil)
		require.Equal(t, http.StatusOK, first.StatusCode, "body=%s", first.RawBody)
		tr := w.clientCredentials(t, secondSub, nil)
		requireRefused(t, tr, "invalid_grant")
		assert.Contains(t, tr.RawBody, "agent identity is discovered")
		requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, secondSub, second, "discovered")

		unbound := newSA()
		requireRefused(t, w.clientCredentials(t, unbound, nil), "invalid_grant")
		assert.Empty(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, unbound), "one bound for registrations and adoptions")
	})

	t.Run("the account's cap on unadopted agents does not apply", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{MaxDiscoveredPerAccount: 1}, nil)
		w.set(t, discoverSettings(w.tn))
		requireRefused(t, w.clientCredentials(t, newSA(), nil), "invalid_grant")
		require.Len(t, w.tn.firstContactIdentities(t), 1, "the cap is reached")

		w.set(t, adoptSettings(w.tn))
		sub := newSA()
		inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
		resp := w.clientCredentials(t, sub, nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	})

	// Concurrent first calls for one inventoried agent activate it once:
	// every request mints, and the audit trail holds one activation and one
	// binding enable.
	t.Run("concurrent first calls adopt once", func(t *testing.T) {
		w := newFCWorkload(t, zeroid.FirstContactConfig{RatePerMinute: 100}, nil)
		w.set(t, adoptSettings(w.tn))
		sub := newSA()
		inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
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
			assert.Equal(t, http.StatusOK, statuses[i], "request %d: %s", i, bodies[i])
		}
		assert.Equal(t, "active", w.tn.identity(t, inv.id)["status"])
		bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
		require.Len(t, bindings, 1)
		assert.Equal(t, true, bindings[0]["enabled"])
		rows := auditOf(t, inv.id)
		assert.Len(t, activations(t, rows), 1, "one activation")
		assert.Len(t, bindingEnables(t, rows), 1, "one binding enable")
		assert.Empty(t, w.tn.firstContactIdentities(t), "nothing registered")
	})
}

func TestFirstContact_StandingAdoptionIDJAG(t *testing.T) {
	p := newFCIDJAG(t, nil)
	status, body := p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, adoptSettings(p.tn), p.tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)

	t.Run("adopt: the agent is adopted on its first ID-JAG, with the person resolved first", func(t *testing.T) {
		agent := uid("0oa-agent")
		inv := inventoryAgent(t, p.f, p.tn, p.rowID, agent, p.tn.mappedHeaders, nil)
		before := p.tn.identity(t, inv.id)

		resp := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		claims := decodeIssuedTokenClaims(t, resp.AccessToken)
		assert.Equal(t, "user_hf_alice", claims["sub"])
		assert.Equal(t, p.tn.account, claims["account_id"])
		assert.Equal(t, p.tn.mapped, claims["project_id"])
		assert.Equal(t, []string{before["wimse_uri"].(string)}, actChain(t, claims), "the adopted agent is the current actor")
		assert.Equal(t, inv.id, p.f.lastPerson.AgentIdentityID, "the resolver was told which agent")

		id := p.tn.identity(t, inv.id)
		assert.Equal(t, "active", id["status"])
		assert.Equal(t, fcOwner, id["owner_user_id"])
		assert.Equal(t, "verified_third_party", id["trust_level"])
		adoption := id["metadata"].(map[string]any)["first_contact_adoption"].(map[string]any)
		assert.Equal(t, "id_jag", adoption["grant_type"])
		assert.Equal(t, agent, adoption["subject_key"])
		assert.NotContains(t, fmt.Sprint(id["metadata"]), p.aliceSub, "the person is not recorded on the agent")
		bindings := bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent)
		require.Len(t, bindings, 1)
		assert.Equal(t, true, bindings[0]["enabled"])

		again := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
		require.Equal(t, http.StatusOK, again.StatusCode, "body=%s", again.RawBody)
	})

	t.Run("a person the resolver refuses leaves the agent discovered, and the ID-JAG redeemable", func(t *testing.T) {
		agent, stranger := uid("0oa-agent"), uid("00u-stranger")
		inv := inventoryAgent(t, p.f, p.tn, p.rowID, agent, p.tn.mappedHeaders, nil)
		assertion := p.idJAG(t, p.clientID, agent, stranger)
		resp := p.redeem(t, assertion, p.keyed)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "not a member")
		requireUntouched(t, p.f, p.tn, p.tn.mappedHeaders, p.rowID, agent, inv, "discovered")

		p.f.member(p.f.idp.OktaIssuer(), stranger, "user_hf_"+stranger)
		resp = p.redeem(t, assertion, p.keyed)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		assert.Equal(t, "active", p.tn.identity(t, inv.id)["status"])
	})

	t.Run("an application_id naming another agent adopts nothing", func(t *testing.T) {
		agent := uid("0oa-agent")
		inv := inventoryAgent(t, p.f, p.tn, p.rowID, agent, p.tn.mappedHeaders, nil)
		other := p.tn.agent(t)
		assertion := p.idJAG(t, p.clientID, agent, p.aliceSub)
		resp := postFederation(t, p.f.http.URL, map[string]any{
			"grant_type": fcJWTBearer, "assertion": assertion, "client_id": p.keyed.ClientID,
			"client_assertion": rpAssertion(t, p.keyed), "client_assertion_type": clientAssertionType,
			"application_id": other.id,
		})
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "application_id")
		requireUntouched(t, p.f, p.tn, p.tn.mappedHeaders, p.rowID, agent, inv, "discovered")

		ok := p.redeem(t, assertion, p.keyed)
		require.Equal(t, http.StatusOK, ok.StatusCode, "the ID-JAG was not spent: %s", ok.RawBody)
	})

	t.Run("a registered client adopts nothing", func(t *testing.T) {
		clientID := uid("registered-client")
		key := keyClient(t, p.tn.tiTenant, clientID, "")
		client := oauthClientResp{ClientID: clientID, Key: key}
		agent := uid("0oa-agent")
		inv := inventoryAgent(t, p.f, p.tn, p.rowID, agent, p.tn.mappedHeaders, nil)
		resp := p.redeem(t, p.idJAG(t, clientID, agent, p.aliceSub), client)
		requireRefused(t, resp, "invalid_grant")
		requireUntouched(t, p.f, p.tn, p.tn.mappedHeaders, p.rowID, agent, inv, "discovered")
	})

	t.Run("an explicitly disabled binding is refused before the ID-JAG is spent", func(t *testing.T) {
		agent := uid("0oa-agent")
		inv := inventoryAgent(t, p.f, p.tn, p.rowID, agent, p.tn.mappedHeaders, nil)
		status, body := p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID+"/bindings/"+inv.bindingID,
			map[string]any{"enabled": false}, p.tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assertion := p.idJAG(t, p.clientID, agent, p.aliceSub)
		resp := p.redeem(t, assertion, p.keyed)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "agent identity is discovered")
		requireUntouched(t, p.f, p.tn, p.tn.mappedHeaders, p.rowID, agent, inv, "discovered")
		n, err := testDB.NewSelect().Table("id_jag_jti").Where("jti = ?", decodeJWTPayload(t, assertion)["jti"]).Count(context.Background())
		require.NoError(t, err)
		assert.Zero(t, n, "refused as without first contact: the jti is not spent")
	})
}
