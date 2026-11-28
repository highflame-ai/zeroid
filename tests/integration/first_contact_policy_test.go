package integration_test

// An adopt row's first_contact_credential_policy_id (docs/external-issuers.md,
// "First contact"): the credential policy the row assigns, as the identity's
// own, to every agent it adopts, whether first contact registers it or a
// standing adoption activates it. Without one the project's default policy
// governs the agents, and a default that sets no scopes refuses the first
// call of every workload agent the row adopts.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io/fs"
	"maps"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	zeroid "github.com/highflame-ai/zeroid"
)

// withProject is tn with first contact mapped to another project of its
// account.
func (tn fcTenant) withProject(project string) fcTenant {
	tn.mapped = project
	tn.mappedHeaders = map[string]string{"X-Account-ID": tn.account, "X-Project-ID": project, "X-User-ID": "admin@" + tn.account}
	return tn
}

// adoptPolicy creates, in the mapped project, a credential policy an adopted
// agent can mint under on both first-contact grants, and returns its id.
func (tn fcTenant) adoptPolicy(t *testing.T, extra map[string]any) string {
	t.Helper()
	body := map[string]any{
		"name":                uid("fc-adopt-policy"),
		"allowed_grant_types": []string{"client_credentials", "jwt_bearer", "token_exchange"},
		"allowed_scopes":      []string{"tools:read"},
		"user_grant_scopes":   []string{"tools:read"},
		"max_ttl_seconds":     3600,
	}
	maps.Copy(body, extra)
	return createRichCredentialPolicy(t, body, tn.mappedHeaders)
}

func adoptWithPolicy(tn fcTenant, policyID string) map[string]any {
	s := adoptSettings(tn)
	s["first_contact_credential_policy_id"] = policyID
	return s
}

// deletePolicy sends DELETE /credential-policies/{id} and returns the status
// and the problem body.
func deletePolicy(t *testing.T, policyID string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	resp := doRequest(t, http.MethodDelete, adminPath("/credential-policies/"+policyID), nil, headers)
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func policyExists(t *testing.T, policyID string) bool {
	t.Helper()
	n, err := testDB.NewSelect().Table("credential_policies").Where("id = ?", policyID).Count(context.Background())
	require.NoError(t, err)
	return n == 1
}

func TestFirstContactPolicy_IssuerAPI(t *testing.T) {
	f := newDBFederation(t)
	tn := newFCTenant(t)
	policy := tn.adoptPolicy(t, nil)
	create := func(t *testing.T, extra map[string]any) (int, map[string]any) {
		t.Helper()
		body := map[string]any{"kind": "workload", "issuer": f.idp.K8sIssuer(), "audiences": []string{federationIssuer}}
		maps.Copy(body, extra)
		return f.call(t, http.MethodPost, "/external-issuers", body, tn.headers)
	}
	refused := func(t *testing.T, status int, body map[string]any, msgAndArgs ...any) {
		t.Helper()
		assert.Equal(t, http.StatusBadRequest, status, msgAndArgs...)
		assert.Equal(t, "first_contact_policy_invalid", body["code"], msgAndArgs...)
	}

	t.Run("create refuses a policy that cannot be assigned", func(t *testing.T) {
		trusted := maps.Clone(tn.mappedHeaders)
		trusted[testApprovalChannelWriteHeader] = "1"
		approver := createRichCredentialPolicy(t, map[string]any{
			"name": uid("approver"), "max_ttl_seconds": 3600,
			"allowed_grant_types": []string{"client_credentials"}, "allowed_scopes": []string{"ciba:approve"},
		}, trusted)
		otherProject := createRichCredentialPolicy(t, map[string]any{
			"name": uid("elsewhere"), "max_ttl_seconds": 3600, "allowed_grant_types": []string{"client_credentials"},
		}, tn.headers)
		expired := tn.adoptPolicy(t, map[string]any{"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
		inactive := tn.adoptPolicy(t, nil)
		patchCredentialPolicy(t, inactive, map[string]any{"is_active": false}, tn.mappedHeaders)

		for name, extra := range map[string]map[string]any{
			"on a discover row":               {"first_contact": "discover", "first_contact_project_id": tn.mapped, "first_contact_credential_policy_id": policy},
			"on a row with first contact off": {"first_contact_credential_policy_id": policy},
			"an unknown policy":               adoptWithPolicy(tn, "6f1c2b9e-0000-4000-8000-00000000dead"),
			"not a policy id":                 adoptWithPolicy(tn, "workloads"),
			"a policy of another project":     adoptWithPolicy(tn, otherProject),
			"an inactive policy":              adoptWithPolicy(tn, inactive),
			"an expired policy":               adoptWithPolicy(tn, expired),
			"a policy listing ciba:approve":   adoptWithPolicy(tn, approver),
		} {
			status, body := create(t, extra)
			refused(t, status, body, "%s: %v", name, body)
		}
	})

	var rowID string
	t.Run("create stores the policy, and it reads back", func(t *testing.T) {
		status, body := create(t, adoptWithPolicy(tn, policy))
		require.Equal(t, http.StatusCreated, status, "%v", body)
		rowID = body["id"].(string)
		assert.Equal(t, policy, body["first_contact_credential_policy_id"])
		assert.Equal(t, "admin@"+tn.account, body["first_contact_updated_by"])
		status, body = f.call(t, http.MethodGet, "/external-issuers/"+rowID, nil, tn.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, policy, body["first_contact_credential_policy_id"])
	})

	t.Run("a row that names none returns it empty", func(t *testing.T) {
		other := newFCTenant(t)
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": f.idp.OktaIssuer(), "claim_mapping": map[string]string{"user_id": "sub"},
		}, other.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		got, present := body["first_contact_credential_policy_id"]
		assert.True(t, present, "always returned")
		assert.Equal(t, "", got)
	})

	t.Run("the issuer's audit documents carry it", func(t *testing.T) {
		var rows []fcAuditRow
		err := testDB.NewSelect().Table("identity_audit_logs").
			Column("caller_user_id", "table_name", "action", "old_data", "new_data").
			Where("table_name = 'external_issuers'").Where("new_data->>'id' = ?", rowID).
			Where("new_data->>'first_contact_credential_policy_id' = ?", policy).Scan(context.Background(), &rows)
		require.NoError(t, err)
		require.NotEmpty(t, rows)
		assert.Equal(t, "admin@"+tn.account, rows[0].Caller)
	})

	t.Run("changing the policy names who changed it", func(t *testing.T) {
		second := tn.adoptPolicy(t, nil)
		changer := maps.Clone(tn.headers)
		changer["X-User-ID"] = "changer@" + tn.account
		status, body := f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact_credential_policy_id": second}, changer)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, second, body["first_contact_credential_policy_id"])
		assert.Equal(t, "changer@"+tn.account, body["first_contact_updated_by"])

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact_credential_policy_id": policy}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, "admin@"+tn.account, body["first_contact_updated_by"])
	})

	t.Run("a project change needs a policy of the new project", func(t *testing.T) {
		moved := tn.withProject(uid("fc-proj"))
		status, body := f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact_project_id": moved.mapped}, tn.headers)
		refused(t, status, body, "%v", body)
		assert.Contains(t, body["detail"], moved.mapped)
		status, body = f.call(t, http.MethodGet, "/external-issuers/"+rowID, nil, tn.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, tn.mapped, body["first_contact_project_id"], "nothing changed")

		movedPolicy := moved.adoptPolicy(t, nil)
		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact_project_id": moved.mapped, "first_contact_credential_policy_id": movedPolicy}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, moved.mapped, body["first_contact_project_id"])
		assert.Equal(t, movedPolicy, body["first_contact_credential_policy_id"])

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact_project_id": tn.mapped, "first_contact_credential_policy_id": policy}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
	})

	t.Run("discover and off clear it, and refuse one", func(t *testing.T) {
		status, body := f.call(t, http.MethodPatch, "/external-issuers/"+rowID, map[string]any{"first_contact": "discover"}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, "", body["first_contact_credential_policy_id"], "discover clears it")
		assert.Equal(t, tn.mapped, body["first_contact_project_id"], "the rest of the mapping stays")

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact_credential_policy_id": policy}, tn.headers)
		refused(t, status, body, "a policy on a discover row: %v", body)

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID, adoptWithPolicy(tn, policy), tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, policy, body["first_contact_credential_policy_id"])

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"first_contact": "off", "first_contact_credential_policy_id": policy}, tn.headers)
		refused(t, status, body, "off naming a policy: %v", body)

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID, map[string]any{"first_contact": "off"}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, "", body["first_contact_credential_policy_id"], "off clears it")
	})

	t.Run("a stored policy that became unusable does not block a rename or a disable", func(t *testing.T) {
		later := tn.adoptPolicy(t, nil)
		status, body := f.call(t, http.MethodPatch, "/external-issuers/"+rowID, adoptWithPolicy(tn, later), tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		patchCredentialPolicy(t, later, map[string]any{"is_active": false}, tn.mappedHeaders)

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+rowID,
			map[string]any{"display_name": "Renamed", "enabled": false}, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, later, body["first_contact_credential_policy_id"])
	})
}

// A credential policy an adopt row names cannot be deleted while the row
// names it, as a policy a service key holds cannot.
func TestFirstContactPolicy_DeleteGuard(t *testing.T) {
	w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
	policy := w.tn.adoptPolicy(t, nil)
	w.set(t, adoptWithPolicy(w.tn, policy))

	status, body := deletePolicy(t, policy, w.tn.mappedHeaders)
	assert.Equal(t, http.StatusConflict, status, "%v", body)
	assert.Contains(t, body["detail"], "first-contact mapping")
	assert.True(t, policyExists(t, policy), "a refused delete leaves the policy")

	t.Run("a disabled row still holds it", func(t *testing.T) {
		w.set(t, map[string]any{"enabled": false})
		status, _ := deletePolicy(t, policy, w.tn.mappedHeaders)
		assert.Equal(t, http.StatusConflict, status)
		w.set(t, map[string]any{"enabled": true})
	})

	t.Run("another tenant's delete is a 404, as before", func(t *testing.T) {
		status, _ := deletePolicy(t, policy, w.tn.headers)
		assert.Equal(t, http.StatusNotFound, status)
		assert.True(t, policyExists(t, policy))
	})

	t.Run("once the row names it no more, it deletes", func(t *testing.T) {
		w.set(t, map[string]any{"first_contact_credential_policy_id": ""})
		status, body := deletePolicy(t, policy, w.tn.mappedHeaders)
		assert.Equal(t, http.StatusNoContent, status, "%v", body)
		assert.False(t, policyExists(t, policy))
	})

	t.Run("a deleted row holds nothing", func(t *testing.T) {
		other := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
		held := other.tn.adoptPolicy(t, nil)
		other.set(t, adoptWithPolicy(other.tn, held))
		status, _ := other.f.call(t, http.MethodDelete, "/external-issuers/"+other.rowID, nil, other.tn.headers)
		require.Equal(t, http.StatusNoContent, status)
		status, body := deletePolicy(t, held, other.tn.mappedHeaders)
		assert.Equal(t, http.StatusNoContent, status, "%v", body)
	})
}

func TestFirstContactPolicy_Workload(t *testing.T) {
	// The mapped project has no default policy yet: the one ZeroID creates
	// sets no scopes, so it lets a workload agent mint nothing.
	w := newFCWorkload(t, zeroid.FirstContactConfig{}, nil)
	w.tn = w.tn.withProject(uid("fc-bare"))

	var beforePolicy string
	t.Run("without a row policy the project's scopeless default refuses the first call", func(t *testing.T) {
		w.set(t, adoptSettings(w.tn))
		sub := newSA()
		resp := w.clientCredentials(t, sub, nil)
		requireRefused(t, resp, "invalid_scope")
		assert.Contains(t, resp.RawBody, "no scope limit")
		bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
		require.Len(t, bindings, 1, "registered and adopted, under the project's default")
		beforePolicy = bindings[0]["identity_id"].(string)
	})

	policy := w.tn.adoptPolicy(t, nil)
	w.set(t, map[string]any{"first_contact_credential_policy_id": policy})

	t.Run("with the row's policy the first call mints", func(t *testing.T) {
		sub := newSA()
		resp := w.clientCredentials(t, sub, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		claims := decodeJWTPayload(t, resp.AccessToken)
		assert.Equal(t, w.tn.mapped, claims["project_id"])
		assert.Equal(t, "tools:read", claims["scope"])

		bindings := bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub)
		require.Len(t, bindings, 1)
		id := w.tn.identity(t, bindings[0]["identity_id"].(string))
		assert.Equal(t, policy, id["credential_policy_id"], "the row's policy is the identity's own")
		assert.Equal(t, "active", id["status"])
		adoption := id["metadata"].(map[string]any)["first_contact_adoption"].(map[string]any)
		assert.Equal(t, policy, adoption["credential_policy_id"], "the adoption record names the policy")
	})

	t.Run("an agent adopted before the policy was set keeps the policy it was adopted with", func(t *testing.T) {
		id := w.tn.identity(t, beforePolicy)
		assert.NotEqual(t, policy, id["credential_policy_id"])
	})

	t.Run("standing adoption: the row's policy replaces the agent's own", func(t *testing.T) {
		sub := newSA()
		inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
		before := w.tn.identity(t, inv.id)
		require.NotEmpty(t, before["credential_policy_id"], "an inventoried agent carries its project's default from birth")
		require.NotEqual(t, policy, before["credential_policy_id"])

		resp := w.clientCredentials(t, sub, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		id := w.tn.identity(t, inv.id)
		assert.Equal(t, "active", id["status"])
		assert.Equal(t, policy, id["credential_policy_id"])
		adoption := id["metadata"].(map[string]any)["first_contact_adoption"].(map[string]any)
		assert.Equal(t, policy, adoption["credential_policy_id"])

		acts := activations(t, auditOf(t, inv.id))
		require.Len(t, acts, 1)
		var after map[string]any
		require.NoError(t, json.Unmarshal(acts[0].NewData, &after))
		assert.Equal(t, policy, after["credential_policy_id"], "the activation's audit row carries the policy")
		assert.Equal(t, fcActor, acts[0].Caller)
	})
}

// A policy that is missing or cannot be assigned at adoption time fails
// closed: nothing is registered or adopted, and the call is refused as if
// first contact were off.
func TestFirstContactPolicy_FailsClosed(t *testing.T) {
	w := newFCWorkload(t, zeroid.FirstContactConfig{RatePerMinute: 100}, nil)
	policy := w.tn.adoptPolicy(t, nil)
	w.set(t, adoptWithPolicy(w.tn, policy))
	ctx := context.Background()

	refusedUnbound := func(t *testing.T) {
		t.Helper()
		sub := newSA()
		resp := w.clientCredentials(t, sub, nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding", "the refusal of first contact off")
		assert.Empty(t, bindingsFor(t, w.f, w.tn.tiTenant, w.rowID, sub), "nothing bound")
	}
	refusedInventoried := func(t *testing.T) {
		t.Helper()
		sub := newSA()
		inv := inventoryAgent(t, w.f, w.tn, w.rowID, sub, w.tn.mappedHeaders, nil)
		before := w.tn.identity(t, inv.id)
		resp := w.clientCredentials(t, sub, nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "agent identity is discovered")
		requireUntouched(t, w.f, w.tn, w.tn.mappedHeaders, w.rowID, sub, inv, "discovered")
		assert.Equal(t, before["credential_policy_id"], w.tn.identity(t, inv.id)["credential_policy_id"])
	}

	t.Run("inactive", func(t *testing.T) {
		registered := len(w.tn.firstContactIdentities(t))
		patchCredentialPolicy(t, policy, map[string]any{"is_active": false}, w.tn.mappedHeaders)
		refusedUnbound(t)
		refusedInventoried(t)
		assert.Len(t, w.tn.firstContactIdentities(t), registered, "nothing registered")

		patchCredentialPolicy(t, policy, map[string]any{"is_active": true}, w.tn.mappedHeaders)
		resp := w.clientCredentials(t, newSA(), nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "active again, it adopts: %s", resp.RawBody)
	})

	t.Run("expired", func(t *testing.T) {
		_, err := testDB.NewUpdate().Table("credential_policies").Set("expires_at = now() - interval '1 minute'").
			Where("id = ?", policy).Exec(ctx)
		require.NoError(t, err)
		refusedUnbound(t)
		refusedInventoried(t)
		_, err = testDB.NewUpdate().Table("credential_policies").Set("expires_at = NULL").Where("id = ?", policy).Exec(ctx)
		require.NoError(t, err)
	})

	t.Run("missing", func(t *testing.T) {
		// The API refuses the delete while the row names the policy; this
		// stands for one removed behind its back.
		gone := w.tn.adoptPolicy(t, nil)
		w.set(t, map[string]any{"first_contact_credential_policy_id": gone})
		_, err := testDB.NewDelete().Table("credential_policies").Where("id = ?", gone).Exec(ctx)
		require.NoError(t, err)
		refusedUnbound(t)
		refusedInventoried(t)
	})
}

// On the ID-JAG path the policy is checked before the person is resolved and
// the jti is spent, so a refused ID-JAG stays redeemable.
func TestFirstContactPolicy_IDJAG(t *testing.T) {
	p := newFCIDJAG(t, nil)
	policy := p.tn.adoptPolicy(t, nil)
	status, body := p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, adoptWithPolicy(p.tn, policy), p.tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)
	jtiSpent := func(t *testing.T, assertion string) bool {
		t.Helper()
		n, err := testDB.NewSelect().Table("id_jag_jti").Where("jti = ?", decodeJWTPayload(t, assertion)["jti"]).Count(context.Background())
		require.NoError(t, err)
		return n == 1
	}

	t.Run("a registered agent gets the row's policy", func(t *testing.T) {
		agent := uid("0oa-agent")
		resp := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		bindings := bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent)
		require.Len(t, bindings, 1)
		id := p.tn.identity(t, bindings[0]["identity_id"].(string))
		assert.Equal(t, policy, id["credential_policy_id"])
	})

	t.Run("an adopted inventoried agent gets the row's policy", func(t *testing.T) {
		agent := uid("0oa-agent")
		inv := inventoryAgent(t, p.f, p.tn, p.rowID, agent, p.tn.mappedHeaders, nil)
		resp := p.redeem(t, p.idJAG(t, p.clientID, agent, p.aliceSub), p.keyed)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		assert.Equal(t, policy, p.tn.identity(t, inv.id)["credential_policy_id"])
	})

	t.Run("an unusable policy refuses before the jti is spent", func(t *testing.T) {
		patchCredentialPolicy(t, policy, map[string]any{"is_active": false}, p.tn.mappedHeaders)
		agent := uid("0oa-agent")
		assertion := p.idJAG(t, p.clientID, agent, p.aliceSub)
		resp := p.redeem(t, assertion, p.keyed)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
		assert.Empty(t, bindingsFor(t, p.f, p.tn.tiTenant, p.rowID, agent))
		assert.False(t, jtiSpent(t, assertion), "refused as without first contact: the jti is not spent")

		inventoried := uid("0oa-agent")
		inv := inventoryAgent(t, p.f, p.tn, p.rowID, inventoried, p.tn.mappedHeaders, nil)
		standing := p.idJAG(t, p.clientID, inventoried, p.aliceSub)
		resp = p.redeem(t, standing, p.keyed)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "agent identity is discovered")
		requireUntouched(t, p.f, p.tn, p.tn.mappedHeaders, p.rowID, inventoried, inv, "discovered")
		assert.False(t, jtiSpent(t, standing))

		patchCredentialPolicy(t, policy, map[string]any{"is_active": true}, p.tn.mappedHeaders)
		resp = p.redeem(t, assertion, p.keyed)
		require.Equal(t, http.StatusOK, resp.StatusCode, "the same ID-JAG redeems once the policy is usable: %s", resp.RawBody)
		resp = p.redeem(t, standing, p.keyed)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		assert.Equal(t, policy, p.tn.identity(t, inv.id)["credential_policy_id"])
	})
}

// TestFirstContactPolicyMigration applies migration 075's down and up
// scripts inside a transaction that is rolled back, so the shared schema is
// left untouched.
func TestFirstContactPolicyMigration(t *testing.T) {
	ctx := context.Background()
	const name = "075_external_issuer_first_contact_policy"
	up, err := fs.ReadFile(zeroid.MigrationFiles(), name+".up.sql")
	require.NoError(t, err)
	down, err := fs.ReadFile(zeroid.MigrationFiles(), name+".down.sql")
	require.NoError(t, err)

	hasColumn := func(tx bun.Tx) bool {
		var n int
		require.NoError(t, tx.QueryRowContext(ctx,
			`SELECT count(*) FROM information_schema.columns
			 WHERE table_name = 'external_issuers' AND column_name = 'first_contact_credential_policy_id'`).Scan(&n))
		return n == 1
	}
	checkDef := func(tx bun.Tx) string {
		var def string
		require.NoError(t, tx.QueryRowContext(ctx,
			`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'external_issuers_first_contact_check'`).Scan(&def))
		return def
	}

	tx, err := testDB.BeginTx(ctx, &sql.TxOptions{})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	require.True(t, hasColumn(tx), "migration must be applied by the suite")
	require.Contains(t, checkDef(tx), "first_contact_credential_policy_id")
	_, err = tx.ExecContext(ctx, string(down))
	require.NoError(t, err)
	require.False(t, hasColumn(tx), "down must drop the column")
	def := checkDef(tx)
	assert.Contains(t, def, "first_contact_owner_user_id", "down keeps the first-contact check")
	assert.NotContains(t, def, "first_contact_credential_policy_id")
	_, err = tx.ExecContext(ctx, string(up))
	require.NoError(t, err)
	require.True(t, hasColumn(tx), "up must add the column")
	require.Contains(t, checkDef(tx), "first_contact_credential_policy_id")
}
