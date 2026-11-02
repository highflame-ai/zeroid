package integration_test

// Workload issuer proof of control (ADR 0042 open question 8): the deployer
// writes a workload row disabled, ZeroID verifies a challenge token under it
// (verify-workload-token), and the deployer enables exactly the row it
// checked (if_updated_at). Against the real database and HTTP routes.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/internal/mockidp"
)

const workloadChallenge = "highflame-issuer-verification:itest-0123456789abcdef"

func TestWorkloadIssuerProof(t *testing.T) {
	w := newWorkloadFed(t)
	path := "/external-issuers/" + w.rowID

	status, row := w.f.call(t, http.MethodPatch, path, map[string]any{"enabled": false}, w.tn.headers)
	require.Equal(t, http.StatusOK, status, "disable: %v", row)

	t.Run("a disabled row mints nothing", func(t *testing.T) {
		requireRefused(t, w.clientCredentials(t, w.assertion(t, nil), nil), "invalid_client")
	})

	verify := func(t *testing.T, token, audience string) (int, map[string]any) {
		t.Helper()
		return w.f.call(t, http.MethodPost, path+"/verify-workload-token",
			map[string]any{"token": token, "audience": audience}, w.tn.headers)
	}

	t.Run("a token for the challenge verifies under the disabled row", func(t *testing.T) {
		status, body := verify(t, w.assertion(t, map[string]any{"aud": workloadChallenge}), workloadChallenge)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, w.rowID, body["issuer_id"])
		assert.Equal(t, w.sub, body["subject"])
	})

	t.Run("a P2 assertion is no proof", func(t *testing.T) {
		status, body := verify(t, w.assertion(t, nil), workloadChallenge)
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		assert.Equal(t, "audience_mismatch", body["code"])
		status, body = verify(t, w.assertion(t, nil), federationIssuer)
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		assert.Equal(t, "audience_not_a_challenge", body["code"])
	})

	t.Run("an enable conditioned on a stale read is refused", func(t *testing.T) {
		_, before := w.f.call(t, http.MethodGet, path, nil, w.tn.headers)
		checked := before["updated_at"]
		require.NotEmpty(t, checked)

		status, body := w.f.call(t, http.MethodPatch, path,
			map[string]any{"claim_constraints": map[string][]string{"sub": {w.sub}}}, w.tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)

		status, body = w.f.call(t, http.MethodPatch, path,
			map[string]any{"enabled": true, "if_updated_at": checked}, w.tn.headers)
		assert.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "issuer_changed", body["code"])

		_, after := w.f.call(t, http.MethodGet, path, nil, w.tn.headers)
		assert.Equal(t, false, after["enabled"], "the row stays off")
	})

	t.Run("an enable conditioned on the current read succeeds and the row mints", func(t *testing.T) {
		_, current := w.f.call(t, http.MethodGet, path, nil, w.tn.headers)
		status, body := w.f.call(t, http.MethodPatch, path,
			map[string]any{"enabled": true, "if_updated_at": current["updated_at"]}, w.tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)

		resp := w.clientCredentials(t, w.assertion(t, nil), nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	})
}

// A shared issuer's row may pin several values, and a token carries one: a
// row pinning the account's own value and another customer's is never
// proven.
func TestWorkloadIssuerProof_SharedIssuerPinsOneValue(t *testing.T) {
	f := newDBFederation(t)
	tn := newTITenant(t)
	iss := f.idp.EntraIssuer(sharedTenant)

	create := func(t *testing.T, hd []string) string {
		t.Helper()
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "workload", "issuer": iss, "audiences": []string{federationIssuer},
			"claim_constraints": map[string][]string{"hd": hd}, "enabled": false,
		}, tn.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		t.Cleanup(func() { _, _ = f.call(t, http.MethodDelete, "/external-issuers/"+body["id"].(string), nil, tn.headers) })
		return body["id"].(string)
	}
	token := func(t *testing.T, hd string) string {
		t.Helper()
		tok, _, err := f.idp.Mint(mockidp.MintRequest{
			Profile: mockidp.ProfileEntraAppOnly, Tenant: sharedTenant, TTLSeconds: 300,
			Claims: map[string]any{"aud": workloadChallenge, "hd": hd},
		})
		require.NoError(t, err)
		return tok
	}

	t.Run("two pinned values", func(t *testing.T) {
		id := create(t, []string{"attacker.example", "victim.example"})
		status, body := f.call(t, http.MethodPost, "/external-issuers/"+id+"/verify-workload-token",
			map[string]any{"token": token(t, "attacker.example"), "audience": workloadChallenge}, tn.headers)
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		assert.Equal(t, "pin_not_single", body["code"])
	})

	t.Run("one pinned value, and a token outside it", func(t *testing.T) {
		id := create(t, []string{"acme.example"})
		path := "/external-issuers/" + id + "/verify-workload-token"
		status, body := f.call(t, http.MethodPost, path,
			map[string]any{"token": token(t, "acme.example"), "audience": workloadChallenge}, tn.headers)
		assert.Equal(t, http.StatusOK, status, "%v", body)
		status, body = f.call(t, http.MethodPost, path,
			map[string]any{"token": token(t, "victim.example"), "audience": workloadChallenge}, tn.headers)
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		assert.Equal(t, "constraint_mismatch", body["code"])
	})
}
