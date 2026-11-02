package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Setting sub_type approval_channel, or putting ciba:approve into an
// identity's allowed_scopes, a credential policy or an API key, requires a
// request marked with zeroid.WithTrustedApprovalChannelWrite. The check runs
// on the decoded values, so it holds however the request body was spelled.

func channelWriteHeaders() map[string]string {
	h := adminHeaders()
	h[testApprovalChannelWriteHeader] = "1"
	return h
}

func requireForbidden(t *testing.T, resp *http.Response, what string) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, what)
}

func createCIBAApprovePolicy(t *testing.T) string {
	t.Helper()
	resp := post(t, adminPath("/credential-policies"), map[string]any{
		"name":                uid("ciba-approve-pol"),
		"max_ttl_seconds":     3600,
		"allowed_grant_types": []string{"api_key", "client_credentials"},
		"allowed_scopes":      []string{"ciba:approve"},
	}, channelWriteHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	id, _ := decode(t, resp)["id"].(string)
	require.NotEmpty(t, id)
	return id
}

func TestApprovalChannelWritesRequireTrustedContext(t *testing.T) {
	t.Run("register with the marker is refused", func(t *testing.T) {
		ext := uid("chan-marker")
		requireForbidden(t, post(t, adminPath("/agents/register"), map[string]any{
			"name": ext, "external_id": ext, "identity_type": "service",
			"sub_type": "approval_channel", "created_by": "test-user",
		}, adminHeaders()), "marker")
	})

	t.Run("register listing ciba:approve is refused", func(t *testing.T) {
		ext := uid("chan-scope")
		requireForbidden(t, post(t, adminPath("/agents/register"), map[string]any{
			"name": ext, "external_id": ext, "identity_type": "service",
			"allowed_scopes": []string{"ciba:approve"}, "created_by": "test-user",
		}, adminHeaders()), "scope")
	})

	// Request bodies with non-canonical field spellings or duplicate keys are
	// refused rather than registering an identity.
	for name, tmpl := range map[string]string{
		"folded duplicate keys": `{"name":"%[1]s","external_id":"%[1]s","identity_type":"service","created_by":"test-user",` +
			`"sub_type":"approval_channel","ſub_type":"api_service","allowed_scopes":["ciba:approve"],"allowed_ſcopes":[]}`,
		"upper-case duplicate key": `{"name":"%[1]s","external_id":"%[1]s","identity_type":"service","created_by":"test-user",` +
			`"sub_type":"approval_channel","SUB_TYPE":"approval_channel"}`,
		"repeated key": `{"name":"%[1]s","external_id":"%[1]s","identity_type":"service","created_by":"test-user",` +
			`"allowed_scopes":["tools:read"],"allowed_scopes":["ciba:approve"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			ext := uid("chan-variant")
			body := json.RawMessage(fmt.Sprintf(tmpl, ext))
			resp := post(t, adminPath("/agents/register"), body, adminHeaders())
			defer func() { _ = resp.Body.Close() }()
			require.NotEqual(t, http.StatusCreated, resp.StatusCode, "a variant body must never create the identity")
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Fatalf("expected a 4xx refusal, got %d", resp.StatusCode)
			}
		})
	}

	t.Run("identity create with the marker or scope is refused", func(t *testing.T) {
		for _, extra := range []map[string]any{
			{"sub_type": "approval_channel"},
			{"allowed_scopes": []string{"ciba:approve"}},
		} {
			ext := uid("ident-chan")
			body := map[string]any{"external_id": ext, "name": ext, "identity_type": "service", "owner_user_id": "test-user"}
			for k, v := range extra {
				body[k] = v
			}
			requireForbidden(t, post(t, adminPath("/identities"), body, adminHeaders()), "identity create")
		}
	})

	t.Run("identity update adding ciba:approve or a listing policy is refused", func(t *testing.T) {
		ext := uid("ident-plain")
		resp := post(t, adminPath("/identities"), map[string]any{
			"external_id": ext, "name": ext, "identity_type": "service", "owner_user_id": "test-user",
		}, adminHeaders())
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		id, _ := decode(t, resp)["id"].(string)
		require.NotEmpty(t, id)

		requireForbidden(t, doRequest(t, http.MethodPatch, adminPath("/identities/"+id),
			map[string]any{"allowed_scopes": []string{"ciba:approve"}}, adminHeaders()), "update scopes")
		policyID := createCIBAApprovePolicy(t)
		requireForbidden(t, doRequest(t, http.MethodPatch, adminPath("/identities/"+id),
			map[string]any{"credential_policy_id": policyID}, adminHeaders()), "attach policy")
	})

	t.Run("credential policy create or update listing ciba:approve is refused", func(t *testing.T) {
		requireForbidden(t, post(t, adminPath("/credential-policies"), map[string]any{
			"name": uid("pol"), "max_ttl_seconds": 3600, "allowed_scopes": []string{"ciba:approve"},
		}, adminHeaders()), "policy create")

		resp := post(t, adminPath("/credential-policies"), map[string]any{
			"name": uid("pol-plain"), "max_ttl_seconds": 3600, "allowed_scopes": []string{"tools:read"},
		}, adminHeaders())
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		id, _ := decode(t, resp)["id"].(string)
		requireForbidden(t, doRequest(t, http.MethodPatch, adminPath("/credential-policies/"+id),
			map[string]any{"allowed_scopes": []string{"tools:read", "ciba:approve"}}, adminHeaders()), "policy update")
	})

	t.Run("register with a policy listing ciba:approve is refused", func(t *testing.T) {
		policyID := createCIBAApprovePolicy(t)
		ext := uid("chan-policy")
		requireForbidden(t, post(t, adminPath("/agents/register"), map[string]any{
			"name": ext, "external_id": ext, "identity_type": "service",
			"credential_policy_id": policyID, "created_by": "test-user",
		}, adminHeaders()), "register with policy")
	})

	t.Run("API key with ciba:approve is refused", func(t *testing.T) {
		ext := uid("key-owner")
		resp := post(t, adminPath("/identities"), map[string]any{
			"external_id": ext, "name": ext, "identity_type": "service", "owner_user_id": "test-user",
		}, adminHeaders())
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		id, _ := decode(t, resp)["id"].(string)

		h := adminHeaders()
		h["X-User-ID"] = "test-user"
		requireForbidden(t, post(t, adminPath("/api-keys"), map[string]any{
			"name": uid("k"), "identity_id": id, "scopes": []string{"ciba:approve"},
		}, h), "api key scopes")
		requireForbidden(t, post(t, adminPath("/api-keys"), map[string]any{
			"name": uid("k"), "identity_id": id, "credential_policy_id": createCIBAApprovePolicy(t),
		}, h), "api key policy")
	})

	t.Run("trusted context registers an approval channel", func(t *testing.T) {
		ext := uid("chan-trusted")
		resp := post(t, adminPath("/agents/register"), map[string]any{
			"name": ext, "external_id": ext, "identity_type": "service",
			"sub_type": "approval_channel", "allowed_scopes": []string{"ciba:approve"}, "created_by": "test-user",
		}, channelWriteHeaders())
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		ident, _ := decode(t, resp)["identity"].(map[string]any)
		require.Equal(t, "approval_channel", ident["sub_type"])
	})
}
