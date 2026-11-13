package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Issuing, rotating or removing credentials of an approval channel requires a
// request marked with zeroid.WithTrustedApprovalChannelWrite, and discovery
// ingest leaves approval channels unchanged.

func issueChannelCredential(t *testing.T, identityID string, scopes []string, headers map[string]string) *http.Response {
	t.Helper()
	return post(t, adminPath("/credentials/issue"), map[string]any{
		"identity_id": identityID, "scopes": scopes, "grant_type": "client_credentials",
	}, headers)
}

func TestApprovalChannelCredentialIssue(t *testing.T) {
	t.Run("untrusted issue for an approval channel is refused", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		requireForbidden(t, issueChannelCredential(t, ch.ID, []string{"ciba:approve"}, adminHeaders()), "with ciba:approve")
		requireForbidden(t, issueChannelCredential(t, ch.ID, nil, adminHeaders()), "without scopes")
	})

	t.Run("a scope refusal is a client error", func(t *testing.T) {
		plain := registerPlainServiceIdentity(t)
		resp := issueChannelCredential(t, plain.ID, []string{"ciba:approve"}, adminHeaders())
		body := decode(t, resp)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
	})

	t.Run("trusted issue for an approval channel succeeds", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		resp := issueChannelCredential(t, ch.ID, []string{"ciba:approve"}, channelWriteHeaders())
		body := decode(t, resp)
		require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", body)
	})
}

func TestApprovalChannelCredentialRotate(t *testing.T) {
	ch := registerChannel(t, "approval_channel", "")
	resp := issueChannelCredential(t, ch.ID, []string{"ciba:approve"}, channelWriteHeaders())
	body := decode(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", body)
	credID, _ := body["credential"].(map[string]any)["id"].(string)
	token, _ := body["token"].(map[string]any)["access_token"].(string)
	require.NotEmpty(t, credID)
	require.NotEmpty(t, token)

	requireForbidden(t, post(t, adminPath("/credentials/"+credID+"/rotate"), nil, adminHeaders()), "untrusted rotate")
	require.Equal(t, true, introspect(t, token)["active"], "a refused rotation leaves the credential active")

	rot := post(t, adminPath("/credentials/"+credID+"/rotate"), nil, channelWriteHeaders())
	require.Equal(t, http.StatusCreated, rot.StatusCode, "%v", decode(t, rot))
	require.Equal(t, false, introspect(t, token)["active"], "a trusted rotation revokes the old credential")
}

func TestApprovalChannelCredentialRemovalRequiresTrustedContext(t *testing.T) {
	t.Run("OAuth client", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		resp := registerClient(t, ch.ExternalID, "", channelWriteHeaders())
		body := decode(t, resp)
		require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", body)
		id, _ := body["client"].(map[string]any)["id"].(string)
		require.NotEmpty(t, id)

		requireForbidden(t, doRequest(t, http.MethodDelete, adminPath("/oauth/clients/"+id), nil, adminHeaders()), "untrusted delete")
		del := doRequest(t, http.MethodDelete, adminPath("/oauth/clients/"+id), nil, channelWriteHeaders())
		_ = del.Body.Close()
		require.Less(t, del.StatusCode, 300)
	})

	t.Run("API key", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		resp := createKeyFor(t, ch.ID, trustedKeyHeaders())
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		body := decode(t, resp)
		id, _ := body["id"].(string)
		key, _ := body["key"].(string)
		require.NotEmpty(t, id)

		revoke := map[string]any{"reason": "test"}
		requireForbidden(t, post(t, adminPath("/api-keys/"+id+"/revoke"), revoke, untrustedKeyHeaders()), "untrusted revoke")
		requireCIBAApproveMinted(t, mintAPIKeyScope(t, key, "ciba:approve"))

		ok := post(t, adminPath("/api-keys/"+id+"/revoke"), revoke, trustedKeyHeaders())
		_ = ok.Body.Close()
		require.Equal(t, http.StatusOK, ok.StatusCode)
	})
}

// TestDiscoveryLeavesApprovalChannelsUnchanged pins that discovery ingest,
// single or batch, and the source prune/release/purge sweeps do not modify an
// approval channel.
func TestDiscoveryLeavesApprovalChannelsUnchanged(t *testing.T) {
	ext := uid("okta-channel")
	source := uid("src")
	created := ingestDiscovered(t, map[string]any{
		"external_id": ext, "origin": "okta", "name": "bridge", "source_id": source,
		"identity_type": "service",
	})
	id, _ := created["identity"].(map[string]any)["id"].(string)
	require.NotEmpty(t, id)

	meta := map[string]any{"attestation_issuers": []string{"https://issuer.example.test"}}
	up := doRequest(t, http.MethodPatch, adminPath("/identities/"+id), map[string]any{
		"allowed_scopes": []string{"ciba:approve"}, "metadata": meta,
	}, channelWriteHeaders())
	require.Equal(t, http.StatusOK, up.StatusCode, "%v", decode(t, up))

	readIdentity := func() map[string]any {
		r := get(t, adminPath("/identities/"+id), adminHeaders())
		require.Equal(t, http.StatusOK, r.StatusCode)
		return decode(t, r)
	}
	before := readIdentity()

	change := map[string]any{
		"external_id": ext, "origin": "okta", "name": "renamed", "description": "changed",
		"metadata": map[string]any{"attestation_issuers": []string{"https://other.example.test"}},
	}
	single := post(t, adminPath("/identities/discovered"), change, adminHeaders())
	_ = single.Body.Close()
	require.Equal(t, http.StatusOK, single.StatusCode)
	ingestBatch(t, []map[string]any{change})

	require.Equal(t, 0, pruneStale(t, "okta", source, time.Now().UTC().Format(time.RFC3339Nano)))
	for _, path := range []string{"/identities/discovered/release-source", "/identities/discovered/purge-source"} {
		r := post(t, adminPath(path), map[string]any{"origin": "okta", "source_id": source}, adminHeaders())
		_ = r.Body.Close()
		require.Equal(t, http.StatusOK, r.StatusCode, path)
	}

	after := readIdentity()
	for _, k := range []string{"name", "description", "metadata", "status", "source_id", "sub_type", "identity_type", "allowed_scopes"} {
		require.Equal(t, before[k], after[k], "field %s", k)
	}
}
