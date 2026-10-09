package integration_test

import (
	"context"
	"database/sql"
	"io/fs"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// Obtaining any credential for an approval channel (an identity with sub_type
// approval_channel, or whose scope ceiling lists ciba:approve) requires a
// request marked with zeroid.WithTrustedApprovalChannelWrite: API keys, key
// rotation, public keys, OAuth clients and client secrets. ciba:approve is
// minted only from an API key, OAuth client or public key that was itself
// written in that context.

type channelIdentity struct {
	ID         string
	ExternalID string
	WIMSEURI   string
	APIKey     string
}

// registerChannel registers an approval channel as a trusted write. With a
// policyID it lists ciba:approve on that policy instead of on the identity.
func registerChannel(t *testing.T, subType, policyID string) channelIdentity {
	t.Helper()
	ext := uid("chan")
	body := map[string]any{
		"name": ext, "external_id": ext, "identity_type": "service", "created_by": "test-user",
	}
	if subType != "" {
		body["sub_type"] = subType
	}
	if policyID != "" {
		body["credential_policy_id"] = policyID
	} else {
		body["allowed_scopes"] = []string{"ciba:approve"}
	}
	resp := post(t, adminPath("/agents/register"), body, channelWriteHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	out := decode(t, resp)
	ident, _ := out["identity"].(map[string]any)
	key, _ := out["api_key"].(string)
	require.NotEmpty(t, key)
	return channelIdentity{
		ID: ident["id"].(string), ExternalID: ext, WIMSEURI: ident["wimse_uri"].(string), APIKey: key,
	}
}

// registerPlainServiceIdentity registers a service identity with no
// approval-channel grant, as an ordinary (untrusted) write.
func registerPlainServiceIdentity(t *testing.T) channelIdentity {
	t.Helper()
	ext := uid("svc-plain")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name": ext, "external_id": ext, "identity_type": "service", "created_by": "test-user",
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	out := decode(t, resp)
	ident, _ := out["identity"].(map[string]any)
	key, _ := out["api_key"].(string)
	return channelIdentity{
		ID: ident["id"].(string), ExternalID: ext, WIMSEURI: ident["wimse_uri"].(string), APIKey: key,
	}
}

func untrustedKeyHeaders() map[string]string {
	h := adminHeaders()
	h["X-User-ID"] = "test-user"
	return h
}

func trustedKeyHeaders() map[string]string {
	h := channelWriteHeaders()
	h["X-User-ID"] = "test-user"
	return h
}

func createKeyFor(t *testing.T, identityID string, headers map[string]string) *http.Response {
	t.Helper()
	return post(t, adminPath("/api-keys"), map[string]any{"name": uid("k"), "identity_id": identityID}, headers)
}

func apiKeyFrom(t *testing.T, resp *http.Response) string {
	t.Helper()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decode(t, resp)
	key, _ := body["key"].(string)
	require.NotEmpty(t, key, "%v", body)
	return key
}

func requireCIBAApproveMinted(t *testing.T, resp *http.Response) {
	t.Helper()
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	scope, _ := body["scope"].(string)
	require.Contains(t, strings.Fields(scope), "ciba:approve")
}

func requireCIBAApproveRefused(t *testing.T, resp *http.Response) {
	t.Helper()
	body := decode(t, resp)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
}

func jwtBearerScope(t *testing.T, assertion, scope string) *http.Response {
	t.Helper()
	return post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":  assertion, "scope": scope,
	}, nil)
}

func clientCredentialsScope(t *testing.T, clientID, secret, scope string) *http.Response {
	t.Helper()
	return post(t, "/oauth2/token", map[string]any{
		"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret,
		"scope": scope, "account_id": testAccountID, "project_id": testProjectID,
	}, nil)
}

func registerClient(t *testing.T, clientID, identityID string, headers map[string]string) *http.Response {
	t.Helper()
	body := map[string]any{
		"client_id": clientID, "name": clientID, "confidential": true,
		"grant_types": []string{"client_credentials"}, "scopes": []string{"ciba:approve"},
	}
	if identityID != "" {
		body["identity_id"] = identityID
	}
	return post(t, adminPath("/oauth/clients"), body, headers)
}

func TestApprovalChannelCredentialsRequireTrustedContext(t *testing.T) {
	t.Run("API key for an approval channel", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		requireForbidden(t, createKeyFor(t, ch.ID, untrustedKeyHeaders()), "untrusted key")

		key := apiKeyFrom(t, createKeyFor(t, ch.ID, trustedKeyHeaders()))
		requireCIBAApproveMinted(t, mintAPIKeyScope(t, key, "ciba:approve"))
	})

	t.Run("API key for an identity whose policy lists ciba:approve", func(t *testing.T) {
		ch := registerChannel(t, "", createCIBAApprovePolicy(t))
		requireForbidden(t, createKeyFor(t, ch.ID, untrustedKeyHeaders()), "untrusted key")
	})

	t.Run("key rotation", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		requireForbidden(t, post(t, adminPath("/agents/registry/"+ch.ID+"/rotate-key"), nil, adminHeaders()), "untrusted rotate")
		// A refused rotation leaves the existing key in place.
		requireCIBAApproveMinted(t, mintAPIKeyScope(t, ch.APIKey, "ciba:approve"))

		resp := post(t, adminPath("/agents/registry/"+ch.ID+"/rotate-key"), nil, channelWriteHeaders())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		key, _ := decode(t, resp)["api_key"].(string)
		require.NotEmpty(t, key)
		requireCIBAApproveMinted(t, mintAPIKeyScope(t, key, "ciba:approve"))
	})

	t.Run("public key on agent update", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		k := generateKey(t)
		body := map[string]any{"public_key_pem": ecPublicKeyPEM(t, k)}
		requireForbidden(t, doRequest(t, http.MethodPatch, adminPath("/agents/registry/"+ch.ID), body, adminHeaders()), "untrusted agent update")
		requireForbidden(t, doRequest(t, http.MethodPatch, adminPath("/identities/"+ch.ID), body, adminHeaders()), "untrusted identity update")
		requireCIBAApproveRefused(t, jwtBearerScope(t, buildAssertion(t, k, ch.WIMSEURI), "ciba:approve"))

		resp := doRequest(t, http.MethodPatch, adminPath("/agents/registry/"+ch.ID), body, channelWriteHeaders())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
		requireCIBAApproveMinted(t, jwtBearerScope(t, buildAssertion(t, k, ch.WIMSEURI), "ciba:approve"))
	})

	t.Run("self-service public key", func(t *testing.T) {
		// POST /agents/self/public-key stores the key through
		// IdentityService.SetPublicKey after verifying the key proofs.
		svc := service.NewIdentityService(postgres.NewIdentityRepository(testDB),
			service.NewCredentialPolicyService(postgres.NewCredentialPolicyRepository(testDB)), nil, nil, nil, "")
		ctx := context.Background()

		ch := registerChannel(t, "approval_channel", "")
		pub := ecPublicKeyPEM(t, generateKey(t))
		_, err := svc.SetPublicKey(ctx, ch.ID, testAccountID, testProjectID, pub)
		require.ErrorIs(t, err, service.ErrApprovalChannelWriteNotTrusted)

		updated, err := svc.SetPublicKey(service.WithTrustedApprovalChannelWrite(ctx), ch.ID, testAccountID, testProjectID, pub)
		require.NoError(t, err)
		require.True(t, updated.PublicKeyChannelTrusted)

		plain := registerPlainServiceIdentity(t)
		updated, err = svc.SetPublicKey(ctx, plain.ID, testAccountID, testProjectID, pub)
		require.NoError(t, err)
		require.False(t, updated.PublicKeyChannelTrusted)
	})

	t.Run("OAuth client whose client_id names an approval channel", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		requireForbidden(t, registerClient(t, ch.ExternalID, "", adminHeaders()), "untrusted client")

		resp := registerClient(t, ch.ExternalID, "", channelWriteHeaders())
		body := decode(t, resp)
		require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", body)
		secret, _ := body["client_secret"].(string)
		requireCIBAApproveMinted(t, clientCredentialsScope(t, ch.ExternalID, secret, "ciba:approve"))

		// Rotating that client's secret is a trusted write too.
		client, _ := body["client"].(map[string]any)
		id, _ := client["id"].(string)
		require.NotEmpty(t, id)
		requireForbidden(t, post(t, adminPath("/oauth/clients/"+id+"/rotate-secret"), nil, adminHeaders()), "untrusted rotate-secret")
		rot := post(t, adminPath("/oauth/clients/"+id+"/rotate-secret"), nil, channelWriteHeaders())
		require.Equal(t, http.StatusOK, rot.StatusCode)
		_ = rot.Body.Close()
	})

	t.Run("OAuth client bound to an approval channel", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		requireForbidden(t, registerClient(t, uid("cc-chan"), ch.ID, adminHeaders()), "untrusted bound client")
	})
}

// TestCIBAApproveRequiresTrustedCredential pins that ciba:approve is minted
// only from a credential written in the trusted context: an API key, OAuth
// client or public key obtained while the identity was an ordinary one does
// not mint it after the identity is made an approval channel.
func TestCIBAApproveRequiresTrustedCredential(t *testing.T) {
	plain := registerPlainServiceIdentity(t)

	k := generateKey(t)
	resp := doRequest(t, http.MethodPatch, adminPath("/agents/registry/"+plain.ID),
		map[string]any{"public_key_pem": ecPublicKeyPEM(t, k)}, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	cr := registerClient(t, plain.ExternalID, "", adminHeaders())
	cb := decode(t, cr)
	require.Equal(t, http.StatusCreated, cr.StatusCode, "%v", cb)
	secret, _ := cb["client_secret"].(string)

	up := doRequest(t, http.MethodPatch, adminPath("/identities/"+plain.ID),
		map[string]any{"allowed_scopes": []string{"ciba:approve"}}, channelWriteHeaders())
	require.Equal(t, http.StatusOK, up.StatusCode)
	_ = up.Body.Close()

	requireCIBAApproveRefused(t, mintAPIKeyScope(t, plain.APIKey, "ciba:approve"))
	requireCIBAApproveRefused(t, jwtBearerScope(t, buildAssertion(t, k, plain.WIMSEURI), "ciba:approve"))
	requireCIBAApproveRefused(t, clientCredentialsScope(t, plain.ExternalID, secret, "ciba:approve"))

	// A key issued in the trusted context mints it.
	key := apiKeyFrom(t, createKeyFor(t, plain.ID, trustedKeyHeaders()))
	requireCIBAApproveMinted(t, mintAPIKeyScope(t, key, "ciba:approve"))
}

// TestApprovalChannelCredentialMarkerMigration applies migration 052's down
// and up scripts inside a transaction that is rolled back.
func TestApprovalChannelCredentialMarkerMigration(t *testing.T) {
	ctx := context.Background()
	const name = "052_approval_channel_credential_marker"
	up, err := fs.ReadFile(zeroid.MigrationFiles(), name+".up.sql")
	require.NoError(t, err)
	down, err := fs.ReadFile(zeroid.MigrationFiles(), name+".down.sql")
	require.NoError(t, err)

	countColumns := func(tx bun.Tx) int {
		var n int
		require.NoError(t, tx.QueryRowContext(ctx,
			`SELECT count(*) FROM information_schema.columns
			 WHERE (table_name = 'service_keys' AND column_name = 'channel_trusted')
			    OR (table_name = 'oauth_clients' AND column_name = 'channel_trusted')
			    OR (table_name = 'identities' AND column_name = 'public_key_channel_trusted')`).Scan(&n))
		return n
	}

	tx, err := testDB.BeginTx(ctx, &sql.TxOptions{})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	require.Equal(t, 3, countColumns(tx), "migration must be applied by the suite")
	_, err = tx.ExecContext(ctx, string(down))
	require.NoError(t, err)
	require.Equal(t, 0, countColumns(tx), "down must drop every column")
	_, err = tx.ExecContext(ctx, string(up))
	require.NoError(t, err)
	require.Equal(t, 3, countColumns(tx), "up must add every column")
}
