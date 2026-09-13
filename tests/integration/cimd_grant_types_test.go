package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/internal/service"
)

// End-to-end coverage for zeroid#344: a CIMD document that lists a grant this
// server does not implement must still resolve.
//
// The reported failure was MCPJam's public document, which declares
// `["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]`.
// device_code is a grant ZeroID does not implement and could therefore never
// issue — yet its mere presence failed the whole document with
// `invalid_client_metadata`, and `cimdOAuthError` deliberately withholds the
// cause, so the client saw an opaque 400 it could not act on. The client could
// not fix it either: a CIMD document is a single declaration published to every
// authorization server it talks to.
//
// These tests drive the real CIMD resolution path rather than the synthesizer
// directly, so they cover the document fetch, parse and cache as well.

// newGrantTypesDocServer serves a self-referencing CIMD document whose
// grant_types are supplied by the caller.
func newGrantTypesDocServer(t *testing.T, grantTypesJSON string) (*service.CIMDService, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"client_id":%q,"client_name":"MCPJam","redirect_uris":["http://127.0.0.1:9000/cb"],"grant_types":%s}`,
			clientID, grantTypesJSON)
	}))
	t.Cleanup(ts.Close)
	return service.NewCIMDService(service.CIMDConfig{Enabled: true, HTTPClient: ts.Client()}), ts.URL
}

func TestCIMD_DocumentListingAnUnimplementedGrantStillResolves(t *testing.T) {
	ctx := context.Background()

	// The exact shape from the issue.
	cimdSvc, base := newGrantTypesDocServer(t,
		`["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]`)
	clientID := base + "/.well-known/oauth/client-metadata.json"

	client, err := cimdSvc.ResolveClient(ctx, clientID)
	require.NoError(t, err,
		"a document listing device_code must resolve — the grant is simply not offered, "+
			"and the client cannot drop it without breaking its other servers")
	require.NotNil(t, client)

	assert.Equal(t, []string{"authorization_code", "refresh_token"}, client.GrantTypes,
		"the synthesized client carries the supported intersection, in document order")
	assert.Equal(t, "MCPJam", client.Name)
	assert.NotContains(t, client.GrantTypes, "urn:ietf:params:oauth:grant-type:device_code")
}

// The security invariant the old rejection was reaching for, asserted where it
// actually lives: what reaches the synthesized client's GrantTypes. The token
// endpoint gates client_credentials on exactly this list, so a grant absent
// here cannot be obtained — which is what makes dropping safe rather than
// merely permissive.
func TestCIMD_M2MGrantInDocumentDoesNotReachTheClient(t *testing.T) {
	ctx := context.Background()

	cimdSvc, base := newGrantTypesDocServer(t,
		`["authorization_code","client_credentials","urn:ietf:params:oauth:grant-type:token-exchange"]`)
	clientID := base + "/client.json"

	client, err := cimdSvc.ResolveClient(ctx, clientID)
	require.NoError(t, err, "the document resolves; the unsupported grants are simply dropped")

	assert.Equal(t, []string{"authorization_code"}, client.GrantTypes)
	assert.NotContains(t, client.GrantTypes, "client_credentials",
		"a zero-registration client must never be able to obtain an M2M grant")
	assert.NotContains(t, client.GrantTypes, "urn:ietf:params:oauth:grant-type:token-exchange")
}

// authorization_code is the one flow CIMD exists for. A document that leaves
// nothing after narrowing still fails — dropping is not the same as accepting
// anything.
func TestCIMD_DocumentWithNoSupportedGrantIsStillRejected(t *testing.T) {
	ctx := context.Background()

	cimdSvc, base := newGrantTypesDocServer(t, `["client_credentials","urn:ietf:params:oauth:grant-type:device_code"]`)

	_, err := cimdSvc.ResolveClient(ctx, base+"/client.json")
	require.Error(t, err,
		"with no authorization_code left there is no interactive flow to synthesize a client for")
}

// The control: an ordinary document is unaffected, and an omitted grant_types
// still defaults to [authorization_code] per the draft.
func TestCIMD_OrdinaryDocumentsAreUnaffected(t *testing.T) {
	ctx := context.Background()

	t.Run("explicit supported grants", func(t *testing.T) {
		cimdSvc, base := newGrantTypesDocServer(t, `["authorization_code","refresh_token"]`)
		client, err := cimdSvc.ResolveClient(ctx, base+"/client.json")
		require.NoError(t, err)
		assert.Equal(t, []string{"authorization_code", "refresh_token"}, client.GrantTypes)
	})

	t.Run("omitted grant_types defaults to authorization_code", func(t *testing.T) {
		cimdSvc, base := newGrantTypesDocServer(t, `null`)
		client, err := cimdSvc.ResolveClient(ctx, base+"/client.json")
		require.NoError(t, err)
		assert.Equal(t, []string{"authorization_code"}, client.GrantTypes)
	})
}

// Editing a published document must not kill live sessions.
//
// This is the same bug as zeroid#344 in its second, subtler form. The refresh
// path RE-RESOLVES the CIMD document on every rotation, deliberately, so that a
// republished document acts as the revocation lever (oauth.go: "that document
// edit is CIMD's revocation lever"). Under the old validator, a client that
// merely ADDED a grant type to its document — say device_code, to support a new
// server — did not just lose new logins: re-resolution failed, and every live
// refresh token stopped rotating at its next use.
//
// The revocation lever itself must keep working, so this also pins the inverse:
// REMOVING refresh_token still stops rotation.
func TestCIMD_AddingAGrantToAPublishedDocumentKeepsRefreshUsable(t *testing.T) {
	ctx := context.Background()

	// A document server whose grant_types can be republished mid-test.
	grants := `["authorization_code","refresh_token"]`
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"client_id":%q,"client_name":"MCPJam","redirect_uris":["http://127.0.0.1:9000/cb"],"grant_types":%s}`,
			clientID, grants)
	}))
	defer ts.Close()

	// CacheTTL 0 would use the default hour; these assertions are about what a
	// fresh resolution yields, so each step builds its own service.
	resolve := func() (grantTypes []string, err error) {
		svc := service.NewCIMDService(service.CIMDConfig{Enabled: true, HTTPClient: ts.Client()})
		c, err := svc.ResolveClient(ctx, ts.URL+"/client.json")
		if err != nil {
			return nil, err
		}
		return c.GrantTypes, nil
	}

	before, err := resolve()
	require.NoError(t, err)
	require.Contains(t, before, "refresh_token", "baseline: rotation is permitted")

	// The client republishes with an extra grant for some OTHER server.
	grants = `["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]`

	after, err := resolve()
	require.NoError(t, err,
		"re-resolution must still succeed — otherwise adding a grant for another "+
			"authorization server silently revokes every live refresh token here")
	assert.Contains(t, after, "refresh_token",
		"rotation must survive a document edit that only adds an unsupported grant")
	assert.NotContains(t, after, "urn:ietf:params:oauth:grant-type:device_code")

	// The revocation lever still works: dropping refresh_token stops rotation.
	grants = `["authorization_code"]`
	revoked, err := resolve()
	require.NoError(t, err)
	assert.NotContains(t, revoked, "refresh_token",
		"republishing without refresh_token must still withdraw rotation — that is "+
			"the only revocation mechanism a zero-registration client has")
}
