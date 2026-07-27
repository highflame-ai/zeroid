// CIMD × registry-deactivation regression tests.
//
// Guards the fix for "deactivated registry clients are resurrected by the CIMD
// fallback": the registry-miss → CIMD fallback in IssueAuthCode and
// VerifyPresentedClientAuth must fire ONLY when the registry has no row at all.
// A row that exists but is deactivated (is_active = false) was deliberately
// registered, so deactivation must stay a kill switch — the flow must NOT fall
// through to the client's published metadata document and re-synthesize it.
//
// Both assertions use a document-fetch hit counter: the security property is
// not just "returns an error" but "never even reaches out for the document".
package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// newCIMDDocServer stands up an HTTPS server that serves a valid, self-
// referencing CIMD document for any path requested, counting fetches. The
// returned client trusts the server's self-signed cert (and, being the
// server's own client, sidesteps the SSRF guard for the loopback address) —
// the same pattern the service-package unit tests use.
func newCIMDDocServer(t *testing.T) (svc *service.CIMDService, base string, hits *int32) {
	t.Helper()
	var count int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Test","redirect_uris":["http://127.0.0.1:9000/cb"]}`, clientID)
	}))
	t.Cleanup(ts.Close)
	svc = service.NewCIMDService(service.CIMDConfig{Enabled: true, HTTPClient: ts.Client()})
	return svc, ts.URL, &count
}

// TestCIMD_DeactivatedRegistryClientNotResurrected pins that deactivating a
// registry client whose client_id is a CIMD-shaped URL kills it on both the
// authorize path (IssueAuthCode) and the introspection/revocation path
// (VerifyPresentedClientAuth), with no outbound document fetch — while an
// unregistered CIMD URL still resolves (the fallback is not over-broadened).
func TestCIMD_DeactivatedRegistryClientNotResurrected(t *testing.T) {
	ctx := context.Background()

	cimdSvc, base, hits := newCIMDDocServer(t)
	deactivatedID := base + "/client.json"      // registered, then deactivated
	unregisteredID := base + "/greenfield.json" // never in the registry

	clientRepo := postgres.NewOAuthClientRepository(testDB)
	clientSvc := service.NewOAuthClientService(clientRepo)

	// Register a public PKCE client under the CIMD URL, then deactivate it —
	// the exact state a deployer reaches when shutting a client down.
	require.NoError(t, clientRepo.Create(ctx, &domain.OAuthClient{
		ID:                           uuid.New().String(),
		ClientID:                     deactivatedID,
		Name:                         "cimd-deactivation-regression",
		ClientType:                   "public",
		TokenEndpointAuthMethod:      "none",
		BackchannelTokenDeliveryMode: "poll",
		GrantTypes:                   []string{"authorization_code", "refresh_token"},
		RedirectURIs:                 []string{"http://127.0.0.1:9000/cb"},
		Scopes:                       []string{},
		IsActive:                     false,
	}))
	t.Cleanup(func() {
		_, _ = testDB.NewDelete().Model((*domain.OAuthClient)(nil)).
			Where("client_id = ?", deactivatedID).Exec(context.Background())
	})

	oauthSvc := service.NewOAuthService(nil, nil, clientSvc, nil, nil, nil, nil,
		service.OAuthServiceConfig{
			Issuer:         "https://auth.test.example.com",
			AuthCodeIssuer: "https://auth.test.example.com",
			HMACSecret:     "test-hmac-secret-do-not-use-in-prod-32b!",
		})
	oauthSvc.SetCIMDService(cimdSvc)

	_, challenge := pkcePair(t)

	// 1. Authorize path: a deactivated CIMD-URL client must be refused without
	//    fetching its document.
	t.Run("IssueAuthCode refuses deactivated client, no fetch", func(t *testing.T) {
		before := atomic.LoadInt32(hits)
		_, err := oauthSvc.IssueAuthCode(ctx, service.IssueAuthCodeRequest{
			ClientID:            deactivatedID,
			RedirectURI:         "http://127.0.0.1:9000/cb",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
			AccountID:           "acct-regression",
		})
		require.Error(t, err)
		assert.Equal(t, int32(0), atomic.LoadInt32(hits)-before,
			"deactivation must be a kill switch — no CIMD document fetch may occur")
	})

	// 2. Introspection/revocation path: same client, same guarantee.
	t.Run("VerifyPresentedClientAuth refuses deactivated client, no fetch", func(t *testing.T) {
		before := atomic.LoadInt32(hits)
		err := oauthSvc.VerifyPresentedClientAuth(ctx, deactivatedID, "")
		require.Error(t, err)
		assert.Equal(t, int32(0), atomic.LoadInt32(hits)-before,
			"deactivation must be a kill switch — no CIMD document fetch may occur")
	})

	// 3. Positive control: an unregistered CIMD URL still resolves via the
	//    fallback (the fix narrows resurrection, it must not disable CIMD).
	t.Run("VerifyPresentedClientAuth still resolves unregistered CIMD client", func(t *testing.T) {
		before := atomic.LoadInt32(hits)
		err := oauthSvc.VerifyPresentedClientAuth(ctx, unregisteredID, "")
		require.NoError(t, err)
		assert.Equal(t, int32(1), atomic.LoadInt32(hits)-before,
			"an unregistered CIMD client_id must resolve by fetching its document")
	})
}

// pkcePair returns a PKCE verifier and its S256 challenge.
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = strings.Repeat("a", 43) // RFC 7636 minimum length
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}
