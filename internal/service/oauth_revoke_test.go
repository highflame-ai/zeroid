package service

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// Unit coverage for RFC 7009 §2.1 revocation by a CIMD client
// (zeroid#419). The registry lookup and the credential store need a database,
// so the end-to-end path lives in tests/integration/cimd_revoke_test.go; these
// tests pin the decisions that do not.

// TestAuthorizeCIMDRevoker_NonCIMDRequestsFallThrough pins the
// shapes that must NOT enter the CIMD revocation path and must instead fall
// through to VerifyPresentedClientAuth, unchanged. The OAuthService here has
// no client registry wired: reaching the registry would panic, so every case
// also proves the decision is made before any lookup.
func TestAuthorizeCIMDRevoker_NonCIMDRequestsFallThrough(t *testing.T) {
	const cimdURL = "https://app.example.com/oauth/client.json"
	enabled := &OAuthService{cimdSvc: NewCIMDService(CIMDConfig{Enabled: true})}

	cases := []struct {
		name string
		svc  *OAuthService
		req  RevocationRequest
	}{
		{"anonymous", enabled, RevocationRequest{Token: "t"}},
		{"client_secret presented", enabled, RevocationRequest{Token: "t", ClientID: cimdURL, ClientSecret: "s"}},
		// No client_id, so the client is identified by the assertion's iss —
		// and a non-CIMD iss is a registered client's business.
		{"assertion with a registered-style iss", enabled, RevocationRequest{
			Token: "t", ClientAssertion: unsignedAssertion(t, "cli-client"), ClientAssertionType: clientAssertionTypeJWTBearer,
		}},
		{"assertion with no iss and no client_id", enabled, RevocationRequest{
			Token: "t", ClientAssertion: "not-a-jwt", ClientAssertionType: clientAssertionTypeJWTBearer,
		}},
		// client_id wins over iss, as everywhere else: a registered client_id
		// is not rerouted by a CIMD-shaped iss.
		{"registered client_id with a CIMD iss", enabled, RevocationRequest{
			Token: "t", ClientID: "cli-client", ClientAssertion: unsignedAssertion(t, cimdURL),
			ClientAssertionType: clientAssertionTypeJWTBearer,
		}},
		{"registered-style client_id", enabled, RevocationRequest{Token: "t", ClientID: "cli-client"}},
		{"https URL without a path", enabled, RevocationRequest{Token: "t", ClientID: "https://app.example.com"}},
		{"CIMD disabled", &OAuthService{cimdSvc: NewCIMDService(CIMDConfig{Enabled: false})},
			RevocationRequest{Token: "t", ClientID: cimdURL}},
		{"CIMD not wired", &OAuthService{}, RevocationRequest{Token: "t", ClientID: cimdURL}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.svc.authorizeCIMDRevoker(context.Background(), tc.req)
			require.NoError(t, err)
			assert.Empty(t, got, "this shape must fall through to VerifyPresentedClientAuth")
		})
	}
}

// TestAuthenticateCIMDRevoker resolves real documents through the real
// CIMDService and checks how each client must authenticate to revoke. The
// function delegates to verifyConfidentialClientAuth — the one the
// authorization_code and refresh_token grants use for the same client — so
// the assertion rules (aud, jti single-use, key from the document) are the
// token endpoint's, not a copy.
func TestAuthenticateCIMDRevoker(t *testing.T) {
	ctx := context.Background()

	t.Run("public client (none)", func(t *testing.T) {
		var docURL string
		cimdSvc, base, _ := newCIMDTestServer(t, CIMDConfig{Enabled: true}, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, docJSON(docURL, `,"token_endpoint_auth_method":"none"`))
		})
		docURL = base + "/oauth/client.json"
		client, err := cimdSvc.ResolveClient(ctx, docURL)
		require.NoError(t, err)
		svc := clientAssertionSvc(dpop.NewMemoryStore())

		t.Run("is identified by client_id alone", func(t *testing.T) {
			assert.NoError(t, svc.authenticateCIMDRevoker(ctx, client, docURL, "", ""))
		})
		t.Run("may not present an assertion — nothing vetted a key for it", func(t *testing.T) {
			assertion := mintAssertion(t, newTestKey(t), docURL, assertionOpts{})
			requireInvalidClient(t, svc.authenticateCIMDRevoker(ctx, client, docURL, assertion, clientAssertionTypeJWTBearer))
		})
	})

	t.Run("confidential client (private_key_jwt)", func(t *testing.T) {
		key := newTestKey(t)
		cimdSvc, base := cimdKeyDocServer(t, key)
		clientID := base + "/.well-known/oauth/client-metadata.json"
		client, err := cimdSvc.ResolveClient(ctx, clientID)
		require.NoError(t, err)
		svc := clientAssertionSvc(dpop.NewMemoryStore())

		t.Run("a valid assertion authenticates", func(t *testing.T) {
			assertion := mintAssertion(t, key, clientID, assertionOpts{})
			assert.NoError(t, svc.authenticateCIMDRevoker(ctx, client, clientID, assertion, clientAssertionTypeJWTBearer))
		})
		t.Run("the token endpoint URL is an accepted aud", func(t *testing.T) {
			assertion := mintAssertion(t, key, clientID, assertionOpts{aud: testAssertionIssuer + "/oauth2/token"})
			assert.NoError(t, svc.authenticateCIMDRevoker(ctx, client, clientID, assertion, clientAssertionTypeJWTBearer))
		})
		t.Run("client_id alone is refused", func(t *testing.T) {
			err := svc.authenticateCIMDRevoker(ctx, client, clientID, "", "")
			requireInvalidClient(t, err)
			assert.Contains(t, err.Error(), "private_key_jwt")
		})
		t.Run("an assertion signed by a key the document does not publish is refused", func(t *testing.T) {
			assertion := mintAssertion(t, newTestKey(t), clientID, assertionOpts{})
			requireInvalidClient(t, svc.authenticateCIMDRevoker(ctx, client, clientID, assertion, clientAssertionTypeJWTBearer))
		})
		t.Run("an assertion for another audience is refused", func(t *testing.T) {
			assertion := mintAssertion(t, key, clientID, assertionOpts{aud: "https://other-as.example.com"})
			requireInvalidClient(t, svc.authenticateCIMDRevoker(ctx, client, clientID, assertion, clientAssertionTypeJWTBearer))
		})
		t.Run("an assertion whose iss names another client is refused", func(t *testing.T) {
			assertion := mintAssertion(t, key, clientID, assertionOpts{iss: "https://other.example.com/c.json"})
			requireInvalidClient(t, svc.authenticateCIMDRevoker(ctx, client, clientID, assertion, clientAssertionTypeJWTBearer))
		})
		t.Run("an assertion is single-use", func(t *testing.T) {
			assertion := mintAssertion(t, key, clientID, assertionOpts{jti: "revoke-replay-probe"})
			require.NoError(t, svc.authenticateCIMDRevoker(ctx, client, clientID, assertion, clientAssertionTypeJWTBearer))
			requireInvalidClient(t, svc.authenticateCIMDRevoker(ctx, client, clientID, assertion, clientAssertionTypeJWTBearer))
		})
	})

	t.Run("an unimplemented method is refused", func(t *testing.T) {
		requireInvalidClient(t, (&OAuthService{}).authenticateCIMDRevoker(ctx, &domain.OAuthClient{
			ClientID: "https://app.example.com/c.json", ClientType: "public",
			TokenEndpointAuthMethod: "tls_client_auth",
		}, "https://app.example.com/c.json", "", ""))
	})

	t.Run("no client is refused", func(t *testing.T) {
		requireInvalidClient(t, (&OAuthService{}).authenticateCIMDRevoker(ctx, nil, "x", "", ""))
	})
}

// unsignedAssertion is a syntactically valid JWT carrying only iss — enough
// for ClientIDFromAssertion to peek, and nothing that could verify.
func unsignedAssertion(t *testing.T, iss string) string {
	t.Helper()
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, iss))
	raw, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	require.NoError(t, err)
	return string(raw)
}

// TestTokenIssuedToClient pins the ownership comparison: only an exact match
// on the token's own client_id claim counts.
func TestTokenIssuedToClient(t *testing.T) {
	const owner = "https://app.example.com/oauth/client.json"

	build := func(t *testing.T, claims map[string]any) jwt.Token {
		t.Helper()
		tok := jwt.New()
		for k, v := range claims {
			require.NoError(t, tok.Set(k, v))
		}
		return tok
	}

	cases := []struct {
		name     string
		claims   map[string]any
		clientID string
		want     bool
	}{
		{"matching client_id", map[string]any{"client_id": owner}, owner, true},
		{"another client's token", map[string]any{"client_id": "https://other.example.com/c.json"}, owner, false},
		{"case differs", map[string]any{"client_id": "https://APP.example.com/oauth/client.json"}, owner, false},
		{"trailing slash differs", map[string]any{"client_id": owner + "/"}, owner, false},
		{"no client_id claim", map[string]any{"sub": "x"}, owner, false},
		// application_id carries the client_id on the authorization_code path
		// but is not reserved against additional_claims, so it must not count.
		{"application_id only", map[string]any{"application_id": owner}, owner, false},
		{"non-string client_id claim", map[string]any{"client_id": 42}, owner, false},
		{"empty presenting client never matches an empty claim", map[string]any{"client_id": ""}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tokenIssuedToClient(build(t, tc.claims), tc.clientID))
		})
	}

	assert.False(t, tokenIssuedToClient(nil, owner), "a nil token matches nothing")
}
