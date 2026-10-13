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
)

// Unit coverage for RFC 7009 §2.1 revocation by a public CIMD client
// (zeroid#419). The registry lookup and the credential store need a database,
// so the end-to-end path lives in tests/integration/cimd_revoke_test.go; these
// tests pin the decisions that do not.

// TestAuthorizeCIMDRevoker_OnlyClientIDOnlyCIMDRequestsTakeThePath pins the
// shapes that must NOT enter the CIMD revocation path and must instead fall
// through to VerifyPresentedClientAuth, unchanged. The OAuthService here has
// no client registry wired: reaching the registry would panic, so every case
// also proves the decision is made before any lookup.
func TestAuthorizeCIMDRevoker_OnlyClientIDOnlyCIMDRequestsTakeThePath(t *testing.T) {
	const cimdURL = "https://app.example.com/oauth/client.json"
	enabled := &OAuthService{cimdSvc: NewCIMDService(CIMDConfig{Enabled: true})}

	cases := []struct {
		name string
		svc  *OAuthService
		req  RevocationRequest
	}{
		{"anonymous", enabled, RevocationRequest{Token: "t"}},
		{"client_secret presented", enabled, RevocationRequest{Token: "t", ClientID: cimdURL, ClientSecret: "s"}},
		{"client_assertion presented", enabled, RevocationRequest{Token: "t", ClientID: cimdURL, ClientAssertion: "a.b.c"}},
		{"client_assertion_type alone presented", enabled, RevocationRequest{
			Token: "t", ClientID: cimdURL, ClientAssertionType: clientAssertionTypeJWTBearer,
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

// TestCIMDRevokerMustBePublic resolves real documents through the real
// CIMDService and checks which of them may revoke by client_id alone. A
// document declaring private_key_jwt describes a confidential client: naming
// it proves nothing, so it is refused exactly as before this path existed.
func TestCIMDRevokerMustBePublic(t *testing.T) {
	ctx := context.Background()

	t.Run("a document declaring none is a public client and is accepted", func(t *testing.T) {
		var docURL string
		cimdSvc, base, _ := newCIMDTestServer(t, CIMDConfig{Enabled: true}, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, docJSON(docURL, `,"token_endpoint_auth_method":"none"`))
		})
		docURL = base + "/oauth/client.json"

		client, err := cimdSvc.ResolveClient(ctx, docURL)
		require.NoError(t, err)
		assert.NoError(t, cimdRevokerMustBePublic(client))
	})

	t.Run("a document declaring private_key_jwt is confidential and is refused", func(t *testing.T) {
		cimdSvc, base := cimdKeyDocServer(t, newTestKey(t))
		client, err := cimdSvc.ResolveClient(ctx, base+"/.well-known/oauth/client-metadata.json")
		require.NoError(t, err)

		err = cimdRevokerMustBePublic(client)
		requireInvalidClient(t, err)
	})

	t.Run("an unimplemented method is refused", func(t *testing.T) {
		requireInvalidClient(t, cimdRevokerMustBePublic(&domain.OAuthClient{
			ClientID: "https://app.example.com/c.json", ClientType: "public",
			TokenEndpointAuthMethod: "tls_client_auth",
		}))
	})

	t.Run("no client is refused", func(t *testing.T) {
		requireInvalidClient(t, cimdRevokerMustBePublic(nil))
	})
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
