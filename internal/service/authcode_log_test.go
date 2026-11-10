package service

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// captureAuthCodeLog swaps the global logger for one that writes to a buffer.
func captureAuthCodeLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	orig := log.Logger
	log.Logger = zerolog.New(buf)
	t.Cleanup(func() { log.Logger = orig })
	return buf
}

// TestLogAuthorizationCodeRedeemed pins the success line of an
// authorization_code redemption: for one request, how the client authenticated
// and that its code_verifier matched, with no credential in it.
func TestLogAuthorizationCodeRedeemed(t *testing.T) {
	t.Run("records the client authentication and the PKCE result", func(t *testing.T) {
		buf := captureAuthCodeLog(t)
		logAuthorizationCodeRedeemed(authCodeRedemption{
			requestID:  "host/abc-000001",
			clientID:   "https://client.example/metadata.json",
			cimd:       true,
			clientAuth: "none",
			accountID:  "acct",
			projectID:  "proj",
			userID:     "user-1",
			jti:        "jti-1",
		})

		var line map[string]any
		require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line))
		assert.Equal(t, "authorization code redeemed", line["message"])
		assert.Equal(t, "info", line["level"])
		assert.Equal(t, "host/abc-000001", line["request_id"])
		assert.Equal(t, "https://client.example/metadata.json", line["client_id"])
		assert.Equal(t, true, line["cimd"])
		assert.Equal(t, "none", line["client_auth"])
		assert.Equal(t, false, line["sent_authorization_header"])
		assert.Equal(t, false, line["sent_client_secret"])
		assert.Equal(t, false, line["sent_client_assertion"])
		assert.Equal(t, "S256", line["code_challenge_method"])
		assert.Equal(t, "verified", line["code_verifier"])
		assert.Equal(t, "acct", line["account_id"])
		assert.Equal(t, "proj", line["project_id"])
		assert.Equal(t, "user-1", line["user_id"])
		assert.Equal(t, "jti-1", line["jti"])
	})

	t.Run("omits request_id when the request carried none", func(t *testing.T) {
		buf := captureAuthCodeLog(t)
		logAuthorizationCodeRedeemed(authCodeRedemption{clientID: "cli", clientAuth: "none", jti: "jti-2"})

		var line map[string]any
		require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line))
		assert.Equal(t, "jti-2", line["jti"])
		assert.NotContains(t, line, "request_id")
	})
}

// TestClientAuthRequired pins the names the success line uses for the client
// authentication verifyConfidentialClientAuth enforces, including rows that
// predate token_endpoint_auth_method and the inconsistent "none" row that
// still holds a secret (enforced as secret-based, so named that way).
func TestClientAuthRequired(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client domain.OAuthClient
		want   string
	}{
		{"key-based client", domain.OAuthClient{TokenEndpointAuthMethod: "private_key_jwt"}, "private_key_jwt"},
		{"public client", domain.OAuthClient{TokenEndpointAuthMethod: "none", ClientType: "public"}, "none"},
		{"client_secret_basic", domain.OAuthClient{TokenEndpointAuthMethod: "client_secret_basic"}, "client_secret"},
		{"client_secret_post", domain.OAuthClient{TokenEndpointAuthMethod: "client_secret_post"}, "client_secret"},
		{"legacy public row", domain.OAuthClient{ClientType: "public"}, "none"},
		{"legacy confidential row", domain.OAuthClient{ClientType: "confidential", ClientSecret: "$2a$hash"}, "client_secret"},
		{"none row holding a secret", domain.OAuthClient{TokenEndpointAuthMethod: "none", ClientSecret: "$2a$hash"}, "client_secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, clientAuthRequired(&tc.client))
		})
	}
}
