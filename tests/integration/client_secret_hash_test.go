package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func storedClientSecret(t *testing.T, clientID string) string {
	t.Helper()
	var stored string
	require.NoError(t, testDB.NewSelect().TableExpr("oauth_clients").Column("client_secret").
		Where("client_id = ?", clientID).Scan(context.Background(), &stored))
	return stored
}

func clientCredentials(t *testing.T, clientID, secret string) int {
	t.Helper()
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret,
		"account_id": testAccountID, "project_id": testProjectID, "scope": "data:read",
	}, nil)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// New secrets are stored as SHA-256 digests, never as the plaintext.
func TestClientSecretStoredAsSHA256(t *testing.T) {
	ext := uid("secret-sha256")
	registerIdentity(t, ext, []string{"data:read"})
	c := registerOAuthClient(t, ext, []string{"data:read"})

	stored := storedClientSecret(t, c.ClientID)
	assert.True(t, strings.HasPrefix(stored, "sha256$"), "stored hash %q", stored)
	assert.NotContains(t, stored, c.ClientSecret)
	assert.Equal(t, http.StatusOK, clientCredentials(t, c.ClientID, c.ClientSecret))
	assert.Equal(t, http.StatusUnauthorized, clientCredentials(t, c.ClientID, c.ClientSecret+"0"))
}

// A client registered before the switch still authenticates, and its bcrypt
// hash is upgraded on the first successful verify.
func TestLegacyBcryptClientSecretUpgradedOnUse(t *testing.T) {
	ext := uid("secret-legacy")
	registerIdentity(t, ext, []string{"data:read"})
	c := registerOAuthClient(t, ext, []string{"data:read"})

	legacy, err := bcrypt.GenerateFromPassword([]byte(c.ClientSecret), bcrypt.MinCost)
	require.NoError(t, err)
	_, err = testDB.NewUpdate().TableExpr("oauth_clients").Set("client_secret = ?", string(legacy)).
		Where("client_id = ?", c.ClientID).Exec(context.Background())
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, clientCredentials(t, c.ClientID, "wrong"))
	assert.Equal(t, string(legacy), storedClientSecret(t, c.ClientID), "failed verify must not upgrade")

	require.Equal(t, http.StatusOK, clientCredentials(t, c.ClientID, c.ClientSecret))
	assert.True(t, strings.HasPrefix(storedClientSecret(t, c.ClientID), "sha256$"), "hash not upgraded")
	assert.Equal(t, http.StatusOK, clientCredentials(t, c.ClientID, c.ClientSecret), "upgraded hash must verify")
}
