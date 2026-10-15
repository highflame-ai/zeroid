package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A grant that names no lifetime gets the server default (3600s here). A
// policy with a shorter max_ttl_seconds must shorten that lifetime, not refuse
// the grant: before the fix every jwt-bearer grant under a 900s policy failed
// with "requested TTL 3600s exceeds policy maximum 900s".
func TestPolicyMaxTTL_ShortensDefaultLifetime(t *testing.T) {
	pol := post(t, adminPath("/credential-policies"), map[string]any{
		"name":                uid("short-ttl-policy"),
		"max_ttl_seconds":     900,
		"allowed_grant_types": []string{"jwt_bearer"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, pol.StatusCode)
	policyID, _ := decode(t, pol)["id"].(string)
	require.NotEmpty(t, policyID)

	key := generateKey(t)
	externalID := uid("short-ttl-agent")
	reg := post(t, adminPath("/agents/register"), map[string]any{
		"name": externalID, "external_id": externalID, "created_by": "test-user",
		"public_key_pem": ecPublicKeyPEM(t, key), "credential_policy_id": policyID,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, reg.StatusCode)
	identity, _ := decode(t, reg)["identity"].(map[string]any)
	wimse, _ := identity["wimse_uri"].(string)
	require.NotEmpty(t, wimse)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":  buildAssertion(t, key, wimse),
	}, nil)
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%v", body)
	assert.EqualValues(t, 900, body["expires_in"], "the default lifetime is shortened to the policy maximum")
}
