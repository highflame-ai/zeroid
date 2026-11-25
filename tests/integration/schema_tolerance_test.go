package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A rolling deploy or a rollback runs this version against a schema that a
// newer version's migration has already extended. The expiry sweep claims a
// row with UPDATE ... RETURNING *, so a column this version does not know must
// not break the scan: the deactivation is already committed by then, and the
// cascade that revokes the identity's tokens would be skipped for good.
func TestExpirySweepToleratesAColumnFromANewerSchema(t *testing.T) {
	ctx := context.Background()
	_, err := testDB.ExecContext(ctx,
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS zz_newer_schema_probe TEXT")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(),
			"ALTER TABLE identities DROP COLUMN IF EXISTS zz_newer_schema_probe")
	})

	reg := registerAgent(t, uid("newer-schema"))
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)["access_token"].(string)
	require.True(t, introspect(t, token)["active"].(bool), "token should be active before the sweep")

	stampExpiredInDB(t, reg.AgentID)
	testZeroIDServer.RunCleanupOnce(ctx)

	idResp, err := doRaw(t, http.MethodGet, adminPath("/identities/"+reg.AgentID), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, idResp.StatusCode)
	assert.Equal(t, "deactivated", decode(t, idResp)["status"], "the sweep must deactivate the expired identity")
	assert.False(t, introspect(t, token)["active"].(bool),
		"the sweep's cascade must revoke the token even when the schema has a column this version does not know")
}
