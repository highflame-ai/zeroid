package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// TestDelegationChain_LineageCapRefusalNamesTheChain: a token may be
// delegated from at most postgres.MaxLineageDepth credentials. Re-scoping
// links a new credential to its parent without adding depth, so a chain can
// reach that cap at depth 1. The refusal says the chain is too long, in the
// invalid_grant family the other lineage refusals use, and does not claim an
// identity is suspended or deactivated: none is.
func TestDelegationChain_LineageCapRefusalNamesTheChain(t *testing.T) {
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)
	root, _ := tn.workloadRoot(t, policyID, scopes)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	actor := tn.register(t, uid("rescope"), policyID, ecPublicKeyPEM(t, key), scopes)

	// The root and the first exchange are the chain's first two credentials;
	// every re-scope adds one more without adding depth.
	status, body := exchangeWithKey(t, root, key, actor, scopes)
	require.Equal(t, http.StatusOK, status, "%v", body)
	token := body["access_token"].(string)
	for n := 3; n <= postgres.MaxLineageDepth+1; n++ {
		status, body = exchangeWithKey(t, token, key, actor, scopes)
		require.Equal(t, http.StatusOK, status, "credential %d of the chain is within the cap: %v", n, body)
		require.EqualValues(t, 1, decodeJWTPayload(t, body["access_token"].(string))["delegation_depth"], "re-scoping adds no depth")
		token = body["access_token"].(string)
	}

	status, body = exchangeWithKey(t, token, key, actor, scopes)
	assert.Equal(t, http.StatusBadRequest, status, "a token delegated from more than %d credentials is refused: %v", postgres.MaxLineageDepth, body)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.NotEqual(t, "identity is suspended or deactivated", body["error_description"], "no identity is stopped")
	assert.Contains(t, body["error_description"], "delegation chain")
	assert.Contains(t, body["error_description"], fmt.Sprint(postgres.MaxLineageDepth))

	// Every identity in the chain is still usable: a fresh chain from the
	// same root is issued.
	status, body = exchangeWithKey(t, root, key, actor, scopes)
	assert.Equal(t, http.StatusOK, status, "%v", body)

	// The deepest token issued is reached by revoking the root: the cascade
	// walk goes as far down as issuance lets the chain grow.
	require.True(t, introspect(t, token)["active"].(bool), "the deepest token is active before the root is revoked")
	resp := post(t, "/oauth2/token/revoke", map[string]any{"token": root}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
	assert.False(t, introspect(t, token)["active"].(bool), "revoking the root revokes the %dth credential of its chain", postgres.MaxLineageDepth+1)
}

// TestCascadeFunctionsWalkToMaxLineageDepth reads the cascade revocation
// functions a migrated database actually runs, so a later migration that
// redefines one of them, however it spells the definition, cannot change
// its depth bound without this failing.
func TestCascadeFunctionsWalkToMaxLineageDepth(t *testing.T) {
	bound := regexp.MustCompile(`chain\.depth\s*<\s*(\d+)`)
	for _, fn := range []string{"revoke_credentials_cascade", "revoke_credential_cascade", "revoke_credentials_by_owner"} {
		var src []string
		require.NoError(t, testDB.NewRaw("SELECT prosrc FROM pg_proc WHERE proname = ?", fn).Scan(context.Background(), &src), fn)
		require.Len(t, src, 1, "%s is defined once", fn)
		matches := bound.FindAllStringSubmatch(src[0], -1)
		require.NotEmpty(t, matches, "%s: no chain.depth bound found; update this test if the walk changed shape", fn)
		for _, m := range matches {
			assert.Equal(t, strconv.Itoa(postgres.MaxLineageDepth), m[1], "%s walks to chain.depth < %s, but MaxLineageDepth is %d", fn, m[1], postgres.MaxLineageDepth)
		}
	}
}
