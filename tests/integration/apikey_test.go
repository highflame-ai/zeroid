package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyProductFilter(t *testing.T) {
	// Create keys with different products — no identity_id needed.
	// EnsureServiceIdentity auto-provisions a service identity per product.
	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"

	respA := post(t, "/api/v1/api-keys", map[string]any{
		"name":    "analytics-key",
		"product": "analytics",
	}, headers)
	require.Equal(t, http.StatusCreated, respA.StatusCode)

	respB := post(t, "/api/v1/api-keys", map[string]any{
		"name":    "monitoring-key",
		"product": "monitoring",
	}, headers)
	require.Equal(t, http.StatusCreated, respB.StatusCode)

	// Second analytics key — should reuse the same service identity.
	respC := post(t, "/api/v1/api-keys", map[string]any{
		"name":    "analytics-key-2",
		"product": "analytics",
	}, headers)
	require.Equal(t, http.StatusCreated, respC.StatusCode)

	// Filter by product=analytics — should return 2 keys sharing the same identity.
	resp := get(t, "/api/v1/api-keys?product=analytics", adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	keys := body["keys"].([]any)
	assert.Equal(t, 2, len(keys), "should return exactly 2 analytics keys")

	for _, k := range keys {
		m := k.(map[string]any)
		assert.Equal(t, "analytics", m["product"], "should only return analytics keys")
	}

	id1 := keys[0].(map[string]any)["identity_id"].(string)
	id2 := keys[1].(map[string]any)["identity_id"].(string)
	assert.Equal(t, id1, id2, "both analytics keys should share the same service identity")

	// Filter by product=monitoring — should return 1 key.
	resp = get(t, "/api/v1/api-keys?product=monitoring", adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	keys = body["keys"].([]any)
	assert.Equal(t, 1, len(keys), "should return exactly 1 monitoring key")
	assert.Equal(t, "monitoring", keys[0].(map[string]any)["product"])

	// No filter — returns all keys (at least 3 from this test + any from other tests).
	resp = get(t, "/api/v1/api-keys", adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	allKeys := body["keys"].([]any)
	assert.GreaterOrEqual(t, len(allKeys), 3, "should return at least all three created keys")
}
