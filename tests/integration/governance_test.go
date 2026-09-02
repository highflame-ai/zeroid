package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Governance tests use a per-test tenant so that DRM rows (which are
// append-only and tenant-scoped via the AuthorizeDelegation check) do
// not leak into the shared TestMain Postgres and reject token_exchange
// in other tests that run later in the suite.

func govTenant(t *testing.T) (accountID, projectID string, headers map[string]string) {
	t.Helper()
	suffix := uid("gov")
	accountID = "acct-" + suffix
	projectID = "proj-" + suffix
	headers = map[string]string{
		"X-Account-ID": accountID,
		"X-Project-ID": projectID,
	}
	return
}

func govRegisterIdentity(t *testing.T, headers map[string]string, externalID string, scopes []string, publicKeyPEM string) (id, wimseURI string) {
	t.Helper()
	body := map[string]any{
		"external_id":    externalID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": scopes,
	}
	if publicKeyPEM != "" {
		body["public_key_pem"] = publicKeyPEM
	}
	resp := post(t, adminPath("/identities"), body, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	raw := decode(t, resp)
	return raw["id"].(string), raw["wimse_uri"].(string)
}

func govRegisterOAuthClient(t *testing.T, headers map[string]string, clientID string, scopes []string) (cid, secret string) {
	t.Helper()
	resp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":    clientID,
		"name":         clientID + "-client",
		"confidential": true,
		"grant_types":  []string{"client_credentials"},
		"scopes":       scopes,
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	raw := decode(t, resp)
	client := raw["client"].(map[string]any)
	return client["client_id"].(string), raw["client_secret"].(string)
}

func govIntrospect(t *testing.T, headers map[string]string, tokenStr string) map[string]any {
	t.Helper()
	resp := post(t, "/oauth2/token/introspect", map[string]string{"token": tokenStr}, headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decode(t, resp)
}

// TestGovernanceBinding_TokenExchange — happy path. DRM permits the pair;
// the issued JWT carries the four governance claims and introspection
// surfaces them.
func TestGovernanceBinding_TokenExchange(t *testing.T) {
	accountID, projectID, headers := govTenant(t)

	orchID := uid("gov-orch")
	_, orchWIMSE := govRegisterIdentity(t, headers, orchID, []string{"data:read"}, "")
	orchClientID, orchSecret := govRegisterOAuthClient(t, headers, orchID, []string{"data:read"})

	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("gov-sub")
	_, subWIMSE := govRegisterIdentity(t, headers, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))

	drmResp := post(t, adminPath("/governance/decision-rights-matrix"), map[string]any{
		"version":      "1.0.0",
		"effective_at": time.Now().UTC().Add(-time.Second),
		"allowed_delegations": []map[string]any{
			{"from": orchWIMSE, "to": subWIMSE},
		},
	}, headers)
	require.Equal(t, http.StatusCreated, drmResp.StatusCode)
	drmBody := decode(t, drmResp)
	drmHash := drmBody["hash"].(string)
	require.True(t, strings.HasPrefix(drmHash, "sha256:"))

	catResp := post(t, adminPath("/governance/constraint-catalog"), map[string]any{
		"version":      "2026-05-18T00:00:00Z",
		"effective_at": time.Now().UTC().Add(-time.Second),
		"document":     json.RawMessage(`{"policies":["permit(principal,action,resource)"]}`),
	}, headers)
	require.Equal(t, http.StatusCreated, catResp.StatusCode)
	catBody := decode(t, catResp)
	catHash := catBody["hash"].(string)
	require.True(t, strings.HasPrefix(catHash, "sha256:"))

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    accountID,
		"project_id":    projectID,
		"client_id":     orchClientID,
		"client_secret": orchSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	actorAssertion := buildAssertion(t, subKey, subWIMSE)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DRM-permitted exchange must succeed")
	delegatedToken := decode(t, resp)["access_token"].(string)

	result := govIntrospect(t, headers, delegatedToken)
	assert.True(t, result["active"].(bool))
	assert.Equal(t, "1.0.0", result["drm_version"])
	assert.Equal(t, drmHash, result["drm_hash"])
	assert.Equal(t, "2026-05-18T00:00:00Z", result["constraint_catalog_version"])
	assert.Equal(t, catHash, result["constraint_catalog_hash"])
}

// TestGovernanceBinding_UnauthorizedDelegation — DRM allows a different
// `to` pattern than the actor's WIMSE URI; exchange must be rejected.
func TestGovernanceBinding_UnauthorizedDelegation(t *testing.T) {
	accountID, projectID, headers := govTenant(t)

	orchID := uid("gov-orch-deny")
	_, orchWIMSE := govRegisterIdentity(t, headers, orchID, []string{"data:read"}, "")
	orchClientID, orchSecret := govRegisterOAuthClient(t, headers, orchID, []string{"data:read"})

	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("gov-sub-deny")
	_, subWIMSE := govRegisterIdentity(t, headers, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))

	drmResp := post(t, adminPath("/governance/decision-rights-matrix"), map[string]any{
		"version":      "deny-1.0",
		"effective_at": time.Now().UTC().Add(-time.Second),
		"allowed_delegations": []map[string]any{
			{"from": orchWIMSE, "to": "spiffe://example.test/never-matches/*"},
		},
	}, headers)
	require.Equal(t, http.StatusCreated, drmResp.StatusCode)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    accountID,
		"project_id":    projectID,
		"client_id":     orchClientID,
		"client_secret": orchSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	actorAssertion := buildAssertion(t, subKey, subWIMSE)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestGovernanceBinding_NoConfigBackwardCompat — a fresh tenant with no
// DRM/catalog row still completes token_exchange exactly like pre-#59
// ZeroID and the issued token has none of the governance claims.
func TestGovernanceBinding_NoConfigBackwardCompat(t *testing.T) {
	accountID, projectID, headers := govTenant(t)

	orchID := uid("gov-bc-orch")
	_, _ = govRegisterIdentity(t, headers, orchID, []string{"data:read"}, "")
	orchClientID, orchSecret := govRegisterOAuthClient(t, headers, orchID, []string{"data:read"})

	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("gov-bc-sub")
	_, subWIMSE := govRegisterIdentity(t, headers, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    accountID,
		"project_id":    projectID,
		"client_id":     orchClientID,
		"client_secret": orchSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	actorAssertion := buildAssertion(t, subKey, subWIMSE)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "exchange must succeed when no DRM is configured")
	delegatedToken := decode(t, resp)["access_token"].(string)

	result := govIntrospect(t, headers, delegatedToken)
	_, hasDRM := result["drm_hash"]
	_, hasCat := result["constraint_catalog_hash"]
	assert.False(t, hasDRM)
	assert.False(t, hasCat)
}
