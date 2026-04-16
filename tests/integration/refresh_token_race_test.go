package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefreshTokenConcurrentRotation closes the RFC 6749 §6 rotation race:
// two concurrent POSTs with the same refresh token must not both issue a
// successor. Exactly one request wins and receives a new token; the rest are
// rejected with invalid_grant.
//
// Before the fix, the read-check-revoke sequence ran under READ COMMITTED
// (despite the comment claiming "serializable"), so both rotations passed the
// active check before either committed the revocation — both then minted new
// tokens, bypassing reuse detection entirely.
func TestRefreshTokenConcurrentRotation(t *testing.T) {
	const concurrency = 10

	// Acquire a single refresh token via the authorization_code flow.
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-race-001", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	refreshToken := decode(t, resp)["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)

	var (
		successes int32
		failures  int32
		wg        sync.WaitGroup
	)
	start := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			status := rotateRaw(t, refreshToken)
			if status == http.StatusOK {
				atomic.AddInt32(&successes, 1)
			} else {
				atomic.AddInt32(&failures, 1)
			}
		}()
	}

	close(start) // release all goroutines at once
	wg.Wait()

	// Security-critical invariant: exactly one successor minted.
	assert.Equal(t, int32(1), atomic.LoadInt32(&successes),
		"exactly one concurrent rotation should succeed")
	assert.Equal(t, int32(concurrency-1), atomic.LoadInt32(&failures),
		"all other concurrent rotations should be rejected")
}

// TestRefreshTokenReuseRevokesFamily verifies family revocation cascades when
// reuse is detected: replaying an already-rotated refresh token must invalidate
// not only the replayed token but every successor in the family (rt2 and
// beyond). Complements TestRefreshTokenRotation, which only checks that the
// replayed token itself is rejected.
func TestRefreshTokenReuseRevokesFamily(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-reuse-001", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rt1 := decode(t, resp)["refresh_token"].(string)

	// First rotation: succeeds, yields rt2.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt1,
		"client_id":     testMCPClientID,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rt2 := decode(t, resp)["refresh_token"].(string)
	require.NotEmpty(t, rt2)

	// Replay rt1 — already revoked → reuse detected → family revoked.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt1,
		"client_id":     testMCPClientID,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_grant", decode(t, resp)["error"])

	// rt2 must also be dead now — the family was revoked as a unit.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt2,
		"client_id":     testMCPClientID,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"rt2 must be revoked once reuse was detected on its sibling rt1")
}

// rotateRaw issues a refresh_token grant request directly without going through
// the require-heavy post helper, so it is safe to call from goroutines. Returns
// the HTTP status code, or 0 if the request could not be made (surfaced via
// t.Errorf so a real transport failure doesn't masquerade as a silent miss).
func rotateRaw(t *testing.T, refreshToken string) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     testMCPClientID,
	})
	if err != nil {
		t.Errorf("marshal refresh request: %v", err)
		return 0
	}
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/oauth2/token", bytes.NewReader(body))
	if err != nil {
		t.Errorf("build refresh request: %v", err)
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("execute refresh request: %v", err)
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}
