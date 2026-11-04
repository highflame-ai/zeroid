package integration_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serverLog collects the in-process server's log lines. The server writes from
// its own goroutines while the test reads, hence the lock.
type serverLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *serverLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *serverLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// lines decodes every line written so far.
func (l *serverLog) lines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewBufferString(l.String()))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var line map[string]any
		require.NoError(t, json.Unmarshal(sc.Bytes(), &line), "log line %q", sc.Text())
		out = append(out, line)
	}
	require.NoError(t, sc.Err())
	return out
}

// find returns the lines with this message whose fields match want.
func (l *serverLog) find(t *testing.T, message string, want map[string]any) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range l.lines(t) {
		if line["message"] != message {
			continue
		}
		match := true
		for k, v := range want {
			if line[k] != v {
				match = false
				break
			}
		}
		if match {
			out = append(out, line)
		}
	}
	return out
}

// captureServerLog sends the server's log lines, Info and above, to a serverLog
// for the rest of the test. The suite runs the server at warn, which would drop
// the Info lines these tests read. Safe to mutate shared state: no integration
// test calls t.Parallel().
func captureServerLog(t *testing.T) *serverLog {
	t.Helper()
	sl := &serverLog{}
	origLogger, origLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(sl)
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	t.Cleanup(func() {
		log.Logger = origLogger
		zerolog.SetGlobalLevel(origLevel)
	})
	return sl
}

// TestAuthorizationCodeRedemptionLog pins the server's record of an
// authorization_code redemption: one line, tied to the token request by its
// request_id, that says how the client authenticated and that PKCE held, while
// neither the code nor the code_verifier appears anywhere in the log.
func TestAuthorizationCodeRedemptionLog(t *testing.T) {
	redeem := func(t *testing.T, userID string, headers map[string]string) (verifier, code string, resp *http.Response) {
		t.Helper()
		verifier, challenge := buildPKCEPair(t)
		code = buildAuthCode(t, testCLIClientID, userID, testRedirectURI, challenge, []string{"data:read"})
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     testCLIClientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
		}, headers)
		return verifier, code, resp
	}

	t.Run("a public client that sends no credentials", func(t *testing.T) {
		logs := captureServerLog(t)
		verifier, code, resp := redeem(t, "user-log-001", nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		token := decode(t, resp)

		lines := logs.find(t, "authorization code redeemed", nil)
		require.Len(t, lines, 1)
		line := lines[0]
		assert.Equal(t, testCLIClientID, line["client_id"])
		assert.Equal(t, false, line["cimd"])
		assert.Equal(t, "none", line["client_auth"])
		assert.Equal(t, false, line["sent_authorization_header"])
		assert.Equal(t, false, line["sent_client_secret"])
		assert.Equal(t, false, line["sent_client_assertion"])
		assert.Equal(t, "S256", line["code_challenge_method"])
		assert.Equal(t, "verified", line["code_verifier"])
		assert.Equal(t, testAccountID, line["account_id"])
		assert.Equal(t, testProjectID, line["project_id"])
		assert.Equal(t, "user-log-001", line["user_id"])
		assert.Equal(t, token["jti"], line["jti"], "names the access token the response carried")

		// The same request_id as the token request's own request.start line.
		starts := logs.find(t, "request.start", map[string]any{"path": "/oauth2/token"})
		require.Len(t, starts, 1)
		assert.NotEmpty(t, line["request_id"])
		assert.Equal(t, starts[0]["request_id"], line["request_id"])

		raw := logs.String()
		assert.NotContains(t, raw, verifier, "the code_verifier must never be logged")
		assert.NotContains(t, raw, code, "the authorization code must never be logged")
	})

	t.Run("an Authorization header is recorded, and authenticates nothing", func(t *testing.T) {
		logs := captureServerLog(t)
		_, _, resp := redeem(t, "user-log-002", map[string]string{"Authorization": "Bearer not-a-client-credential"})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		lines := logs.find(t, "authorization code redeemed", nil)
		require.Len(t, lines, 1)
		assert.Equal(t, true, lines[0]["sent_authorization_header"])
		assert.Equal(t, false, lines[0]["sent_client_secret"])
		assert.Equal(t, "none", lines[0]["client_auth"])
		assert.NotContains(t, logs.String(), "not-a-client-credential", "the header's value must never be logged")
	})

	t.Run("a refused redemption writes no line", func(t *testing.T) {
		logs := captureServerLog(t)
		_, challenge := buildPKCEPair(t)
		wrongVerifier, _ := buildPKCEPair(t)
		code := buildAuthCode(t, testCLIClientID, "user-log-003", testRedirectURI, challenge, []string{"data:read"})
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     testCLIClientID,
			"code":          code,
			"code_verifier": wrongVerifier,
			"redirect_uri":  testRedirectURI,
		}, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		_ = resp.Body.Close()

		assert.Empty(t, logs.find(t, "authorization code redeemed", nil))
		assert.NotContains(t, logs.String(), wrongVerifier, "a refused code_verifier must never be logged either")
	})
}
