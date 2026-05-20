package integration_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// TestCIBA_BcAuthorize_PerClientRateLimit covers the per-client token bucket
// on /oauth2/bc-authorize (issue #139 acceptance criteria):
//
//   - 20 rapid requests as one client → first N succeed, the rest receive
//     HTTP 429 with error="slow_down" and a Retry-After header.
//   - The rate-limit check fires BEFORE the BackchannelNotifier dispatches —
//     a client that exceeds its cap cannot spam end-user notifications.
//   - The rate-limit check fires BEFORE persistence — the
//     backchannel_auth_requests table does not accumulate rows from the
//     rejected requests.
func TestCIBA_BcAuthorize_PerClientRateLimit(t *testing.T) {
	clientID := uid("ciba-rl-perclient")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	// Drive limits to a small, deterministic value so 20 requests cross the
	// threshold inside a single sub-second test step. Per-user is set high
	// so this test isolates the per-client path; the next test inverts it.
	const allowed = 5
	testZeroIDServer.SetBackchannelRateLimits(allowed, 1000)
	t.Cleanup(func() {
		// Restore production defaults for subsequent tests.
		testZeroIDServer.SetBackchannelRateLimits(10, 5)
	})

	var notifyCount int64
	testZeroIDServer.SetBackchannelNotifier(func(_ context.Context, _ zeroid.BackchannelNotification) error {
		atomic.AddInt64(&notifyCount, 1)
		return nil
	})
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	preRows := countBackchannelRowsForClient(t, clientID)

	const (
		burst     = 20
		loginHint = "ratelimit-victim@example.com"
	)

	var (
		successes  int
		rateLimits int
	)
	for i := 0; i < burst; i++ {
		resp := post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id":  clientID,
			"account_id": testAccountID,
			"project_id": testProjectID,
			"login_hint": loginHint,
			"scope":      "openid",
		}, nil)

		switch resp.StatusCode {
		case http.StatusOK:
			successes++
			_ = resp.Body.Close()
		case http.StatusTooManyRequests:
			rateLimits++
			body := decode(t, resp)
			require.Equal(t, "slow_down", body["error"],
				"429 responses must carry error=slow_down per CIBA Core §11; body=%v", body)

			ra := resp.Header.Get("Retry-After")
			require.NotEmpty(t, ra, "429 responses must include a Retry-After header (RFC 7231 §7.1.3)")
			raSecs, err := strconv.Atoi(ra)
			require.NoError(t, err, "Retry-After must be integer delta-seconds; got %q", ra)
			require.GreaterOrEqual(t, raSecs, 1, "Retry-After must be ≥ 1s")
		default:
			t.Fatalf("unexpected status %d on bc-authorize request %d", resp.StatusCode, i)
		}
	}

	// First N succeed, remainder are rate-limited — the primary acceptance
	// criterion. Token-bucket bursting means we get exactly `allowed`
	// successes when traffic arrives faster than the refill rate (which a
	// sub-second loop trivially does).
	require.Equal(t, allowed, successes,
		"first %d requests must succeed (token-bucket capacity)", allowed)
	require.Equal(t, burst-allowed, rateLimits,
		"remaining %d requests must be rate-limited with 429", burst-allowed)

	// Rate limit fires BEFORE the notifier — attacker cannot spam end-user
	// notifications even with high request volume.
	require.Equal(t, int64(allowed), atomic.LoadInt64(&notifyCount),
		"notifier must fire only for the %d allowed requests; rejected requests must not invoke the notifier", allowed)

	// Rate limit fires BEFORE persistence — the table is protected from
	// the DoS-via-pending-rows attack surface.
	postRows := countBackchannelRowsForClient(t, clientID)
	require.Equal(t, int64(allowed), postRows-preRows,
		"backchannel_auth_requests must accumulate only the %d allowed rows; rejected requests must not persist", allowed)
}

// TestCIBA_BcAuthorize_PerUserRateLimit covers the per-user (login_hint) cap:
// a single user cannot be spammed across many clients in the same tenant.
//
// Two distinct clients post to the same login_hint. The per-user cap is
// driven below the per-client cap so the per-user limiter fires first.
func TestCIBA_BcAuthorize_PerUserRateLimit(t *testing.T) {
	clientA := uid("ciba-rl-userA")
	clientB := uid("ciba-rl-userB")
	registerTestOAuthClient(clientA, []string{"client_credentials"})
	registerTestOAuthClient(clientB, []string{"client_credentials"})

	// per-user = 3, per-client = high → per-user trips before per-client.
	const userCap = 3
	testZeroIDServer.SetBackchannelRateLimits(1000, userCap)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelRateLimits(10, 5)
	})

	const (
		burst     = 10
		loginHint = "shared-victim@example.com"
	)

	successes := 0
	rejections := 0
	for i := 0; i < burst; i++ {
		// Alternate between clients so the per-client bucket is never
		// approached and only the per-user bucket can be the cause of any
		// 429.
		cid := clientA
		if i%2 == 1 {
			cid = clientB
		}
		resp := post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id":  cid,
			"account_id": testAccountID,
			"project_id": testProjectID,
			"login_hint": loginHint,
		}, nil)

		switch resp.StatusCode {
		case http.StatusOK:
			successes++
		case http.StatusTooManyRequests:
			rejections++
			body := decode(t, resp)
			require.Equal(t, "slow_down", body["error"], "body=%v", body)
		default:
			t.Fatalf("unexpected status %d on iteration %d", resp.StatusCode, i)
		}
		_ = resp.Body.Close()
	}

	require.Equal(t, userCap, successes,
		"per-user cap must throttle requests targeting one login_hint regardless of client_id")
	require.Equal(t, burst-userCap, rejections)
}

// TestCIBA_BcAuthorize_CustomRateLimiter proves the extension point:
// deployers can plug a custom zeroid.RateLimiter into the bc-authorize
// pipeline via Server.SetBackchannelRateLimiters without any changes to
// zeroid internals. The same hook is what production deployments use to
// swap in a Redis-backed (or any other shared-store) limiter for multi-
// instance correctness.
//
// This test installs a deny-everything stub on the per-client dimension
// and asserts every request gets 429 + slow_down + Retry-After through the
// deployer-supplied limiter. The reverse case (backend error → fail open)
// is asserted in TestCIBA_BcAuthorize_CustomRateLimiter_FailOpen.
func TestCIBA_BcAuthorize_CustomRateLimiter(t *testing.T) {
	clientID := uid("ciba-rl-custom")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	stub := &recordingLimiter{
		decide: func(_ context.Context, _ string) (bool, time.Duration, error) {
			return false, 7 * time.Second, nil
		},
	}
	testZeroIDServer.SetBackchannelRateLimiters(stub, nil) // per-user disabled
	t.Cleanup(func() {
		// Restore the default in-memory backend at production defaults.
		testZeroIDServer.SetBackchannelRateLimits(10, 5)
	})

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "custom-limiter@example.com",
	}, nil)
	defer resp.Body.Close()

	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode,
		"custom limiter denial must surface as 429")
	body := decode(t, resp)
	require.Equal(t, "slow_down", body["error"])
	require.Equal(t, "7", resp.Header.Get("Retry-After"),
		"custom limiter's retryAfter must be plumbed verbatim through the Retry-After header")
	require.Equal(t, int64(1), stub.calls(), "custom limiter must be invoked exactly once per request")
}

// TestCIBA_BcAuthorize_TenantBypassClosed proves that varying tenant IDs in
// the request body does NOT reset the per-client rate-limit bucket. The
// previous design keyed buckets on (client_id, account_id, project_id),
// which let an attacker bypass the cap by supplying random tenant values.
// The bucket key is now just client_id.
func TestCIBA_BcAuthorize_TenantBypassClosed(t *testing.T) {
	clientID := uid("ciba-rl-tenant-bypass")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	const allowed = 3
	testZeroIDServer.SetBackchannelRateLimits(allowed, 1000)
	t.Cleanup(func() { testZeroIDServer.SetBackchannelRateLimits(10, 5) })

	// Fire `allowed+3` requests, each with a unique account_id + project_id
	// pair. If the limiter keyed on the tenant tuple, every request would
	// look like a fresh bucket and all would succeed (the bypass). With the
	// fix, only the first `allowed` succeed.
	successes := 0
	rejections := 0
	for i := 0; i < allowed+3; i++ {
		resp := post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id":  clientID,
			"account_id": "acct-bypass-" + strconv.Itoa(i),
			"project_id": "proj-bypass-" + strconv.Itoa(i),
			"login_hint": "victim-" + strconv.Itoa(i) + "@example.com",
		}, nil)
		switch resp.StatusCode {
		case http.StatusOK:
			successes++
		case http.StatusTooManyRequests:
			rejections++
		default:
			t.Fatalf("unexpected status %d on iteration %d", resp.StatusCode, i)
		}
		_ = resp.Body.Close()
	}

	require.Equal(t, allowed, successes,
		"per-client cap must hold even when account_id/project_id vary per request")
	require.Equal(t, 3, rejections)
}

// TestCIBA_BcAuthorize_SetRateLimitersSelfStop proves the limiter passed
// into Server.SetBackchannelRateLimiters is NOT stopped when it equals the
// existing instance. The default in-memory impl's reaper goroutine cannot
// be restarted, so an unconditional Stop would brick a re-installed limiter.
func TestCIBA_BcAuthorize_SetRateLimitersSelfStop(t *testing.T) {
	stub := &recordingLimiter{
		decide: func(_ context.Context, _ string) (bool, time.Duration, error) {
			return true, 0, nil
		},
	}

	testZeroIDServer.SetBackchannelRateLimiters(stub, nil)
	t.Cleanup(func() { testZeroIDServer.SetBackchannelRateLimits(10, 5) })

	// Install the same instance again. The implementation must NOT call
	// Stop() on a limiter it's reinstalling.
	testZeroIDServer.SetBackchannelRateLimiters(stub, nil)

	stub.mu.Lock()
	stopped := stub.stopped
	stub.mu.Unlock()
	require.False(t, stopped,
		"limiter must not be Stop()ped when SetBackchannelRateLimiters reinstalls the same instance")
}

// TestCIBA_BcAuthorize_CustomRateLimiter_FailOpen proves the documented
// fail-open contract: when a deployer-supplied RateLimiter returns a
// backend error (e.g. Redis unreachable), the service permits the request
// rather than locking out legitimate traffic. Critical for production
// deployments — the rate limiter must never DoS the authentication service
// it is supposed to protect.
func TestCIBA_BcAuthorize_CustomRateLimiter_FailOpen(t *testing.T) {
	clientID := uid("ciba-rl-failopen")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	stub := &recordingLimiter{
		decide: func(_ context.Context, _ string) (bool, time.Duration, error) {
			return false, 0, errors.New("simulated backend outage")
		},
	}
	testZeroIDServer.SetBackchannelRateLimiters(stub, nil)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelRateLimits(10, 5)
	})

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "failopen@example.com",
	}, nil)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"limiter backend error must fail open — the auth service must not be locked out by a dependency outage")
	require.Equal(t, int64(1), stub.calls())
}

// recordingLimiter is a deployer-supplied zeroid.RateLimiter used to drive
// the extension-point integration tests. The decide closure is invoked
// inside Allow so each test can return the precise (allowed, retryAfter,
// err) triple it needs.
type recordingLimiter struct {
	mu      sync.Mutex
	nCalls  int64
	stopped bool
	decide  func(ctx context.Context, key string) (bool, time.Duration, error)
}

// Compile-time guarantee the test stub satisfies the public RateLimiter
// contract. Catches signature drift if the interface evolves.
var _ zeroid.RateLimiter = (*recordingLimiter)(nil)

func (r *recordingLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	atomic.AddInt64(&r.nCalls, 1)
	return r.decide(ctx, key)
}

func (r *recordingLimiter) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
}

func (r *recordingLimiter) calls() int64 { return atomic.LoadInt64(&r.nCalls) }

// countBackchannelRowsForClient returns the current row count in
// backchannel_auth_requests for the given client_id. Used to verify that
// rate-limited bc-authorize requests do not persist rows (criterion: rate
// check happens before insertion).
func countBackchannelRowsForClient(t *testing.T, clientID string) int64 {
	t.Helper()
	var n int64
	err := testDB.NewSelect().
		TableExpr("backchannel_auth_requests").
		ColumnExpr("count(*)").
		Where("client_id = ?", clientID).
		Scan(context.Background(), &n)
	require.NoError(t, err)
	return n
}
