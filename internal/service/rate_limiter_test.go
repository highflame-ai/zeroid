package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock returns a controllable time source for deterministic limiter
// tests. Advance() moves the clock forward; concurrent reads via the now()
// closure are safe.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{t: start} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestLimiter builds a limiter and immediately stops its background
// reaper — tests drive elapsed time via the fake clock, so the reaper
// goroutine would be a flakiness source if left running.
func newTestLimiter(t *testing.T, capacity, refillPerSec float64, clock *fakeClock) *TokenBucketLimiter {
	t.Helper()
	l := NewTokenBucketLimiter(capacity, refillPerSec)
	l.Stop()
	l.now = clock.now
	return l
}

// TestTokenBucketLimiter_BurstAllowance proves a fresh bucket permits exactly
// `capacity` requests in immediate succession, then rejects with a positive
// Retry-After.
func TestTokenBucketLimiter_BurstAllowance(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	l := newTestLimiter(t, 5, 5.0/60.0, clock) // 5/min

	for i := 1; i <= 5; i++ {
		ok, retry, err := l.Allow(context.Background(), "k")
		if err != nil {
			t.Fatalf("burst slot %d: unexpected error: %v", i, err)
		}
		if !ok || retry != 0 {
			t.Fatalf("burst slot %d: want (true, 0); got (%v, %v)", i, ok, retry)
		}
	}
	ok, retry, err := l.Allow(context.Background(), "k")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("6th request must be rejected once the bucket is empty")
	}
	if retry < time.Second {
		t.Fatalf("Retry-After must be ≥ 1s per RFC 7231 §7.1.3; got %v", retry)
	}
}

// TestTokenBucketLimiter_RefillsOverTime proves a bucket regenerates a token
// after exactly capacity/refillPerSec seconds.
func TestTokenBucketLimiter_RefillsOverTime(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	// 1 token/sec — single-token refill window is exactly 1 second.
	l := newTestLimiter(t, 1, 1.0, clock)

	if ok, _, _ := l.Allow(context.Background(), "k"); !ok {
		t.Fatal("first request must succeed")
	}
	if ok, _, _ := l.Allow(context.Background(), "k"); ok {
		t.Fatal("second immediate request must be rejected")
	}
	clock.advance(time.Second)
	if ok, _, _ := l.Allow(context.Background(), "k"); !ok {
		t.Fatal("after 1s the bucket must have refilled one token")
	}
}

// TestTokenBucketLimiter_KeysAreIndependent proves two different keys share
// no bucket state — important because per-client and per-user buckets both
// use the same limiter type and a leak would let abuse on one dimension
// silently consume the other dimension's allowance.
func TestTokenBucketLimiter_KeysAreIndependent(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	l := newTestLimiter(t, 1, 1.0, clock)

	if ok, _, _ := l.Allow(context.Background(), "alice"); !ok {
		t.Fatal("alice's first request must succeed")
	}
	if ok, _, _ := l.Allow(context.Background(), "bob"); !ok {
		t.Fatal("bob's first request must succeed (independent bucket)")
	}
	if ok, _, _ := l.Allow(context.Background(), "alice"); ok {
		t.Fatal("alice's second request must be rejected (her bucket is empty)")
	}
}

// TestTokenBucketLimiter_NilReceiverAllows confirms the nil-receiver
// "disabled" contract — callers can pass nil when config sets the limit to
// 0 without sprinkling guards through the call site.
func TestTokenBucketLimiter_NilReceiverAllows(t *testing.T) {
	var l *TokenBucketLimiter
	ok, retry, err := l.Allow(context.Background(), "anything")
	if err != nil {
		t.Fatalf("nil limiter must not error; got %v", err)
	}
	if !ok || retry != 0 {
		t.Fatalf("nil limiter must always allow; got (%v, %v)", ok, retry)
	}
	l.Stop() // must not panic
}

// TestTokenBucketLimiter_DisabledOnZeroConfig confirms the constructor
// returns nil when either parameter is non-positive — the kill-switch
// guarantee operators rely on.
func TestTokenBucketLimiter_DisabledOnZeroConfig(t *testing.T) {
	cases := []struct {
		capacity, refill float64
	}{
		{0, 5.0 / 60.0},
		{5, 0},
		{-1, 1},
		{1, -1},
	}
	for _, c := range cases {
		if got := NewTokenBucketLimiter(c.capacity, c.refill); got != nil {
			got.Stop()
			t.Errorf("NewTokenBucketLimiter(%v, %v) = non-nil; want nil (disabled)", c.capacity, c.refill)
		}
	}
}

// TestTokenBucketLimiter_RetryAfterRoundsUp proves Retry-After is never
// shorter than the actual refill wait — clients honouring the header must
// not poll back before a token is available, otherwise the 429 storm
// continues indefinitely.
func TestTokenBucketLimiter_RetryAfterRoundsUp(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	// 30/min = 0.5 tokens/sec — a single missing token takes 2s to refill.
	l := newTestLimiter(t, 1, 0.5, clock)
	_, _, _ = l.Allow(context.Background(), "k")
	_, retry, _ := l.Allow(context.Background(), "k")
	if retry < 2*time.Second {
		t.Fatalf("Retry-After must round up to ≥ 2s for a 0.5 tokens/sec refill; got %v", retry)
	}
}

// failingLimiter is a RateLimiter that always returns a backend error.
// Used to exercise the fail-open path in BackchannelService.checkRateLimit.
type failingLimiter struct {
	err   error
	calls int
}

func (f *failingLimiter) Allow(_ context.Context, _ string) (bool, time.Duration, error) {
	f.calls++
	return false, 0, f.err
}
func (f *failingLimiter) Stop() {}

// TestRateLimiterInterface_FailOpen documents the contract the
// BackchannelService relies on: an implementation returning a non-nil error
// signals a backend failure, and the call site must NOT block the request
// (fail-open). This test exercises the failingLimiter shape itself — the
// service-level fail-open assertion lives in the integration test where
// Server wiring is in scope.
func TestRateLimiterInterface_FailOpen(t *testing.T) {
	want := errors.New("redis: connection refused")
	l := &failingLimiter{err: want}

	ok, retry, err := l.Allow(context.Background(), "any-key")
	if !errors.Is(err, want) {
		t.Fatalf("want %v; got %v", want, err)
	}
	if ok {
		t.Fatal("a backend-error response should not assert 'allowed'; the caller decides whether to fail open")
	}
	if retry != 0 {
		t.Fatalf("backend-error retryAfter should be zero (no advice possible); got %v", retry)
	}
	if l.calls != 1 {
		t.Fatalf("limiter called %d times; want 1", l.calls)
	}
}

// TestRateLimiterInterface_Compatibility is a compile-time-style check that
// any future RateLimiter implementation can be passed where the interface
// is expected. The compile-time `var _ RateLimiter = ...` assertion in
// rate_limiter.go already does this for TokenBucketLimiter; this test
// guarantees the same for an ad-hoc stub, ensuring the interface stays
// small enough that third-party implementations are not coupled to
// internal types.
func TestRateLimiterInterface_Compatibility(t *testing.T) {
	var _ RateLimiter = (*TokenBucketLimiter)(nil)
	var _ RateLimiter = (*failingLimiter)(nil)
}
