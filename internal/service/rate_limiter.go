package service

import (
	"context"
	"sync"
	"time"
)

// RateLimiter gates a request keyed by an opaque string. Implementations
// must be safe for concurrent use.
//
// Result shape:
//   - (true, 0, nil)            request permitted
//   - (false, retryAfter, nil)  request rejected; retryAfter is the hint
//     surfaced via the Retry-After header, rounded up to whole seconds
//     (RFC 7231 §7.1.3)
//   - (_, _, err)               backend itself failed; the caller decides
//     fail-open vs fail-closed
type RateLimiter interface {
	Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error)
	// Stop releases resources held by the limiter (goroutines, connection
	// pools). Idempotent.
	Stop()
}

// TokenBucketLimiter is an in-process token-bucket RateLimiter. Buckets are
// keyed by string and self-pruning so unbounded keyspaces (e.g. login_hint)
// cannot grow memory without bound. Per-instance only — multi-replica
// deployments should plug a shared-store implementation in via
// Server.SetBackchannelRateLimiters.
type TokenBucketLimiter struct {
	// Capacity is the burst size. A fresh bucket starts full.
	Capacity float64
	// RefillPerSec is the steady-state allowance. For "N requests per
	// minute" use N/60.
	RefillPerSec float64
	// IdleTTL bounds how long an unused bucket lingers before the reaper
	// drops it. Defaults to 10× the time to refill a full bucket so a
	// bucket cannot be reaped while it would still observe drained state
	// on the next request.
	IdleTTL time.Duration

	// now is overridable for deterministic tests; defaults to time.Now.
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucketState

	stop     chan struct{}
	stopOnce sync.Once
}

var _ RateLimiter = (*TokenBucketLimiter)(nil)

type bucketState struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

// NewTokenBucketLimiter starts the background reaper; callers must Stop()
// it during shutdown. Returns nil when capacity or refillPerSec is
// non-positive — the call site treats nil as disabled.
func NewTokenBucketLimiter(capacity, refillPerSec float64) *TokenBucketLimiter {
	if capacity <= 0 || refillPerSec <= 0 {
		return nil
	}
	// 1-minute floor keeps fast limiters from reaping themselves under
	// steady traffic.
	refillSeconds := capacity / refillPerSec
	idleTTL := time.Duration(refillSeconds*10) * time.Second
	if idleTTL < time.Minute {
		idleTTL = time.Minute
	}
	l := &TokenBucketLimiter{
		Capacity:     capacity,
		RefillPerSec: refillPerSec,
		IdleTTL:      idleTTL,
		now:          time.Now,
		buckets:      make(map[string]*bucketState),
		stop:         make(chan struct{}),
	}
	go l.reapLoop()
	return l
}

// Allow is concurrency-safe. The in-memory implementation never returns a
// non-nil error; the signature carries one to satisfy the RateLimiter
// interface (network-backed implementations can fail).
func (l *TokenBucketLimiter) Allow(_ context.Context, key string) (bool, time.Duration, error) {
	if l == nil {
		return true, 0, nil
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		// Start full so a legitimate first request isn't punished.
		b = &bucketState{tokens: l.Capacity, lastRefill: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastRefill).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.RefillPerSec
			if b.tokens > l.Capacity {
				b.tokens = l.Capacity
			}
			b.lastRefill = now
		}
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens -= 1
		return true, 0, nil
	}
	// Fractional tokens carry into the wait so a second 429 in a burst
	// doesn't advertise a needlessly long Retry-After.
	missing := 1 - b.tokens
	waitSec := missing / l.RefillPerSec
	// Round up — RFC 7231 §7.1.3 requires integer delta-seconds.
	retryAfter := time.Duration(waitSec*float64(time.Second)) + time.Second - 1
	retryAfter = retryAfter.Truncate(time.Second)
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return false, retryAfter, nil
}

// Stop is idempotent and nil-safe.
func (l *TokenBucketLimiter) Stop() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() { close(l.stop) })
}

func (l *TokenBucketLimiter) reapLoop() {
	// IdleTTL/2 cadence keeps reaper lock contention with Allow negligible.
	interval := l.IdleTTL / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.reap()
		}
	}
}

func (l *TokenBucketLimiter) reap() {
	cutoff := l.now().Add(-l.IdleTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}
