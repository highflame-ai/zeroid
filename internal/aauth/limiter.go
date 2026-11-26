package aauth

import (
	"sync"
	"time"
)

// DefaultRequestsPerMinute bounds each limited key's Agent Provider requests
// when none is configured.
const DefaultRequestsPerMinute = 60

// limiter is a fixed-window request limit per key: a workload subject at
// /ap/token, a parent agent at /ap/subagent, a durable key at /ap/refresh.
// Keys are identities that have already authenticated, so a caller cannot
// spread itself over fresh keys (anyone can make an hwk key, so a limit on
// that would bound nothing), and an unauthenticated flood is left to the
// ingress.
//
// ponytail: in-process, so N replicas allow N times the limit; a shared
// store if that matters.
type limiter struct {
	perMinute int
	now       func() time.Time

	mu        sync.Mutex
	windows   map[string]*window
	nextPrune time.Time
}

type window struct {
	start time.Time
	count int
}

func newLimiter(perMinute int, now func() time.Time) *limiter {
	if perMinute <= 0 {
		perMinute = DefaultRequestsPerMinute
	}
	return &limiter{perMinute: perMinute, now: now, windows: map[string]*window{}}
}

// allow counts a request for key and reports whether it is within the limit,
// and if not, how long until the window resets.
func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !now.Before(l.nextPrune) {
		for k, w := range l.windows {
			if now.Sub(w.start) >= time.Minute {
				delete(l.windows, k)
			}
		}
		l.nextPrune = now.Add(time.Minute)
	}
	w, ok := l.windows[key]
	if !ok || now.Sub(w.start) >= time.Minute {
		w = &window{start: now}
		l.windows[key] = w
	}
	if w.count >= l.perMinute {
		return false, time.Minute - now.Sub(w.start)
	}
	w.count++
	return true, 0
}

// rateLimited is the refusal past the limit: 429 rate_limited with
// Retry-After (protocol draft, error codes).
func rateLimited(wait time.Duration) *bootstrapRefusal {
	secs := int((wait + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return &bootstrapRefusal{code: "rate_limited", status: 429, retryAfter: secs,
		description: "too many requests for this agent; retry later"}
}
