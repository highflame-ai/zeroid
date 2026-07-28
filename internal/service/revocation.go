package service

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// RevocationEvent is the internal payload delivered to a RevocationNotifierFunc.
// It mirrors the public zeroid.RevocationEvent shape — the top-level
// Server.SetRevocationNotifier hook wraps the public type into this one so the
// service layer stays decoupled from the top-level package's type names (the
// same indirection used for BackchannelNotification).
type RevocationEvent struct {
	JTI        string
	IdentityID string
	AccountID  string
	ProjectID  string
	ExpiresAt  time.Time
	Reason     string
	RevokedAt  time.Time
}

// RevocationNotifierFunc is the internal alias for the public
// zeroid.RevocationNotifier signature. Kept service-package-local so that
// internal callers (CredentialService, RefreshTokenService) don't need to
// import the top-level package.
type RevocationNotifierFunc func(ctx context.Context, e RevocationEvent) error

// revocationNotifyTimeout bounds each detached notifier delivery. Matches the
// backchannel notifier dispatch budget — long enough for a Redis publish or a
// webhook round-trip, short enough that a hung subscriber can't pin a goroutine
// to the server's lifecycle context forever.
const revocationNotifyTimeout = 10 * time.Second

// revocationDispatchConcurrency bounds how many notifier deliveries run at once
// within a single Dispatch call. Delivery is concurrent (so a large cascade's
// last deny-set entry still lands within a bounded freshness window instead of
// queuing behind slow predecessors), but an identity deactivation can cascade
// to a very large number of credentials — an unbounded goroutine-per-event
// fan-out would spawn thousands of simultaneous notifier calls (e.g. Redis
// PUBLISHes) and exhaust connections/goroutines. This semaphore caps the burst
// while keeping enough parallelism that the tail stays well inside budget.
const revocationDispatchConcurrency = 32

// RevocationDispatcher owns the deployer-supplied RevocationNotifier and the
// async-dispatch machinery shared by every revocation path. A single instance
// is constructed in server wiring and handed to both CredentialService (RFC
// 7009 revoke, RevokeCredential, RevokeAllActiveForIdentity, CAE cascade) and
// RefreshTokenService (refresh-token reuse revocation) so one
// Server.SetRevocationNotifier call wires up all of them.
//
// The design deliberately mirrors BackchannelService's notifier plumbing:
//   - notifier + dispatchAsync guarded by mu (RWMutex); request handlers read
//     under RLock so notifier installation never serialises the hot path.
//   - svcCtx/svcCancel: detached goroutines parent on svcCtx (not the inbound
//     request ctx) so a client disconnect can't cancel an already-committed
//     revocation's fan-out; Server.Shutdown calls Stop() to wind them down on
//     graceful shutdown instead of leaking past the HTTP listener close.
//   - dispatchAsync is flipped to false only by tests (SetDispatchSync) so they
//     can assert on the emitted events without goroutine races; production
//     always dispatches asynchronously.
type RevocationDispatcher struct {
	mu           sync.RWMutex
	notifier     RevocationNotifierFunc
	dispatchSync bool // overridable for tests; default async

	svcCtx    context.Context
	svcCancel context.CancelFunc
}

// NewRevocationDispatcher constructs a dispatcher with a Background-derived
// lifecycle context (so test harnesses that never call Start still get a
// working notifier path, matching BackchannelService).
func NewRevocationDispatcher() *RevocationDispatcher {
	svcCtx, svcCancel := context.WithCancel(context.Background())
	return &RevocationDispatcher{
		svcCtx:    svcCtx,
		svcCancel: svcCancel,
	}
}

// SetNotifier wires the deployer's RevocationNotifier. Safe to call any time
// after construction; concurrent reads use RLock so revocation handlers don't
// serialise behind notifier installation. Passing nil clears the notifier
// (revocation becomes a no-op fan-out).
func (d *RevocationDispatcher) SetNotifier(fn RevocationNotifierFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notifier = fn
}

// SetDispatchSync forces synchronous dispatch. Tests use this so they can
// deterministically assert on emitted events without goroutine races.
// Production must keep this false (the default) so notifier latency cannot
// block the request that caused the revocation.
func (d *RevocationDispatcher) SetDispatchSync(sync bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dispatchSync = sync
}

// Stop cancels the dispatcher's lifecycle context, signalling in-flight
// detached notifier goroutines to wind down. Idempotent. Server.Shutdown calls
// this so graceful shutdown does not leak goroutines past the HTTP listener
// close. After Stop, new dispatches no-op rather than launching goroutines
// against a cancelled context.
func (d *RevocationDispatcher) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.svcCancel != nil {
		d.svcCancel()
		d.svcCancel = nil
		d.svcCtx = nil
	}
}

// hasNotifier reports whether a notifier is installed. Used by callers to skip
// enumerating affected credentials (a DB round-trip) when nobody is listening —
// the no-notifier path must stay exactly as cheap as before this hook existed.
func (d *RevocationDispatcher) hasNotifier() bool {
	if d == nil {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.notifier != nil
}

// Dispatch fires the notifier once for each supplied event. Runs on a detached
// goroutine by default (one goroutine per Dispatch call, iterating events in
// order) so notifier latency never blocks the request path. The inbound
// request's ctx is intentionally NOT carried into the dispatch: deliveries
// parent on the dispatcher's long-lived svcCtx so a client disconnect can't
// cancel a fan-out for an already-committed revocation. Graceful shutdown still
// cancels in-flight deliveries via Server.Shutdown -> Stop().
//
// Notifier errors are logged at warn level and never propagated — the
// revocation has already committed; a failed fan-out must not surface as a
// request failure.
func (d *RevocationDispatcher) Dispatch(_ context.Context, events []RevocationEvent) {
	if d == nil || len(events) == 0 {
		return
	}

	// Single RLock snapshot of all shared state the dispatch path needs,
	// preventing a Stop() from racing between two separate acquisitions and
	// leaving a half-stale view (notifier installed, svcCtx already nil).
	d.mu.RLock()
	fn := d.notifier
	syncDispatch := d.dispatchSync
	parent := d.svcCtx
	d.mu.RUnlock()

	if fn == nil || parent == nil {
		return
	}

	deliver := func() {
		// Deliver concurrently: a single revocation can cascade to many JTIs
		// (identity deactivation + delegated descendants), and the embedder's
		// notifier may do network I/O (e.g. a Redis publish). Sequential
		// delivery would queue later events behind slower predecessors, pushing
		// the last deny-set entry past a bounded freshness window. The
		// notifier is documented concurrent-safe, so fan out and join. wg.Wait
		// preserves the synchronous-dispatch contract tests rely on.
		var wg sync.WaitGroup
		sem := make(chan struct{}, revocationDispatchConcurrency)
		for _, e := range events {
			// Stop spawning once the dispatcher's lifecycle context is cancelled
			// (graceful shutdown) — don't leak goroutines past Stop().
			if parent.Err() != nil {
				break
			}
			sem <- struct{}{} // bound concurrency; blocks (backpressure) when the burst is full
			wg.Add(1)
			go func(ev RevocationEvent) {
				defer wg.Done()
				defer func() { <-sem }()
				dctx, cancel := context.WithTimeout(parent, revocationNotifyTimeout)
				defer cancel()
				if err := fn(dctx, ev); err != nil {
					// A cancelled parent during shutdown is expected, not a
					// notifier fault — don't emit a spurious warning for it.
					if parent.Err() != nil {
						return
					}
					log.Warn().
						Err(err).
						Str("jti", ev.JTI).
						Str("reason", ev.Reason).
						Msg("revocation notifier returned error")
				}
			}(e)
		}
		wg.Wait()
	}

	if syncDispatch {
		deliver()
		return
	}
	go deliver()
}
