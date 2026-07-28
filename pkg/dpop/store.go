package dpop

import (
	"context"
	"sync"
	"time"
)

// ReplayStore is the durable ledger for observed proof jti values. Implements
// the RFC 9449 §11.1 anti-replay requirement: a proof's jti must not be
// honored more than once within the freshness window.
//
// Implementations must guarantee atomic check-and-insert — concurrent
// Insert calls for the same jti must result in exactly one nil return and
// every other return being ErrReplay. A non-atomic implementation (read,
// then write) is a TOCTOU bug that defeats the replay defense.
//
// Implementations should periodically prune entries with expiresAt < now to
// bound storage growth. The verifier never reads expired entries (it computes
// freshness from iat), so pruning is a storage-side concern.
type ReplayStore interface {
	// Insert records a previously-unseen jti. Returns ErrReplay (a *dpop.Error
	// with Code = CodeReplay) if the jti is already present and not yet
	// expired. Returns ErrStorageFailure (Code = CodeStorageFailure) wrapping
	// the underlying cause for storage-level failures.
	//
	// expiresAt should be set to iat + MaxAge by the caller — this is the
	// instant after which the entry may be safely garbage-collected.
	Insert(ctx context.Context, jti string, expiresAt time.Time) error
}

// MemoryStore is an in-process ReplayStore backed by a map. Safe for
// concurrent use. Suitable for tests, single-instance dev servers, and
// short-lived ephemeral services that can tolerate losing replay state on
// restart.
//
// Pruning runs lazily on Insert (amortized O(1)). For long-running processes
// with high jti volume, call StartPruner to add periodic eager cleanup.
//
// Not suitable for production multi-replica deployments — each replica would
// only know about jti values it has personally seen, allowing replay across
// replicas.
type MemoryStore struct {
	mu         sync.Mutex
	entries    map[string]time.Time
	nowFn      func() time.Time // injectable for tests
	pruneEvery int              // prune every N inserts; 0 disables amortized pruning
	insertN    int

	pruneStop chan struct{} // closed by StopPruner
}

// NewMemoryStore returns a fresh MemoryStore. Default amortized pruning runs
// every 1024 inserts; override with MemoryStoreOption configuration if needed.
func NewMemoryStore(opts ...MemoryStoreOption) *MemoryStore {
	m := &MemoryStore{
		entries:    make(map[string]time.Time),
		nowFn:      time.Now,
		pruneEvery: 1024,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// MemoryStoreOption configures a MemoryStore.
type MemoryStoreOption func(*MemoryStore)

// WithMemoryNow overrides the clock used by the store. Intended for tests.
func WithMemoryNow(now func() time.Time) MemoryStoreOption {
	return func(m *MemoryStore) { m.nowFn = now }
}

// WithAmortizedPruneEvery sets the insert interval for amortized pruning.
// Pass 0 to disable amortized pruning entirely (only StartPruner / explicit
// Prune calls will collect).
func WithAmortizedPruneEvery(n int) MemoryStoreOption {
	return func(m *MemoryStore) { m.pruneEvery = n }
}

// Insert implements ReplayStore.
func (m *MemoryStore) Insert(_ context.Context, jti string, expiresAt time.Time) error {
	if jti == "" {
		return wrap(CodeInvalidProof, "jti is empty", nil)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if prev, ok := m.entries[jti]; ok && prev.After(m.nowFn()) {
		return ErrReplay
	}
	m.entries[jti] = expiresAt
	m.insertN++
	if m.pruneEvery > 0 && m.insertN >= m.pruneEvery {
		m.pruneLocked()
		m.insertN = 0
	}
	return nil
}

// Prune drops all entries with expiresAt <= now. Safe to call at any time.
// Returns the number of entries pruned.
func (m *MemoryStore) Prune() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pruneLocked()
}

func (m *MemoryStore) pruneLocked() int {
	now := m.nowFn()
	dropped := 0
	for jti, exp := range m.entries {
		if !exp.After(now) {
			delete(m.entries, jti)
			dropped++
		}
	}
	return dropped
}

// Len returns the current entry count. Intended for tests and metrics.
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// StartPruner spawns a goroutine that calls Prune every interval. The
// returned stop function blocks until the pruner has exited.
//
// Calling StartPruner more than once on the same store is a programmer error
// and will panic.
func (m *MemoryStore) StartPruner(interval time.Duration) (stop func()) {
	m.mu.Lock()
	if m.pruneStop != nil {
		m.mu.Unlock()
		panic("dpop: MemoryStore pruner already started")
	}
	m.pruneStop = make(chan struct{})
	stopCh := m.pruneStop
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
				m.Prune()
			}
		}
	}()

	return func() {
		m.mu.Lock()
		if m.pruneStop != nil {
			close(m.pruneStop)
			m.pruneStop = nil
		}
		m.mu.Unlock()
		<-done
	}
}

// NullStore accepts every jti without recording. NEVER use in production —
// it disables RFC 9449's replay defense entirely. Provided for tests that
// want to focus on non-replay validation, and for benchmarks measuring
// non-store overhead.
type NullStore struct{}

// Insert implements ReplayStore by always returning nil. Does NOT detect
// replays — see the type docs.
func (NullStore) Insert(_ context.Context, _ string, _ time.Time) error { return nil }
