package dpop

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStore_Insert_HappyPath(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Insert(context.Background(), "jti-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if got := s.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1", got)
	}
}

func TestMemoryStore_Insert_Replay(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	if err := s.Insert(ctx, "jti-1", exp); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := s.Insert(ctx, "jti-1", exp)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("second insert: want ErrReplay; got %v", err)
	}
}

func TestMemoryStore_Insert_ExpiredEntryNotReplay(t *testing.T) {
	// An entry whose expiresAt has passed should be treated as gone — the same
	// jti can be re-inserted. (In practice the pruner removes it; here we
	// verify the lazy check in Insert handles it correctly even if pruning
	// hasn't run yet.)
	now := time.Now()
	s := NewMemoryStore(WithMemoryNow(func() time.Time { return now }))
	if err := s.Insert(context.Background(), "jti-1", now.Add(-time.Second)); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// Same jti, fresh expiry — should succeed because the old one is expired.
	if err := s.Insert(context.Background(), "jti-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("re-insert of expired jti: want nil; got %v", err)
	}
}

func TestMemoryStore_Insert_EmptyJTI(t *testing.T) {
	s := NewMemoryStore()
	err := s.Insert(context.Background(), "", time.Now().Add(time.Minute))
	if err == nil {
		t.Fatal("empty jti should be rejected")
	}
}

func TestMemoryStore_Prune_DropsExpired(t *testing.T) {
	now := time.Now()
	s := NewMemoryStore(WithMemoryNow(func() time.Time { return now }))
	// Insert 5 expired, 5 live.
	for i := 0; i < 5; i++ {
		if err := s.Insert(context.Background(), tag("expired", i), now.Add(-time.Second)); err != nil {
			t.Fatalf("Insert expired: %v", err)
		}
	}
	for i := 0; i < 5; i++ {
		if err := s.Insert(context.Background(), tag("live", i), now.Add(time.Hour)); err != nil {
			t.Fatalf("Insert live: %v", err)
		}
	}
	if got := s.Prune(); got != 5 {
		t.Fatalf("Prune returned %d; want 5", got)
	}
	if got := s.Len(); got != 5 {
		t.Fatalf("Len after Prune = %d; want 5", got)
	}
}

func TestMemoryStore_AmortizedPruning(t *testing.T) {
	now := time.Now()
	s := NewMemoryStore(
		WithMemoryNow(func() time.Time { return now }),
		WithAmortizedPruneEvery(4),
	)
	// First 3 inserts (all expired) — no pruning yet.
	for i := 0; i < 3; i++ {
		_ = s.Insert(context.Background(), tag("expired", i), now.Add(-time.Second))
	}
	if got := s.Len(); got != 3 {
		t.Fatalf("Len before threshold = %d, want 3", got)
	}
	// 4th insert triggers pruneLocked which collects all the expired ones (and
	// itself, since its expiry is also in the past) — Len drops to 0.
	_ = s.Insert(context.Background(), tag("expired", 3), now.Add(-time.Second))
	if got := s.Len(); got != 0 {
		t.Fatalf("Len after threshold = %d, want 0 (amortized prune should have run)", got)
	}
}

func TestMemoryStore_StartPruner_AndStop(t *testing.T) {
	now := time.Now()
	s := NewMemoryStore(
		WithMemoryNow(func() time.Time { return now }),
		WithAmortizedPruneEvery(0), // disable amortized pruning so only StartPruner runs
	)
	if err := s.Insert(context.Background(), "jti-x", now.Add(-time.Second)); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	stop := s.StartPruner(5 * time.Millisecond)
	defer stop()
	// Wait for at least one prune cycle.
	deadline := time.Now().Add(500 * time.Millisecond)
	for s.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.Len() != 0 {
		t.Fatalf("pruner did not collect expired entry: Len=%d", s.Len())
	}
}

func TestMemoryStore_StartPruner_DoubleStartPanics(t *testing.T) {
	s := NewMemoryStore()
	stop := s.StartPruner(time.Second)
	defer stop()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on double StartPruner")
		}
	}()
	_ = s.StartPruner(time.Second)
}

// TestMemoryStore_Concurrent_AtomicReplay is the load-bearing race test.
// N goroutines race to insert the same jti; exactly one must succeed and the
// rest must fail with ErrReplay. Run with -race.
func TestMemoryStore_Concurrent_AtomicReplay(t *testing.T) {
	s := NewMemoryStore()
	const N = 100
	var (
		wg        sync.WaitGroup
		successes atomic.Int32
		replays   atomic.Int32
		other     atomic.Int32
	)
	exp := time.Now().Add(time.Minute)
	start := make(chan struct{})

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // align all goroutines
			err := s.Insert(context.Background(), "shared-jti", exp)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrReplay):
				replays.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes.Load() != 1 {
		t.Fatalf("successes = %d; want 1 (atomicity violated)", successes.Load())
	}
	if replays.Load() != N-1 {
		t.Fatalf("replays = %d; want %d", replays.Load(), N-1)
	}
	if other.Load() != 0 {
		t.Fatalf("unexpected errors: %d", other.Load())
	}
}

func TestMemoryStore_Concurrent_DistinctJTIs(t *testing.T) {
	s := NewMemoryStore()
	const N = 1000
	var wg sync.WaitGroup
	exp := time.Now().Add(time.Minute)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.Insert(context.Background(), tag("jti", i), exp); err != nil {
				t.Errorf("Insert %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if s.Len() != N {
		t.Fatalf("Len = %d; want %d", s.Len(), N)
	}
}

func TestNullStore_NeverReplays(t *testing.T) {
	s := NullStore{}
	for i := 0; i < 3; i++ {
		if err := s.Insert(context.Background(), "always-the-same", time.Now()); err != nil {
			t.Fatalf("NullStore.Insert call %d: %v", i, err)
		}
	}
}

func tag(prefix string, n int) string {
	const hex = "0123456789abcdef"
	out := []byte(prefix + "-")
	if n == 0 {
		out = append(out, '0')
	}
	for n > 0 {
		out = append(out, hex[n&0xF])
		n >>= 4
	}
	return string(out)
}
