package database

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForPing_SucceedsImmediately(t *testing.T) {
	calls := atomic.Int32{}
	ping := func(ctx context.Context) error {
		calls.Add(1)
		return nil
	}
	if err := waitForPing(context.Background(), ping, WaitOptions{}); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 ping, got %d", got)
	}
}

func TestWaitForPing_RetriesUntilSuccess(t *testing.T) {
	calls := atomic.Int32{}
	ping := func(ctx context.Context) error {
		// Simulate "connection refused" for the first 3 attempts, then succeed.
		// This mirrors the kind-cluster cold-start where postgres binds 5432
		// a few seconds after authn comes up.
		if calls.Add(1) <= 3 {
			return errors.New("connection refused")
		}
		return nil
	}
	opts := WaitOptions{
		Budget:         5 * time.Second,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
		AttemptTimeout: 1 * time.Second,
	}
	start := time.Now()
	if err := waitForPing(context.Background(), ping, opts); err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("expected 4 pings (3 fails + success), got %d", got)
	}
	// 10 + 20 + 40 = 70ms of backoff, plus a few ms of test overhead.
	// The test would fail at >2s if budget logic is wrong.
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Fatalf("retries took %s; expected ~70ms", elapsed)
	}
}

func TestWaitForPing_GivesUpAfterBudget(t *testing.T) {
	calls := atomic.Int32{}
	pingErr := errors.New("connection refused")
	ping := func(ctx context.Context) error {
		calls.Add(1)
		return pingErr
	}
	opts := WaitOptions{
		Budget:         200 * time.Millisecond,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     30 * time.Millisecond,
		AttemptTimeout: 50 * time.Millisecond,
	}
	start := time.Now()
	err := waitForPing(context.Background(), ping, opts)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error after budget exhausted, got nil")
	}
	// Final error must wrap the last ping error so call sites can log a
	// clean cause.
	if !errors.Is(err, pingErr) {
		t.Fatalf("expected error to wrap %q, got: %v", pingErr, err)
	}
	// We give up around the budget; allow modest CI jitter on either side.
	if elapsed < 150*time.Millisecond || elapsed > 600*time.Millisecond {
		t.Fatalf("budget enforcement off: elapsed=%s budget=200ms", elapsed)
	}
	// Should have made several attempts before giving up.
	if got := calls.Load(); got < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", got)
	}
}

func TestWaitForPing_RespectsParentCancellation(t *testing.T) {
	ping := func(ctx context.Context) error {
		return errors.New("connection refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	opts := WaitOptions{
		Budget:         10 * time.Second, // long budget — would mask cancel if not respected
		InitialBackoff: 5 * time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		AttemptTimeout: 100 * time.Millisecond,
	}
	start := time.Now()
	err := waitForPing(ctx, ping, opts)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("did not honor parent cancellation: elapsed=%s", elapsed)
	}
}
