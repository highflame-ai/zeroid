package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// collectEvents returns a notifier that appends every delivered event to a
// mutex-guarded slice, plus an accessor for the captured events.
func collectEvents() (RevocationNotifierFunc, func() []RevocationEvent) {
	var mu sync.Mutex
	var got []RevocationEvent
	fn := func(_ context.Context, e RevocationEvent) error {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
		return nil
	}
	snapshot := func() []RevocationEvent {
		mu.Lock()
		defer mu.Unlock()
		out := make([]RevocationEvent, len(got))
		copy(out, got)
		return out
	}
	return fn, snapshot
}

func sampleEvents(n int) []RevocationEvent {
	out := make([]RevocationEvent, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, RevocationEvent{
			JTI:       "jti-" + string(rune('a'+i)),
			AccountID: "acct",
			ProjectID: "proj",
			Reason:    "test",
			RevokedAt: time.Now(),
		})
	}
	return out
}

// TestRevocationDispatcher_FiresOncePerEvent verifies the notifier is invoked
// exactly once per supplied event — the "N tokens ⇒ N events" contract that
// every cascade path relies on.
func TestRevocationDispatcher_FiresOncePerEvent(t *testing.T) {
	d := NewRevocationDispatcher()
	d.SetDispatchSync(true) // deterministic — no goroutine race in the assertion
	fn, snapshot := collectEvents()
	d.SetNotifier(fn)

	d.Dispatch(context.Background(), sampleEvents(3))

	got := snapshot()
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}
	seen := map[string]int{}
	for _, e := range got {
		seen[e.JTI]++
	}
	for jti, count := range seen {
		if count != 1 {
			t.Errorf("jti %q fired %d times, want exactly 1", jti, count)
		}
	}
}

// TestRevocationDispatcher_NoNotifierIsNoOp verifies that with no notifier
// installed (the default), Dispatch is a no-op and hasNotifier reports false —
// the backward-compatible "nobody is listening" path.
func TestRevocationDispatcher_NoNotifierIsNoOp(t *testing.T) {
	d := NewRevocationDispatcher()
	if d.hasNotifier() {
		t.Fatal("fresh dispatcher must report no notifier")
	}
	// Must not panic and must do nothing observable.
	d.Dispatch(context.Background(), sampleEvents(2))

	// Installing then clearing returns to the no-op state.
	fn, _ := collectEvents()
	d.SetNotifier(fn)
	if !d.hasNotifier() {
		t.Fatal("notifier should be installed")
	}
	d.SetNotifier(nil)
	if d.hasNotifier() {
		t.Fatal("nil notifier must clear installation")
	}
}

// TestRevocationDispatcher_ErrorLoggedNotPropagated verifies that a notifier
// returning an error does not panic or surface — Dispatch has no error return,
// and a failing notifier must not stop subsequent events from firing.
func TestRevocationDispatcher_ErrorLoggedNotPropagated(t *testing.T) {
	d := NewRevocationDispatcher()
	d.SetDispatchSync(true)

	var calls int32
	d.SetNotifier(func(_ context.Context, _ RevocationEvent) error {
		atomic.AddInt32(&calls, 1)
		return errors.New("subscriber down")
	})

	// Dispatch returns nothing — the error is swallowed (logged) inside.
	d.Dispatch(context.Background(), sampleEvents(2))

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("a failing notifier must still fire for every event: got %d, want 2", got)
	}
}

// TestRevocationDispatcher_AsyncDoesNotBlock verifies the production default
// (async dispatch) returns immediately even when the notifier blocks, and that
// the events are eventually delivered.
func TestRevocationDispatcher_AsyncDoesNotBlock(t *testing.T) {
	d := NewRevocationDispatcher()
	// async is the default; do NOT call SetDispatchSync.

	release := make(chan struct{})
	done := make(chan struct{})
	var fired int32
	d.SetNotifier(func(_ context.Context, _ RevocationEvent) error {
		<-release // block until the test lets go
		atomic.AddInt32(&fired, 1)
		return nil
	})

	start := time.Now()
	go func() {
		d.Dispatch(context.Background(), sampleEvents(1))
		close(done)
	}()

	// Dispatch must return promptly even though the notifier is blocked.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Dispatch did not return while notifier was blocked — async dispatch is broken")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Dispatch took %s; async path should return near-instantly", elapsed)
	}

	// Release the notifier and confirm eventual delivery.
	close(release)
	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&fired) == 0 {
		select {
		case <-deadline:
			t.Fatal("notifier never fired after release")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestRevocationDispatcher_StopHaltsDispatch verifies that after Stop() the
// dispatcher no-ops new dispatches rather than launching goroutines against a
// cancelled lifecycle context.
func TestRevocationDispatcher_StopHaltsDispatch(t *testing.T) {
	d := NewRevocationDispatcher()
	d.SetDispatchSync(true)
	var fired int32
	d.SetNotifier(func(_ context.Context, _ RevocationEvent) error {
		atomic.AddInt32(&fired, 1)
		return nil
	})

	d.Stop()
	d.Stop() // idempotent

	d.Dispatch(context.Background(), sampleEvents(3))
	if got := atomic.LoadInt32(&fired); got != 0 {
		t.Fatalf("dispatch after Stop must no-op: notifier fired %d times", got)
	}
}

// TestReservedClaims_BlockAuthorizationClaims documents and enforces the
// security invariant for the role/privilege_scope claims: `role` and `privilege_scope` must be
// reserved so they can never be injected via additional_claims on any grant.
func TestReservedClaims_BlockAuthorizationClaims(t *testing.T) {
	for _, claim := range []string{"role", "privilege_scope"} {
		if !reservedClaims[claim] {
			t.Errorf("claim %q MUST be reserved (privilege-escalation guard)", claim)
		}
	}
}
