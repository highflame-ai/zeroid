package service

import (
	"context"
	"errors"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

func TestMemoPolicy(t *testing.T) {
	calls := 0
	fetch := func() (*domain.CredentialPolicy, error) {
		calls++
		return &domain.CredentialPolicy{ID: "p1", MaxTTLSeconds: 60}, nil
	}

	// Without a memo every call reaches the repository.
	for range 2 {
		if _, err := memoPolicy(context.Background(), "p1", fetch); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("no memo: %d fetches, want 2", calls)
	}

	// With one, a request fetches each policy once.
	calls = 0
	ctx := withPolicyMemo(context.Background())
	a, _ := memoPolicy(ctx, "p1", fetch)
	b, _ := memoPolicy(withPolicyMemo(ctx), "p1", fetch) // nesting keeps the same memo
	if calls != 1 {
		t.Fatalf("memo: %d fetches, want 1", calls)
	}
	// Callers get independent copies, as from the repository.
	a.MaxTTLSeconds = 1
	if b.MaxTTLSeconds != 60 {
		t.Fatal("memo handed out a shared pointer")
	}
	if c, _ := memoPolicy(ctx, "p1", fetch); c.MaxTTLSeconds != 60 {
		t.Fatal("caller mutation leaked into the memo")
	}

	// Failures are not memoized.
	calls = 0
	boom := errors.New("boom")
	fail := func() (*domain.CredentialPolicy, error) { calls++; return nil, boom }
	for range 2 {
		if _, err := memoPolicy(ctx, "missing", fail); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
	}
	if calls != 2 {
		t.Fatalf("failed fetches: %d, want 2", calls)
	}
}
