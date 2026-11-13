package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

func TestMemoPolicy(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	calls := 0
	fetch := func() (*domain.CredentialPolicy, error) {
		calls++
		e := exp
		return &domain.CredentialPolicy{
			ID: "p1", MaxTTLSeconds: 60, AllowedScopes: []string{"a", "b"},
			AllowedGrantTypes: []string{"client_credentials"}, UserGrantScopes: []string{"u"}, ExpiresAt: &e,
		}, nil
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

	// Callers get independent deep copies, slices and pointers included, so
	// one caller narrowing scopes in place can't change what another enforces.
	a.MaxTTLSeconds = 1
	a.AllowedScopes[0] = "mutated"
	a.AllowedGrantTypes[0] = "mutated"
	a.UserGrantScopes[0] = "mutated"
	*a.ExpiresAt = time.Time{}
	for _, p := range []*domain.CredentialPolicy{b, must(memoPolicy(ctx, "p1", fetch))} {
		if p.MaxTTLSeconds != 60 || p.AllowedScopes[0] != "a" || p.AllowedGrantTypes[0] != "client_credentials" ||
			p.UserGrantScopes[0] != "u" || !p.ExpiresAt.Equal(exp) {
			t.Fatalf("caller mutation leaked: %+v", p)
		}
	}

	// A write in the request clears the memo.
	calls = 0
	memoForget(ctx)
	_, _ = memoPolicy(ctx, "p1", fetch)
	if calls != 1 {
		t.Fatalf("after memoForget: %d fetches, want 1", calls)
	}

	// A policy put under another key (default -> by ID) is a hit.
	calls = 0
	memoPut(ctx, "by-id", must(fetch()))
	_, _ = memoPolicy(ctx, "by-id", fetch)
	if calls != 1 {
		t.Fatalf("memoPut: %d fetches, want 1 (the put itself)", calls)
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

// clonePolicy must deep-copy every reference-typed field. Adding one to
// domain.CredentialPolicy fails this until clonePolicy handles it.
func TestClonePolicyCoversReferenceFields(t *testing.T) {
	handled := map[string]bool{"AllowedGrantTypes": true, "AllowedScopes": true, "UserGrantScopes": true, "ExpiresAt": true}
	typ := reflect.TypeFor[domain.CredentialPolicy]()
	for i := range typ.NumField() {
		f := typ.Field(i)
		switch f.Type.Kind() {
		case reflect.Slice, reflect.Map, reflect.Pointer:
			if !handled[f.Name] {
				t.Errorf("CredentialPolicy.%s is a %s; deep-copy it in clonePolicy", f.Name, f.Type.Kind())
			}
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
