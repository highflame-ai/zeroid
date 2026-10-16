package service

import (
	"context"
	"sync"

	"github.com/highflame-ai/zeroid/domain"
)

// A token request resolved the same credential policy up to three times: the
// grant resolving the identity's governing policy, IssueCredential enforcing
// it, and cibaApproveListed checking its scopes. The memo makes those one
// read. It lives on the request's context, so nothing outlives the request
// and a policy edit is seen by the very next request, as before.
type policyMemoKey struct{}

type policyMemo struct {
	mu sync.Mutex
	m  map[string]domain.CredentialPolicy
}

// withPolicyMemo returns ctx carrying a fresh per-request policy memo, or ctx
// unchanged if it already has one.
func withPolicyMemo(ctx context.Context) context.Context {
	if _, ok := ctx.Value(policyMemoKey{}).(*policyMemo); ok {
		return ctx
	}
	return context.WithValue(ctx, policyMemoKey{}, &policyMemo{m: map[string]domain.CredentialPolicy{}})
}

// memoPolicy returns the policy for key from ctx's memo, calling fetch on a
// miss. Each caller gets its own copy, as it did from the repository. Errors
// are not memoized.
func memoPolicy(ctx context.Context, key string, fetch func() (*domain.CredentialPolicy, error)) (*domain.CredentialPolicy, error) {
	memo, ok := ctx.Value(policyMemoKey{}).(*policyMemo)
	if !ok {
		return fetch()
	}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if p, hit := memo.m[key]; hit {
		return &p, nil
	}
	p, err := fetch()
	if err != nil {
		return nil, err
	}
	memo.m[key] = *p
	return p, nil
}
