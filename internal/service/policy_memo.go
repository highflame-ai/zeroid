package service

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/highflame-ai/zeroid/domain"
)

// A token request resolved the same credential policy up to three times: the
// grant resolving the identity's governing policy, IssueCredential enforcing
// it, and cibaApproveListed checking its scopes. The memo makes those one
// read. It lives on the request's context, so nothing outlives the request
// and a policy edit is seen by the very next request, as before. A write
// inside the request (UpdatePolicy, DeletePolicy) clears it.
type policyMemoKey struct{}

// errNoDefaultPolicy marks a tenant with no default policy yet, so the miss
// isn't memoized and EnsureDefaultPolicy goes on to create one.
var errNoDefaultPolicy = errors.New("no default credential policy")

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
// miss. Each caller gets its own deep copy, as it did from the repository.
// Errors are not memoized. The lock is held across fetch so concurrent
// lookups in one request share a single read.
func memoPolicy(ctx context.Context, key string, fetch func() (*domain.CredentialPolicy, error)) (*domain.CredentialPolicy, error) {
	memo, ok := ctx.Value(policyMemoKey{}).(*policyMemo)
	if !ok {
		return fetch()
	}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if p, hit := memo.m[key]; hit {
		return clonePolicy(&p), nil
	}
	p, err := fetch()
	if err != nil {
		return nil, err
	}
	memo.m[key] = *clonePolicy(p)
	return p, nil
}

// memoPut records p under key, so a policy found one way (the tenant default)
// is a hit when next looked up another way (by ID).
func memoPut(ctx context.Context, key string, p *domain.CredentialPolicy) {
	if memo, ok := ctx.Value(policyMemoKey{}).(*policyMemo); ok && p != nil {
		memo.mu.Lock()
		memo.m[key] = *clonePolicy(p)
		memo.mu.Unlock()
	}
}

// memoForget empties ctx's memo after a policy write in the same request.
func memoForget(ctx context.Context) {
	if memo, ok := ctx.Value(policyMemoKey{}).(*policyMemo); ok {
		memo.mu.Lock()
		clear(memo.m)
		memo.mu.Unlock()
	}
}

func policyByIDKey(accountID, projectID, id string) string {
	return accountID + "\x00" + projectID + "\x00" + id
}

func defaultPolicyKey(accountID, projectID string) string {
	return accountID + "\x00" + projectID + "\x00default"
}

// clonePolicy copies p including its slices and pointers, so no two callers
// share mutable state. TestClonePolicyCoversReferenceFields fails when a new
// reference-typed field is added to domain.CredentialPolicy without a line here.
func clonePolicy(p *domain.CredentialPolicy) *domain.CredentialPolicy {
	c := *p
	c.AllowedGrantTypes = slices.Clone(p.AllowedGrantTypes)
	c.AllowedScopes = slices.Clone(p.AllowedScopes)
	c.UserGrantScopes = slices.Clone(p.UserGrantScopes)
	if p.ExpiresAt != nil {
		t := *p.ExpiresAt
		c.ExpiresAt = &t
	}
	return &c
}
