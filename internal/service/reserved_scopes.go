package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// ReservedScopes are scope prefixes the deployer keeps for its own APIs
// (Highflame reserves "highflame."). ZeroID knows no names; the deployer sets
// them with Server.SetReservedScopes. With none set, nothing here applies.
//
// A reserved scope is:
//   - written onto an API key only in a context marked WithReservedScopeWrite
//     (APIKeyService.CreateKey);
//   - issued only on the api_key grant, only when the key's own row lists it,
//     only from a key linked to a service identity with a usable creator (so
//     owner_user_id names that creator), and only after the deployer's
//     authorizer allows it;
//   - refused by IssueCredential on every other path, so no grant, exchange or
//     unbounded ceiling can mint one.
//
// Tokens carrying one are capped at the configured lifetime, which bounds how
// long an authorizer's "no" takes to bite.
type ReservedScopes struct {
	mu        sync.RWMutex
	prefixes  []string
	authorize ReservedScopeAuthorizer
	maxTTL    int // seconds; 0 = no extra cap
}

// ReservedScopeGrant is what the authorizer sees for one api_key exchange.
type ReservedScopeGrant struct {
	AccountID string
	ProjectID string
	APIKeyID  string
	CreatedBy string
	Scopes    []string // the reserved scopes about to be issued
}

// ReservedScopeAuthorizer decides an api_key exchange that would issue
// reserved scopes (Highflame: is the key's creator still an org owner or
// admin). Return an error wrapping ErrReservedScopeDenied to refuse: the grant
// fails with invalid_grant and that error's text. Any other error (a lookup
// that failed) fails it closed with a generic server_error, so internal
// detail never reaches the client. It must honour ctx.
type ReservedScopeAuthorizer func(ctx context.Context, g ReservedScopeGrant) error

// ErrReservedScopeWriteNotTrusted is returned when a create-key request lists
// a reserved scope outside a WithReservedScopeWrite context. Handlers map it
// to 403.
var ErrReservedScopeWriteNotTrusted = errors.New(
	"reserved scopes can be written onto an API key only by the deployer's trusted path")

// ErrReservedScopeDenied is what a ReservedScopeAuthorizer wraps to refuse.
var ErrReservedScopeDenied = errors.New("reserved scopes denied")

// reservedScopeTimeout bounds one authorizer call.
const reservedScopeTimeout = 5 * time.Second

// Set configures the prefixes, the authorizer and the lifetime cap. Prefixes
// without an authorizer are refused, so a wiring mistake cannot issue
// reserved scopes unchecked. Empty prefixes turn the feature off.
func (r *ReservedScopes) Set(prefixes []string, authorize ReservedScopeAuthorizer, maxTTL time.Duration) error {
	clean := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if p = strings.TrimSpace(p); p != "" {
			clean = append(clean, p)
		}
	}
	if len(clean) > 0 && authorize == nil {
		return errors.New("reserved scope prefixes need an authorizer")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prefixes, r.authorize, r.maxTTL = clean, authorize, int(maxTTL.Seconds())
	return nil
}

// in returns the reserved scopes among scopes. Nil-safe.
func (r *ReservedScopes) in(scopes []string) []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for _, s := range scopes {
		for _, p := range r.prefixes {
			if strings.HasPrefix(s, p) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// SetReservedScopes shares the deployer's reserved scopes with the key service.
func (s *APIKeyService) SetReservedScopes(r *ReservedScopes) { s.reserved = r }

// SetReservedScopes shares the deployer's reserved scopes with issuance.
func (s *CredentialService) SetReservedScopes(r *ReservedScopes) { s.reserved = r }

func (r *ReservedScopes) authorizer() (ReservedScopeAuthorizer, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.authorize, r.maxTTL
}

type reservedScopeWriteKey struct{}

// WithReservedScopeWrite marks ctx as the deployer's trusted path, which may
// write reserved scopes onto an API key (Highflame: Admin's internal path,
// after it has checked the person's role).
func WithReservedScopeWrite(ctx context.Context) context.Context {
	return context.WithValue(ctx, reservedScopeWriteKey{}, true)
}

// ReservedScopeWrite reports whether ctx carries WithReservedScopeWrite.
func ReservedScopeWrite(ctx context.Context) bool {
	v, _ := ctx.Value(reservedScopeWriteKey{}).(bool)
	return v
}

// authorizeReservedScopes applies the api_key grant's reserved-scope rules to
// issue and, when they pass, marks it authorized and caps its lifetime. A
// grant with no reserved scopes is untouched and never calls the authorizer,
// so ordinary key exchanges gain no dependency on the deployer.
func (s *OAuthService) authorizeReservedScopes(ctx context.Context, issue *IssueRequest, sk *domain.APIKey, identity *domain.Identity) error {
	reserved := s.credentialSvc.reserved
	scopes := reserved.in(issue.Scopes)
	if len(scopes) == 0 {
		return nil
	}
	for _, sc := range scopes {
		if !slices.Contains(sk.Scopes, sc) {
			return oauthBadRequest(oautherror.InvalidScope, fmt.Sprintf("%q is issued only from a key that lists it", sc))
		}
	}
	creator := apiKeyOwnerOverride(identity, sk)
	if creator == "" {
		return oauthBadRequest(oautherror.InvalidScope, "reserved scopes are issued only from a service key with a recorded creator")
	}
	authorize, maxTTL := reserved.authorizer()
	if authorize == nil {
		return oauthServerError("no reserved-scope authorizer configured", nil)
	}
	actx, cancel := context.WithTimeout(ctx, reservedScopeTimeout)
	defer cancel()
	if err := authorize(actx, ReservedScopeGrant{
		AccountID: sk.AccountID, ProjectID: sk.ProjectID, APIKeyID: sk.ID, CreatedBy: creator, Scopes: scopes,
	}); err != nil {
		if errors.Is(err, ErrReservedScopeDenied) {
			return oauthBadRequestCause(oautherror.InvalidGrant, err.Error(), err)
		}
		return oauthServerError("could not authorize the key's reserved scopes", err)
	}
	issue.ReservedScopesAuthorized = true
	issue.MaxTTL = maxTTL
	return nil
}
