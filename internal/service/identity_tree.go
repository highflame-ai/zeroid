package service

// The registration tree. An identity registered by another identity, acting
// as itself, records that identity as its parent, inherits its owner and
// (unless the request names its own) its scope ceilings and credential
// policy, can hold no scope, policy, trust level or lifetime beyond what its
// parent, and the credential the parent presented, hold, and is deactivated
// whenever its parent is. While it or any identity above it is not active, no
// token that speaks for or acts as it is issued or reported active (the
// guards are in CredentialService). A request authenticated as an identity
// writes only to that identity's children. See docs/identity-tree.md.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// CallerIdentity is the registered identity an admin request was
// authenticated as, when the caller is that identity acting as itself: with
// an access token issued to it for itself (no actor, not held for a person).
// The embedder's admin authentication sets it with zeroid.WithCallerIdentity,
// from the token it verified. ZeroID never takes it from a header or the
// request body. An identity registered by such a request records the caller as
// its parent, and every other write such a request makes on an identity is
// refused unless the identity is the caller's own child, and bounded by what
// the caller holds (authorizeCallerWrite).
//
// IdentityID or WIMSEURI identifies the caller; when both are set they must
// name the same identity. The identity must be in the account and project the
// request is made in. Re-exported as zeroid.CallerIdentity.
type CallerIdentity struct {
	// IdentityID is the caller's identity id.
	IdentityID string
	// WIMSEURI is the caller's WIMSE URI: the sub of a token issued to the
	// identity for itself.
	WIMSEURI string
	// Scopes are the scopes of the token the request presented, from its
	// verified scopes claim. A child the request registers, and any
	// identity it changes, can hold no scope outside them. Nil or empty
	// means the token holds none, so a child could hold none either and is
	// refused.
	Scopes []string
	// APIKeyID is the API key the token was minted from, from its verified
	// api_key_id claim (set on tokens from the api_key grant); empty when the
	// token carries none. When set, ZeroID loads the key, which must be an
	// active, unexpired key of the calling identity in the request's tenant,
	// and bounds the child by the key's expiry and credential policy as well.
	APIKeyID string
}

type callerIdentityCtxKey struct{}

// WithCallerIdentity returns ctx carrying the identity the request was
// authenticated as.
func WithCallerIdentity(ctx context.Context, c CallerIdentity) context.Context {
	return context.WithValue(ctx, callerIdentityCtxKey{}, c)
}

// CallerIdentityFromContext returns the identity set by WithCallerIdentity.
func CallerIdentityFromContext(ctx context.Context) (CallerIdentity, bool) {
	c, ok := ctx.Value(callerIdentityCtxKey{}).(CallerIdentity)
	return c, ok
}

type trustedOwnerWriteKey struct{}

// WithTrustedOwnerWrite marks ctx as the deployer's trusted path, which may
// change the owner of an identity registered by another identity. Re-exported
// as zeroid.WithTrustedOwnerWrite.
func WithTrustedOwnerWrite(ctx context.Context) context.Context {
	return context.WithValue(ctx, trustedOwnerWriteKey{}, true)
}

// TrustedOwnerWrite reports whether ctx carries WithTrustedOwnerWrite.
func TrustedOwnerWrite(ctx context.Context) bool {
	v, _ := ctx.Value(trustedOwnerWriteKey{}).(bool)
	return v
}

// ErrParentIdentityRefused is returned when an identity cannot be registered
// under the calling identity, or the caller cannot make a write: the caller
// is not an active, unexpired identity in the request's account and project,
// an identity above it is not, its credential policy is inactive or expired,
// the API key it presented is not its own active key, or it has no owner for
// its children to inherit. Handlers map it to 403.
var ErrParentIdentityRefused = errors.New("the calling identity cannot register or change identities here")

// ErrExceedsParentCeiling marks a write that would let a child identity hold a
// scope its parent, or the token its parent presented, cannot. It is always
// joined with ErrInvalidIdentityField, so handlers answer 400 with the
// message, which names the offending scope.
var ErrExceedsParentCeiling = errors.New("exceeds the parent identity's scope ceiling")

// ErrExceedsParentTrust marks a write that would make a child identity more
// trusted than its parent. It is always joined with ErrInvalidIdentityField,
// so handlers answer 400 with the message, which names trust_level.
var ErrExceedsParentTrust = errors.New("exceeds the parent identity's trust level")

// ErrExceedsParentPolicy marks a write that would place a child identity on a
// credential policy broader than its parent's on any axis (grant types, token
// lifetime, delegation depth, required principal, trust or attestation, or the
// policy's own expiry). Joined with ErrInvalidIdentityField: 400.
var ErrExceedsParentPolicy = errors.New("exceeds the parent identity's credential policy")

// ErrExceedsParentExpiry marks a write that would let a child identity
// outlive its parent, an identity above it, or the API key its parent
// presented. Joined with ErrInvalidIdentityField: 400.
var ErrExceedsParentExpiry = errors.New("exceeds the parent identity's expiry")

// ErrIdentityTreeLimit is returned when a registration would exceed the
// configured tree limits (children per identity, or depth). Handlers map it
// to 409.
var ErrIdentityTreeLimit = errors.New("identity tree limit reached")

// ErrAncestorNotActive is returned when an identity cannot be made active
// because an identity above it in the registration tree is not active and
// unexpired. Handlers map it to 409.
var ErrAncestorNotActive = errors.New("an identity above this one in the registration tree is not active")

// ErrCascadeStillPending is returned when an identity cannot be reactivated
// because the deactivation of the identities below it has not finished.
// Repeating the deactivation finishes it. Handlers map it to 409.
var ErrCascadeStillPending = errors.New("the deactivation of the identities below this one has not finished; repeat the deactivation, then reactivate")

// ErrIdentityChanged is returned when an identity's status changed between
// the read and the write of an update, which was therefore not applied.
// Handlers map it to 409; the request can be repeated.
var ErrIdentityChanged = errors.New("the identity changed while the request was applied; repeat it")

// ErrOwnerWriteNotTrusted is returned when a request changes the owner of an
// identity registered by another identity outside a WithTrustedOwnerWrite
// context, or any identity's owner from a request authenticated as an
// identity. Handlers map it to 403.
var ErrOwnerWriteNotTrusted = errors.New("this identity's owner can be changed only by the deployer's trusted path")

// ErrCascadeIncomplete is returned when an identity was deactivated but some
// identity below it in the registration tree was not. The identity's own
// deactivation stands, it stays marked, and the cleanup worker finishes the
// walk; repeating the deactivation finishes it sooner. Handlers map it to 500.
var ErrCascadeIncomplete = errors.New("deactivation did not reach every identity below this one")

// reasonParentDeactivated is the revocation and lifecycle-signal reason on an
// identity deactivated because an identity above it was.
const reasonParentDeactivated = "parent_deactivated"

// createdByColumnLen is the width of identities.created_by (VARCHAR(255),
// 001_init_schema).
const createdByColumnLen = 255

// ── Limits ───────────────────────────────────────────────────────────────────

// Default tree limits (docs/identity-tree.md).
const (
	// DefaultTreeMaxDepth is the default number of identities that may sit
	// above any identity: an identity registered by an admin is at depth 0,
	// its children at 1, and so on.
	DefaultTreeMaxDepth = 8
	// DefaultTreeMaxChildren is the default number of children, not
	// deactivated, that one identity may have.
	DefaultTreeMaxChildren = 1000
)

// TreeLimits bounds registration trees. A zero field takes its default.
// MaxDepth may not exceed postgres.MaxTreeDepth.
type TreeLimits struct {
	MaxDepth    int
	MaxChildren int
}

// resolved fills defaults.
func (l TreeLimits) resolved() postgres.TreeLimits {
	out := postgres.TreeLimits{MaxDepth: l.MaxDepth, MaxChildren: l.MaxChildren}
	if out.MaxDepth <= 0 {
		out.MaxDepth = DefaultTreeMaxDepth
	}
	if out.MaxDepth > postgres.MaxTreeDepth {
		out.MaxDepth = postgres.MaxTreeDepth
	}
	if out.MaxChildren <= 0 {
		out.MaxChildren = DefaultTreeMaxChildren
	}
	return out
}

// SetTreeLimits sets the registration tree limits. Wired once at server
// construction.
func (s *IdentityService) SetTreeLimits(l TreeLimits) { s.treeLimits = l.resolved() }

// SetReservedScopes shares the deployer's reserved scopes, which never pass
// to a child identity.
func (s *IdentityService) SetReservedScopes(r *ReservedScopes) { s.reserved = r }

// ── The bounding identity ────────────────────────────────────────────────────

// treeBound is an identity that bounds a write: the parent a child is
// registered or changed under, or the identity a request was authenticated
// as. Its scope ceilings, credential policy, trust level and lifetime are
// what the written identity must stay within.
type treeBound struct {
	identity *domain.Identity
	// identityPolicy governs identity itself (its own, else the tenant
	// default).
	identityPolicy *domain.CredentialPolicy
	// policy is the presented API key's policy when the key names one,
	// otherwise identityPolicy. A child is held to both: a policy it is
	// placed on must be within identityPolicy and within policy.
	policy *domain.CredentialPolicy
	// inherit is the policy a child that names none is placed on, and the
	// one naming which counts as inheriting: the narrower of identityPolicy
	// and policy. Nil when neither is within the other; a child must then
	// name a policy within both.
	inherit *domain.CredentialPolicy
	// tokenScopes, when hasToken, are the scopes of the token the caller
	// presented: an extra layer that always restricts.
	tokenScopes []string
	hasToken    bool
	// expiryCap is the earliest expires_at among identity, every identity
	// above it and the presented API key; nil when none is set.
	expiryCap *time.Time
}

// layers returns the scope layers bound places, without the token's.
func (b *treeBound) layers() ceilingLayers {
	policies := []*domain.CredentialPolicy{b.identityPolicy}
	if b.policy != nil && b.policy != b.identityPolicy {
		policies = append(policies, b.policy)
	}
	return ceilingLayers{rowScopes: b.identity.AllowedScopes, policies: policies}
}

// policies returns the distinct credential policies a child is held to.
func (b *treeBound) policies() []*domain.CredentialPolicy {
	var out []*domain.CredentialPolicy
	for _, p := range []*domain.CredentialPolicy{b.identityPolicy, b.policy} {
		if p != nil && (len(out) == 0 || !sameUUID(p.ID, out[0].ID)) {
			out = append(out, p)
		}
	}
	return out
}

// inherits reports whether placing a child on policyID is the same as
// inheriting: it names the policy a child that names none is placed on.
func (b *treeBound) inherits(policyID string) bool {
	return b.inherit != nil && sameUUID(policyID, b.inherit.ID)
}

// token returns the token's scopes as a bound. It restricts even when empty:
// a token that holds no scope lets a child hold none.
func (b *treeBound) token() scopeBound {
	set := make(map[string]bool, len(b.tokenScopes))
	for _, s := range b.tokenScopes {
		set[s] = true
	}
	return scopeBound{restricted: true, scopes: set}
}

// usableChain checks that every identity in chain is active and unexpired.
func usableChain(chain []postgres.Ancestor) error {
	now := time.Now()
	for _, a := range chain {
		if !a.Usable(now) {
			state := string(a.Status)
			if a.Status == domain.IdentityStatusActive {
				state = "expired"
			}
			return fmt.Errorf("identity %s is %s", a.ID, state)
		}
	}
	return nil
}

// earliest returns the earlier of a and b, either of which may be nil.
func earliest(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil || a.Before(*b):
		return a
	}
	return b
}

// usablePolicy refuses a credential policy that is inactive or expired: an
// identity on one can mint nothing, so it can grant nothing either.
func usablePolicy(p *domain.CredentialPolicy) error {
	if p == nil {
		return nil
	}
	if !p.IsActive {
		return fmt.Errorf("its credential policy %q is inactive", p.Name)
	}
	if p.IsExpired() {
		return fmt.Errorf("its credential policy %q has expired", p.Name)
	}
	return nil
}

// resolveCaller resolves the identity a request was authenticated as into
// the bound it places, in (accountID, projectID). The lookup is scoped to
// that tenant, so a caller from another account or project is not found. The
// caller and every identity above it must be active and unexpired, its
// credential policy active and unexpired, and the API key it presented (if
// the token names one) an active, unexpired key of the caller's.
func (s *IdentityService) resolveCaller(ctx context.Context, caller CallerIdentity, accountID, projectID string) (*treeBound, error) {
	var (
		identity *domain.Identity
		err      error
	)
	switch {
	case caller.IdentityID != "":
		id, perr := uuid.Parse(caller.IdentityID)
		if perr != nil {
			return nil, fmt.Errorf("%w: the calling identity's id is not an identity id", ErrParentIdentityRefused)
		}
		identity, err = s.repo.GetByID(ctx, id.String(), accountID, projectID)
	case caller.WIMSEURI != "":
		identity, err = s.repo.GetByWIMSEURI(ctx, caller.WIMSEURI, accountID, projectID)
	default:
		return nil, fmt.Errorf("%w: the caller names no identity", ErrParentIdentityRefused)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: the caller is not an identity in this account and project", ErrParentIdentityRefused)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve the calling identity: %w", err)
	}
	if caller.IdentityID != "" && caller.WIMSEURI != "" && caller.WIMSEURI != identity.WIMSEURI {
		return nil, fmt.Errorf("%w: the caller's identity id and WIMSE URI name different identities", ErrParentIdentityRefused)
	}
	if !identity.Status.IsUsable() {
		return nil, fmt.Errorf("%w: the calling identity is not active (status: %s)", ErrParentIdentityRefused, identity.Status)
	}
	if identity.IsExpired() {
		return nil, fmt.Errorf("%w: the calling identity has expired", ErrParentIdentityRefused)
	}
	b, err := s.boundOfIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}
	b.tokenScopes, b.hasToken = slices.Clone(caller.Scopes), true

	if caller.APIKeyID != "" {
		if err := s.applyPresentedKey(ctx, b, caller.APIKeyID); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// boundOfIdentity is the bound identity places by itself: its ceilings, its
// credential policy, and the earliest expiry along its ancestor chain. The
// chain must be usable and the policy active, or the bound refuses.
func (s *IdentityService) boundOfIdentity(ctx context.Context, identity *domain.Identity) (*treeBound, error) {
	chain, err := s.repo.AncestorChain(ctx, identity.ID, identity.AccountID, identity.ProjectID)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, postgres.ErrBrokenAncestorChain) {
		return nil, fmt.Errorf("%w: the registration tree above %s is broken: %w", ErrParentIdentityRefused, identity.ID, err)
	}
	if err != nil {
		return nil, err
	}
	if err := usableChain(chain); err != nil {
		return nil, fmt.Errorf("%w: %w, above or at %s in the registration tree", ErrParentIdentityRefused, err, identity.ID)
	}
	var expiryCap *time.Time
	for _, a := range chain {
		expiryCap = earliest(expiryCap, a.ExpiresAt)
	}
	policy, err := s.ResolveCredentialPolicy(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("resolve the credential policy of identity %s: %w", identity.ID, err)
	}
	if err := usablePolicy(policy); err != nil {
		return nil, fmt.Errorf("%w: identity %s: %w", ErrParentIdentityRefused, identity.ID, err)
	}
	return &treeBound{identity: identity, identityPolicy: policy, policy: policy, inherit: policy, expiryCap: expiryCap}, nil
}

// applyPresentedKey narrows b by the API key the caller's token was minted
// from: the key must be the caller's own, active and unexpired; its expiry
// caps the bound's, and its credential policy, when it names one, becomes the
// effective policy.
func (s *IdentityService) applyPresentedKey(ctx context.Context, b *treeBound, keyID string) error {
	if _, err := uuid.Parse(keyID); err != nil {
		return fmt.Errorf("%w: the presented API key id is not an id", ErrParentIdentityRefused)
	}
	key, err := s.apiKeyRepo.GetByID(ctx, keyID, b.identity.AccountID, b.identity.ProjectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: the presented API key is not in this account and project", ErrParentIdentityRefused)
		}
		return fmt.Errorf("resolve the presented API key: %w", err)
	}
	if !sameUUID(key.IdentityID, b.identity.ID) {
		return fmt.Errorf("%w: the presented API key does not belong to the calling identity", ErrParentIdentityRefused)
	}
	if key.State != domain.APIKeyStateActive || key.RevokedAt != nil || key.IsExpired() {
		return fmt.Errorf("%w: the presented API key is not active", ErrParentIdentityRefused)
	}
	b.expiryCap = earliest(b.expiryCap, key.ExpiresAt)
	if key.CredentialPolicyID != "" && !sameUUID(key.CredentialPolicyID, b.identityPolicy.ID) {
		keyPolicy, err := s.policySvc.GetPolicy(ctx, key.CredentialPolicyID, b.identity.AccountID, b.identity.ProjectID)
		if err != nil {
			return fmt.Errorf("resolve the presented API key's credential policy: %w", err)
		}
		if err := usablePolicy(keyPolicy); err != nil {
			return fmt.Errorf("%w: the presented API key: %w", ErrParentIdentityRefused, err)
		}
		// The key's policy was a subset of the identity's when the key was
		// made, but either may have changed since. A child is held to both,
		// and inherits whichever is within the other.
		b.policy = keyPolicy
		switch {
		case s.policyWithin(keyPolicy, b.identityPolicy):
			b.inherit = keyPolicy
		case s.policyWithin(b.identityPolicy, keyPolicy):
			b.inherit = b.identityPolicy
		default:
			b.inherit = nil
		}
	}
	return nil
}

// policyWithin reports whether narrower is within wider on every axis
// EnforceSubset checks, and expires no later.
func (s *IdentityService) policyWithin(narrower, wider *domain.CredentialPolicy) bool {
	if s.policySvc.EnforceSubset(narrower, wider) != nil {
		return false
	}
	return wider.ExpiresAt == nil || (narrower.ExpiresAt != nil && !narrower.ExpiresAt.After(*wider.ExpiresAt))
}

// authorizeCallerWrite applies to a write on the existing identity target the
// rules for a request marked with CallerIdentity, and returns the caller's
// bound (nil when the request is not marked). The caller must resolve as
// for a registration (an active, unexpired identity in the request's tenant,
// with an active, unexpired chain and policy, and its own active key when
// the token names one), and target must be an identity it registered: its
// direct child. So a calling identity never writes to itself, its parent, a
// sibling, a grandchild or any identity an admin registered.
func (s *IdentityService) authorizeCallerWrite(ctx context.Context, target *domain.Identity, accountID, projectID string) (*treeBound, error) {
	ref, ok := CallerIdentityFromContext(ctx)
	if !ok {
		return nil, nil
	}
	caller, err := s.resolveCaller(ctx, ref, accountID, projectID)
	if err != nil {
		return nil, err
	}
	if target.ParentIdentityID == "" || !sameUUID(target.ParentIdentityID, caller.identity.ID) {
		return nil, fmt.Errorf("%w: a calling identity can change only the identities it registered", ErrParentIdentityRefused)
	}
	return caller, nil
}

// callerStatusChange refuses a status change a calling identity may not make
// on a child: it may lower a status (active to suspended, anything to
// deactivated or expired), never raise one. Reactivating a child, or
// resuming a suspended one, is for a request not authenticated as an
// identity, so a parent cannot undo a stop the deployer made.
func callerStatusChange(prior, next domain.IdentityStatus) error {
	switch {
	case prior == next:
		return nil
	case next == domain.IdentityStatusSuspended && prior == domain.IdentityStatusActive:
		return nil
	case next == domain.IdentityStatusDeactivated, next == domain.IdentityStatusExpired:
		return nil
	}
	return fmt.Errorf("%w: a calling identity cannot raise an identity's status (%s to %s)", ErrParentIdentityRefused, prior, next)
}

// loadParent loads the bound child's parent places, for a write that changes
// the child's ceilings, policy, trust level, expiry or status. Unlike a
// caller, the parent need not be active: its ceilings bind the child
// whatever its status. A parent missing from the child's tenant is an error,
// so the write fails closed.
func (s *IdentityService) loadParent(ctx context.Context, child *domain.Identity) (*treeBound, error) {
	parent, err := s.repo.GetByID(ctx, child.ParentIdentityID, child.AccountID, child.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("load parent identity %s of %s: %w", child.ParentIdentityID, child.ID, err)
	}
	policy, err := s.ResolveCredentialPolicy(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("resolve the credential policy of parent identity %s: %w", parent.ID, err)
	}
	b := &treeBound{identity: parent, identityPolicy: policy, policy: policy, inherit: policy}
	chain, err := s.repo.AncestorChain(ctx, parent.ID, parent.AccountID, parent.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("read the registration tree above %s: %w", child.ID, err)
	}
	for _, a := range chain {
		b.expiryCap = earliest(b.expiryCap, a.ExpiresAt)
	}
	return b, nil
}

// childCreatedBy is the created_by of an identity registered by parent: the
// parent's WIMSE URI, the name ZeroID gives a workload acting as itself
// elsewhere in the audit trail, so the creation is attributed to the identity
// that performed it rather than to a person. The parent's id stands in when
// the URI is longer than the column.
func childCreatedBy(parent *domain.Identity) string {
	if len(parent.WIMSEURI) <= createdByColumnLen {
		return parent.WIMSEURI
	}
	return parent.ID
}

// inheritedScopes is the allowed_scopes of a child that names none: the
// scopes the bound's own ceiling and the token both allow, without reserved
// scopes, sorted. Empty means the child could hold no scope.
func (s *IdentityService) inheritedScopes(b *treeBound) []string {
	own := b.layers().own()
	out := make([]string, 0, len(b.tokenScopes))
	for _, scope := range b.tokenScopes {
		if own.allows(scope) && len(s.reserved.in([]string{scope})) == 0 && !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}
	slices.Sort(out)
	return out
}

// refuseReserved refuses a child scope layer that lists a reserved scope:
// those are the deployer's own and never pass down a tree.
func (s *IdentityService) refuseReserved(what string, scopes []string) error {
	if r := s.reserved.in(scopes); len(r) > 0 {
		return ceilingError("%s lists the reserved scope %q", what, r[0])
	}
	return nil
}

// checkChildPolicy refuses placing a child on child when it is broader, on
// any axis, than any policy the bound holds it to (the bound identity's own
// and, when the caller presented an API key that names one, the key's): the
// full subset check (CredentialPolicyService.EnforceSubset) and the policy's
// own expiry.
func (s *IdentityService) checkChildPolicy(b *treeBound, child *domain.CredentialPolicy) error {
	if child == nil {
		return nil
	}
	for _, p := range b.policies() {
		if p == nil || sameUUID(child.ID, p.ID) {
			continue
		}
		if err := s.policySvc.EnforceSubset(child, p); err != nil {
			return fmt.Errorf("%w: %w: credential policy %q: %w", ErrInvalidIdentityField, ErrExceedsParentPolicy, child.Name, err)
		}
		if p.ExpiresAt != nil && (child.ExpiresAt == nil || child.ExpiresAt.After(*p.ExpiresAt)) {
			return fmt.Errorf("%w: %w: credential policy %q outlives %q, which expires at %s",
				ErrInvalidIdentityField, ErrExceedsParentPolicy, child.Name, p.Name, p.ExpiresAt.Format(time.RFC3339))
		}
	}
	return nil
}

// checkWithinToken refuses child layers that allow a scope the bound's token
// does not hold.
func checkWithinToken(b *treeBound, child ceilingLayers) error {
	if !b.hasToken {
		return nil
	}
	tok := b.token()
	if scope, open := tok.excess(child.own()); open {
		return ceilingError("the identity would have no scope ceiling, and the calling token holds only %v", b.tokenScopes)
	} else if scope != "" {
		return ceilingError("the identity could hold %q, which the calling token does not", scope)
	}
	if scope, open := tok.excess(child.forPerson()); open {
		return ceilingError("the identity would have no ceiling on what it holds for a person, and the calling token holds only %v", b.tokenScopes)
	} else if scope != "" {
		return ceilingError("the identity could hold %q for a person, which the calling token does not", scope)
	}
	return nil
}

// checkBoundCeilings refuses a child whose scope layers, policy and named
// scopes are not within bound b. rowNamed and policyNamed are as for
// checkChildCeilings.
func (s *IdentityService) checkBoundCeilings(b *treeBound, child ceilingLayers, rowNamed, policyNamed bool) error {
	if err := checkChildCeilings(b.layers(), child, rowNamed, policyNamed); err != nil {
		return err
	}
	if err := checkWithinToken(b, child); err != nil {
		return err
	}
	if policyNamed && len(child.policies) > 0 {
		return s.checkChildPolicy(b, child.policies[0])
	}
	return nil
}

// checkExpiry refuses an expiry beyond the bound's cap. A nil expiry under a
// cap would outlive it.
func checkExpiry(b *treeBound, expiresAt *time.Time) error {
	if b == nil || b.expiryCap == nil {
		return nil
	}
	if expiresAt == nil || expiresAt.After(*b.expiryCap) {
		got := "no expiry"
		if expiresAt != nil {
			got = expiresAt.Format(time.RFC3339)
		}
		return fmt.Errorf("%w: %w: expires_at %s is after %s, when identity %s, an identity above it, or the presented API key expires",
			ErrInvalidIdentityField, ErrExceedsParentExpiry, got, b.expiryCap.Format(time.RFC3339), b.identity.ID)
	}
	return nil
}

// IsRegisteredBy reports whether identityID, in the given tenant, was
// registered by the identity named by parent: whether that identity is its
// parent, and that parent and every identity above it are still active and
// unexpired. Only the direct parent counts, so an identity is not registered
// by its grandparent. An identity outside the tenant, one with no parent, a
// parent reference that names no identity in the tenant, or a parent that is
// not active (suspended, deactivated, expired, or below one that is) reports
// false.
func (s *IdentityService) IsRegisteredBy(ctx context.Context, identityID string, parent CallerIdentity, accountID, projectID string) (bool, error) {
	id, err := uuid.Parse(identityID)
	if err != nil {
		return false, nil
	}
	identity, err := s.repo.GetByID(ctx, id.String(), accountID, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if identity.ParentIdentityID == "" {
		return false, nil
	}
	switch {
	case parent.IdentityID != "":
		if !sameUUID(identity.ParentIdentityID, parent.IdentityID) {
			return false, nil
		}
	case parent.WIMSEURI == "":
		return false, nil
	}
	row, err := s.repo.GetByID(ctx, identity.ParentIdentityID, accountID, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// A reference naming the parent by WIMSE URI, alone or alongside its id,
	// must be the URI of that parent row.
	if parent.WIMSEURI != "" && row.WIMSEURI != parent.WIMSEURI {
		return false, nil
	}
	chain, err := s.repo.AncestorChain(ctx, row.ID, accountID, projectID)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, postgres.ErrBrokenAncestorChain) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return usableChain(chain) == nil, nil
}

// sameUUID reports whether a and b are the same UUID, in any accepted
// spelling. A value that is not a UUID matches nothing.
func sameUUID(a, b string) bool {
	ua, errA := uuid.Parse(a)
	ub, errB := uuid.Parse(b)
	return errA == nil && errB == nil && ua == ub
}

// treeStoreError maps the store's tree refusals onto the service's errors.
func treeStoreError(err error) error {
	switch {
	case errors.Is(err, postgres.ErrParentNotActive):
		return fmt.Errorf("%w: %w", ErrParentIdentityRefused, err)
	case errors.Is(err, postgres.ErrTreeTooDeep), errors.Is(err, postgres.ErrTooManyChildren):
		return fmt.Errorf("%w: %w", ErrIdentityTreeLimit, err)
	case errors.Is(err, postgres.ErrAncestorNotActive):
		return fmt.Errorf("%w: %w", ErrAncestorNotActive, err)
	case errors.Is(err, postgres.ErrIdentityChanged):
		return fmt.Errorf("%w: %w", ErrIdentityChanged, err)
	}
	return err
}

// ── Trust level ──────────────────────────────────────────────────────────────

// childTrustLevel returns the trust level a child of a parent at level parent
// is registered with: the level the request names, or, when it names none,
// def (the registration default) capped at the parent's level. A named level
// above the parent's is refused. Levels are ordered by domain.TrustLevelRank.
func childTrustLevel(requested, def, parent domain.TrustLevel) (domain.TrustLevel, error) {
	parentRank := domain.TrustLevelRank(string(parent))
	if parentRank < 0 {
		// The column's CHECK constraint rules this out; refuse rather than guess.
		return "", fmt.Errorf("%w: the calling identity has no valid trust_level", ErrParentIdentityRefused)
	}
	if requested == "" {
		if domain.TrustLevelRank(string(def)) > parentRank {
			return parent, nil
		}
		return def, nil
	}
	if domain.TrustLevelRank(string(requested)) > parentRank {
		return "", trustError(requested, parent)
	}
	return requested, nil
}

// checkChildTrustRaise refuses a change of a child's trust level from prior to
// next that raises it above its parent's. Lowering is always allowed, and so
// is keeping a level the child already holds even when it is above the
// parent's: a verified attestation can raise a child past its parent, and a
// parent can be lowered after its children were registered.
func checkChildTrustRaise(prior, next, parent domain.TrustLevel) error {
	nextRank := domain.TrustLevelRank(string(next))
	if nextRank > domain.TrustLevelRank(string(prior)) && nextRank > domain.TrustLevelRank(string(parent)) {
		return trustError(next, parent)
	}
	return nil
}

// capTrustAtParent returns level, lowered to the parent's trust level when
// identity has a parent that is less trusted.
func (s *IdentityService) capTrustAtParent(ctx context.Context, identity *domain.Identity, level domain.TrustLevel) (domain.TrustLevel, error) {
	if identity.ParentIdentityID == "" {
		return level, nil
	}
	parent, err := s.repo.GetByID(ctx, identity.ParentIdentityID, identity.AccountID, identity.ProjectID)
	if err != nil {
		return "", fmt.Errorf("load parent identity %s of %s: %w", identity.ParentIdentityID, identity.ID, err)
	}
	if domain.TrustLevelRank(string(level)) > domain.TrustLevelRank(string(parent.TrustLevel)) {
		return parent.TrustLevel, nil
	}
	return level, nil
}

// trustError reports a child trust level above its parent's.
func trustError(level, parent domain.TrustLevel) error {
	return fmt.Errorf("%w: %w: trust_level %q is above the parent's %q", ErrInvalidIdentityField, ErrExceedsParentTrust, level, parent)
}

// ── Scope ceilings ───────────────────────────────────────────────────────────

// scopeBound is the ceiling a set of scope layers places: the intersection of
// the layers that restrict. An empty layer restricts nothing
// (docs/scope-ceilings.md), so a bound with no restricting layer is open and
// allows any scope, while restricting layers that share no scope allow none.
type scopeBound struct {
	restricted bool
	scopes     map[string]bool
}

func boundOf(layers ...[]string) scopeBound {
	var b scopeBound
	for _, layer := range layers {
		if len(layer) == 0 {
			continue
		}
		next := make(map[string]bool, len(layer))
		for _, scope := range layer {
			if !b.restricted || b.scopes[scope] {
				next[scope] = true
			}
		}
		b = scopeBound{restricted: true, scopes: next}
	}
	return b
}

func (b scopeBound) allows(scope string) bool {
	return !b.restricted || b.scopes[scope]
}

// excess compares child against b. It returns the first scope, in sorted
// order, that child allows and b does not; open reports a child that allows
// everything while b restricts.
func (b scopeBound) excess(child scopeBound) (scope string, open bool) {
	if !b.restricted {
		return "", false
	}
	if !child.restricted {
		return "", true
	}
	scopes := make([]string, 0, len(child.scopes))
	for s := range child.scopes {
		scopes = append(scopes, s)
	}
	slices.Sort(scopes)
	for _, s := range scopes {
		if !b.scopes[s] {
			return s, false
		}
	}
	return "", false
}

// ceilingLayers are the scope layers an identity's tokens are bound by: its
// own allowed_scopes and the credential policies that govern it (for a child,
// its one policy; for a bound, the identity's policy and the presented API
// key's, when that names a narrower one).
type ceilingLayers struct {
	rowScopes []string
	policies  []*domain.CredentialPolicy
}

// childLayers is the layers of an identity on one policy.
func childLayers(rowScopes []string, policy *domain.CredentialPolicy) ceilingLayers {
	return ceilingLayers{rowScopes: rowScopes, policies: []*domain.CredentialPolicy{policy}}
}

// policy is the first policy, the one a child is on.
func (l ceilingLayers) policy() *domain.CredentialPolicy {
	if len(l.policies) == 0 {
		return nil
	}
	return l.policies[0]
}

// own is the ceiling on the identity's own authority: allowed_scopes and each
// policy's allowed_scopes.
func (l ceilingLayers) own() scopeBound {
	layers := [][]string{l.rowScopes}
	for _, p := range l.policies {
		if p != nil {
			layers = append(layers, p.AllowedScopes)
		}
	}
	return boundOf(layers...)
}

// forPerson is the ceiling on what the identity may hold for a person, where
// each policy's user_grant_scopes takes the place of its allowed_scopes and
// allowed_scopes still binds (docs/scope-ceilings.md).
func (l ceilingLayers) forPerson() scopeBound {
	layers := [][]string{l.rowScopes}
	for _, p := range l.policies {
		if p != nil {
			layers = append(layers, p.UserGrantScopes)
		}
	}
	return boundOf(layers...)
}

// within reports whether every scope l allows, in both forms, next allows no
// more of: next is no wider than l.
func (l ceilingLayers) within(next ceilingLayers) bool {
	if scope, open := l.own().excess(next.own()); open || scope != "" {
		return false
	}
	if scope, open := l.forPerson().excess(next.forPerson()); open || scope != "" {
		return false
	}
	return true
}

// ceilingError reports a child scope layer that exceeds its parent's.
func ceilingError(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrInvalidIdentityField, ErrExceedsParentCeiling, fmt.Sprintf(format, args...))
}

// checkChildCeilings refuses a child whose scope layers would let it hold a
// scope its parent cannot.
//
// A token never carries a scope outside the intersection of its identity's
// restricting layers, so the decisive check compares those intersections,
// in both forms: the identity's own authority, and what it may hold for a
// person. A child left open while its parent is restricted fails it, which is
// how an empty layer (no restriction) is kept from letting a child escape.
//
// A layer the request named is also checked on its own, so the error names
// what the caller asked for: every scope on a named allowed_scopes, and on a
// named credential policy's allowed_scopes and user_grant_scopes, must be
// within the parent's ceiling, and a named policy that places no scope
// ceiling is refused under a parent that has one. rowNamed and policyNamed
// are false for a layer copied from the parent: that layer is the parent's
// own, and may list a scope another of the parent's layers removes, which the
// intersection check accounts for. Naming the parent's own policy counts as
// copying it.
func checkChildCeilings(parent, child ceilingLayers, rowNamed, policyNamed bool) error {
	parentOwn, parentForPerson := parent.own(), parent.forPerson()

	if rowNamed {
		for _, scope := range child.rowScopes {
			if !parentOwn.allows(scope) {
				return ceilingError("allowed_scopes lists %q", scope)
			}
		}
	}
	if cp := child.policy(); policyNamed && cp != nil {
		if parentOwn.restricted && len(cp.AllowedScopes) == 0 {
			return ceilingError("credential policy %q places no scope ceiling", cp.Name)
		}
		for _, scope := range cp.AllowedScopes {
			if !parentOwn.allows(scope) {
				return ceilingError("credential policy %q lists %q", cp.Name, scope)
			}
		}
		for _, scope := range cp.UserGrantScopes {
			if !parentForPerson.allows(scope) {
				return ceilingError("credential policy %q lists %q in user_grant_scopes", cp.Name, scope)
			}
		}
	}

	if scope, open := parentOwn.excess(child.own()); open {
		return ceilingError("the identity would have no scope ceiling; set allowed_scopes or a credential policy within the parent's")
	} else if scope != "" {
		return ceilingError("the identity could hold %q", scope)
	}
	if scope, open := parentForPerson.excess(child.forPerson()); open {
		return ceilingError("the identity would have no ceiling on what it holds for a person; set allowed_scopes or a credential policy within the parent's")
	} else if scope != "" {
		return ceilingError("the identity could hold %q for a person", scope)
	}
	return nil
}

// ── Deactivation cascade ─────────────────────────────────────────────────────

// retiredStatus reports whether s ends an identity's authority, so that the
// identities below it must be deactivated too.
func retiredStatus(s domain.IdentityStatus) bool {
	return s == domain.IdentityStatusDeactivated || s == domain.IdentityStatusExpired
}

// cascadeRun is the set of identities one run has already walked, so that a
// run that retires several identities of one tree (offboarding an owner whose
// identities registered each other) walks each subtree once.
type cascadeRun struct {
	visited map[string]bool
}

type cascadeRunKey struct{}

// withCascadeRun returns ctx carrying a fresh run, shared by every walk made
// with it.
func withCascadeRun(ctx context.Context) context.Context {
	return context.WithValue(ctx, cascadeRunKey{}, &cascadeRun{visited: map[string]bool{}})
}

// cascadeRunFrom returns ctx's run, or a fresh one.
func cascadeRunFrom(ctx context.Context) *cascadeRun {
	if r, ok := ctx.Value(cascadeRunKey{}).(*cascadeRun); ok {
		return r
	}
	return &cascadeRun{visited: map[string]bool{}}
}

// cascadeResumeBatch is how many marked identities one cleanup pass resumes.
const cascadeResumeBatch = 500

// walkBelow deactivates every identity below root in its registration tree,
// a level at a time: one conditional UPDATE … RETURNING per level deactivates
// that level's children that are not already deactivated (writing only their
// status and the cascade_pending mark), then each changed identity gets the
// cleanup a direct deactivation gets, with the reason parent_deactivated, and
// its mark is cleared once that cleanup succeeded. A cleanup that fails leaves
// the identity marked, for the cleanup worker to repeat.
//
// The walk lists a level's children only after that level's deactivation has
// committed. A child registered before that is found, and one registered
// after is refused, since a registration locks every identity above the new
// child (IdentityRepository.CreateUnderParent). Identities already
// deactivated are passed through, not skipped, so anything below them is
// still reached; the run's visited set keeps each identity to one visit.
//
// ctx's cancellation stops the walk between levels, leaving root marked.
// Request paths pass a context detached from the request's cancellation; the
// cleanup worker passes its own, so a shutdown leaves the rest to the next
// pass. Every step is idempotent and conditional, so walks that overlap never
// clean one identity twice.
func (s *IdentityService) walkBelow(ctx context.Context, root *domain.Identity) error {
	run := cascadeRunFrom(ctx)
	run.visited[root.ID] = true
	detached := context.WithoutCancel(ctx)
	var deactivated, failedCleanups int
	for level := []string{root.ID}; len(level) > 0; {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: stopped below %s after %d identities: %w", ErrCascadeIncomplete, root.ID, deactivated, err)
		}
		changed, err := s.repo.DeactivateChildren(ctx, level, root.AccountID, root.ProjectID)
		if err != nil {
			return fmt.Errorf("%w: deactivate the identities below %s: %w", ErrCascadeIncomplete, root.ID, err)
		}
		cleaned := make([]string, 0, len(changed))
		for _, c := range changed {
			// The status is already written; finish this identity's cleanup
			// whatever happens to ctx.
			if err := s.deactivationCleanup(detached, c, reasonParentDeactivated); err != nil {
				log.Error().Err(err).
					Str("identity_id", c.ID).
					Str("ancestor_id", root.ID).
					Msg("identity tree: cleanup of an identity deactivated below a deactivated one failed; it stays marked for the cleanup worker")
				failedCleanups++
				continue
			}
			cleaned = append(cleaned, c.ID)
		}
		deactivated += len(changed)
		if err := s.repo.ClearCascadePending(detached, cleaned, root.AccountID, root.ProjectID); err != nil {
			log.Warn().Err(err).Str("ancestor_id", root.ID).
				Msg("identity tree: could not clear the mark on cleaned identities; the cleanup worker will repeat their cleanup")
		}
		ids, err := s.repo.ListChildIDs(ctx, level, root.AccountID, root.ProjectID)
		if err != nil {
			return fmt.Errorf("%w: list the identities below %s: %w", ErrCascadeIncomplete, root.ID, err)
		}
		next := make([]string, 0, len(ids))
		for _, id := range ids {
			// A cycle, which the write path cannot create, ends here too.
			if !run.visited[id] {
				run.visited[id] = true
				next = append(next, id)
			}
		}
		level = next
	}
	if deactivated > 0 {
		log.Info().
			Str("identity_id", root.ID).
			Int("count", deactivated).
			Int("cleanup_failures", failedCleanups).
			Msg("identity tree: deactivated the identities below a deactivated identity")
	}
	return nil
}

// finishCascade walks below root, which is retired and marked, and clears
// its mark when the walk completed and keepMark is false (keepMark is set
// when root's own cleanup failed, so the cleanup worker repeats it).
func (s *IdentityService) finishCascade(ctx context.Context, root *domain.Identity, keepMark bool) error {
	if err := s.walkBelow(ctx, root); err != nil {
		return err
	}
	if keepMark {
		// Root's own cleanup failed: it stays marked, moved to the back so
		// the worker's oldest-first batch rotates past it.
		if err := s.repo.TouchCascadePending(context.WithoutCancel(ctx), []string{root.ID}, root.AccountID, root.ProjectID); err != nil {
			log.Warn().Err(err).Str("identity_id", root.ID).Msg("identity tree: could not move the cascade mark")
		}
		return nil
	}
	if err := s.repo.ClearCascadePending(context.WithoutCancel(ctx), []string{root.ID}, root.AccountID, root.ProjectID); err != nil {
		// The walk finished; a stale mark only makes the worker repeat it.
		log.Warn().Err(err).Str("identity_id", root.ID).Msg("identity tree: could not clear the cascade mark")
	}
	return nil
}

// resumeCascade finishes the work an identity's cascade_pending mark says may
// be unfinished: its own deactivation cleanup (repeated; revocation is
// idempotent, though its retirement signal may be emitted again) and the walk
// below it. An identity that is no longer retired has nothing to resume
// (reactivation is refused while the mark is set, so this is a stale mark).
func (s *IdentityService) resumeCascade(ctx context.Context, identity *domain.Identity) error {
	if identity.CascadePendingAt == nil {
		return nil
	}
	if !retiredStatus(identity.Status) {
		return s.repo.ClearCascadePending(context.WithoutCancel(ctx), []string{identity.ID}, identity.AccountID, identity.ProjectID)
	}
	reason := "identity_deactivated"
	switch {
	// The expiry sweep retires an identity past its expires_at as
	// deactivated; a resume keeps the reason it was retired with.
	case identity.Status == domain.IdentityStatusExpired, identity.IsExpired():
		reason = "expired"
	case identity.ParentIdentityID != "":
		reason = reasonParentDeactivated
	}
	cleanupErr := s.deactivationCleanup(context.WithoutCancel(ctx), identity, reason)
	if cleanupErr != nil {
		log.Error().Err(cleanupErr).Str("identity_id", identity.ID).
			Msg("identity tree: resumed cleanup failed; the identity stays marked")
	}
	return s.finishCascade(ctx, identity, cleanupErr != nil)
}

// MarkUnfinishedRetirements marks, up to one batch, the retired identities
// that still have a child that is not deactivated but carry no mark, so the
// resume below walks them: retirements written by a release that predates
// the tree. The cleanup worker calls it on every pass, before
// ResumePendingCascades. Returns how many it marked.
func (s *IdentityService) MarkUnfinishedRetirements(ctx context.Context) (int, error) {
	n, err := s.repo.MarkUnfinishedRetirements(ctx, cascadeResumeBatch)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		log.Warn().Int("count", n).
			Msg("identity tree: found retired identities with live children and no pending cascade (retired by an older release?); marked them for the cascade")
	}
	return n, nil
}

// ResumePendingCascades resumes, oldest first, up to one batch of identities
// still marked cascade_pending: deactivations whose walk below them, or whose
// own cleanup, did not finish (a crash, a canceled sweep, a failed step). The
// cleanup worker calls it on every pass. Returns how many it resumed.
func (s *IdentityService) ResumePendingCascades(ctx context.Context) (int, error) {
	pending, err := s.repo.ListCascadePending(ctx, cascadeResumeBatch)
	if err != nil {
		return 0, err
	}
	ctx = withCascadeRun(ctx)
	resumed := 0
	for _, identity := range pending {
		if ctx.Err() != nil {
			break
		}
		if err := s.resumeCascade(ctx, identity); err != nil {
			log.Error().Err(err).
				Str("identity_id", identity.ID).
				Str("account_id", identity.AccountID).
				Str("project_id", identity.ProjectID).
				Msg("identity tree: resuming a pending cascade failed; the next pass retries")
			// To the back of the queue, so a mark that keeps failing does
			// not keep newer ones out of the batch.
			if terr := s.repo.TouchCascadePending(context.WithoutCancel(ctx), []string{identity.ID}, identity.AccountID, identity.ProjectID); terr != nil {
				log.Warn().Err(terr).Str("identity_id", identity.ID).Msg("identity tree: could not move the cascade mark")
			}
			continue
		}
		resumed++
	}
	if resumed > 0 {
		log.Info().Int("count", resumed).Msg("identity tree: resumed pending deactivation cascades")
	}
	return resumed, nil
}
