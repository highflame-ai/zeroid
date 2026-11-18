package service

// The registration tree. An identity registered by another identity, acting
// as itself, records that identity as its parent, inherits its owner and
// (unless the request names its own) its scope ceilings, can hold no scope
// its parent cannot, and is deactivated whenever its parent is. See
// docs/identity-tree.md.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
)

// CallerIdentity is the registered identity an admin request was
// authenticated as, when the caller is that identity acting as itself: with
// its own API key, client credentials or signed assertion, or with a token
// issued to it for itself (one with no actor, not held for a person). The
// embedder's admin authentication sets it with zeroid.WithCallerIdentity, from
// the credential it verified. ZeroID never takes it from a header or the
// request body. An identity registered by such a request records the caller as
// its parent.
//
// Either field identifies the caller; when both are set they must name the
// same identity. The identity must be in the account and project the request
// is made in. Re-exported as zeroid.CallerIdentity.
type CallerIdentity struct {
	// IdentityID is the caller's identity id.
	IdentityID string
	// WIMSEURI is the caller's WIMSE URI: the sub of a token issued to the
	// identity for itself.
	WIMSEURI string
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

// ErrParentIdentityRefused is returned when an identity cannot be registered
// under the calling identity: the caller is not an active, unexpired identity
// in the request's account and project, or it has no owner for its children to
// inherit. Handlers map it to 403.
var ErrParentIdentityRefused = errors.New("the calling identity cannot register identities here")

// ErrExceedsParentCeiling marks a write that would let a child identity hold a
// scope its parent cannot. It is always joined with ErrInvalidIdentityField,
// so handlers answer 400 with the message, which names the offending scope.
var ErrExceedsParentCeiling = errors.New("exceeds the parent identity's scope ceiling")

// ErrCascadeIncomplete is returned when an identity was deactivated but some
// identity below it in the registration tree was not. The identity's own
// deactivation stands; every step is idempotent, so repeating the
// deactivation finishes the cascade. Handlers map it to 500.
var ErrCascadeIncomplete = errors.New("deactivation did not reach every identity below this one")

// reasonParentDeactivated is the revocation and lifecycle-signal reason on an
// identity deactivated because an identity above it was.
const reasonParentDeactivated = "parent_deactivated"

// createdByColumnLen is the width of identities.created_by (VARCHAR(255),
// 001_init_schema).
const createdByColumnLen = 255

// registeringParent is the calling identity of a registration, resolved as
// the new identity's parent, with the credential policy that governs it.
type registeringParent struct {
	identity *domain.Identity
	policy   *domain.CredentialPolicy
}

// layers returns the parent's scope layers.
func (p *registeringParent) layers() ceilingLayers {
	return ceilingLayers{rowScopes: p.identity.AllowedScopes, policy: p.policy}
}

// resolveRegisteringParent resolves the caller of a registration request into
// the parent of an identity being registered in (accountID, projectID). The
// lookup is scoped to that tenant, so a caller from another account or
// project is not found. The caller must be active and unexpired, and must have
// an owner, because a child inherits it.
func (s *IdentityService) resolveRegisteringParent(ctx context.Context, caller CallerIdentity, accountID, projectID string) (*registeringParent, error) {
	var (
		parent *domain.Identity
		err    error
	)
	switch {
	case caller.IdentityID != "":
		id, perr := uuid.Parse(caller.IdentityID)
		if perr != nil {
			return nil, fmt.Errorf("%w: the calling identity's id is not an identity id", ErrParentIdentityRefused)
		}
		parent, err = s.repo.GetByID(ctx, id.String(), accountID, projectID)
	case caller.WIMSEURI != "":
		parent, err = s.repo.GetByWIMSEURI(ctx, caller.WIMSEURI, accountID, projectID)
	default:
		return nil, fmt.Errorf("%w: the caller names no identity", ErrParentIdentityRefused)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: the caller is not an identity in this account and project", ErrParentIdentityRefused)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve the calling identity: %w", err)
	}
	if caller.IdentityID != "" && caller.WIMSEURI != "" && caller.WIMSEURI != parent.WIMSEURI {
		return nil, fmt.Errorf("%w: the caller's identity id and WIMSE URI name different identities", ErrParentIdentityRefused)
	}
	if !parent.Status.IsUsable() {
		return nil, fmt.Errorf("%w: the calling identity is not active (status: %s)", ErrParentIdentityRefused, parent.Status)
	}
	if parent.IsExpired() {
		return nil, fmt.Errorf("%w: the calling identity has expired", ErrParentIdentityRefused)
	}
	if parent.OwnerUserID == "" {
		return nil, fmt.Errorf("%w: the calling identity has no owner_user_id for its children to inherit", ErrParentIdentityRefused)
	}
	policy, err := s.ResolveCredentialPolicy(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("resolve the calling identity's credential policy: %w", err)
	}
	return &registeringParent{identity: parent, policy: policy}, nil
}

// loadParent loads the parent of child, with its credential policy, for a
// write that changes the child's scope ceilings. The parent need not be
// active: its ceilings bind the child whatever its status. A parent missing
// from the child's tenant is an error, so the write fails closed.
func (s *IdentityService) loadParent(ctx context.Context, child *domain.Identity) (*registeringParent, error) {
	parent, err := s.repo.GetByID(ctx, child.ParentIdentityID, child.AccountID, child.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("load parent identity %s of %s: %w", child.ParentIdentityID, child.ID, err)
	}
	policy, err := s.ResolveCredentialPolicy(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("resolve the credential policy of parent identity %s: %w", parent.ID, err)
	}
	return &registeringParent{identity: parent, policy: policy}, nil
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

// IsRegisteredBy reports whether identityID, in the given tenant, was
// registered by the identity named by parent: whether that identity is its
// parent. Only the direct parent counts, so an identity is not registered by
// its grandparent. An identity outside the tenant, one with no parent, or a
// parent reference that names no identity in the tenant reports false.
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
	if parent.IdentityID != "" {
		if !sameUUID(identity.ParentIdentityID, parent.IdentityID) {
			return false, nil
		}
		if parent.WIMSEURI == "" {
			return true, nil
		}
	} else if parent.WIMSEURI == "" {
		return false, nil
	}
	// The reference names the parent by WIMSE URI, alone or alongside its id:
	// it must be the URI of that parent row.
	row, err := s.repo.GetByID(ctx, identity.ParentIdentityID, accountID, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.WIMSEURI == parent.WIMSEURI, nil
}

// sameUUID reports whether a and b are the same UUID, in any accepted
// spelling. A value that is not a UUID matches nothing.
func sameUUID(a, b string) bool {
	ua, errA := uuid.Parse(a)
	ub, errB := uuid.Parse(b)
	return errA == nil && errB == nil && ua == ub
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
// own allowed_scopes and the credential policy that governs it.
type ceilingLayers struct {
	rowScopes []string
	policy    *domain.CredentialPolicy
}

// own is the ceiling on the identity's own authority: allowed_scopes and the
// policy's allowed_scopes.
func (l ceilingLayers) own() scopeBound {
	var policyScopes []string
	if l.policy != nil {
		policyScopes = l.policy.AllowedScopes
	}
	return boundOf(l.rowScopes, policyScopes)
}

// forPerson is the ceiling on what the identity may hold for a person, where
// the policy's user_grant_scopes takes the place of its allowed_scopes and
// allowed_scopes still binds (docs/scope-ceilings.md).
func (l ceilingLayers) forPerson() scopeBound {
	var userGrantScopes []string
	if l.policy != nil {
		userGrantScopes = l.policy.UserGrantScopes
	}
	return boundOf(l.rowScopes, userGrantScopes)
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
	if policyNamed && child.policy != nil {
		if parentOwn.restricted && len(child.policy.AllowedScopes) == 0 {
			return ceilingError("credential policy %q places no scope ceiling", child.policy.Name)
		}
		for _, scope := range child.policy.AllowedScopes {
			if !parentOwn.allows(scope) {
				return ceilingError("credential policy %q lists %q", child.policy.Name, scope)
			}
		}
		for _, scope := range child.policy.UserGrantScopes {
			if !parentForPerson.allows(scope) {
				return ceilingError("credential policy %q lists %q in user_grant_scopes", child.policy.Name, scope)
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

type deactivationCascadeKey struct{}

// inDeactivationCascade reports whether ctx belongs to a cascade walk, which
// goes on to the identities below whatever it deactivates.
func inDeactivationCascade(ctx context.Context) bool {
	v, _ := ctx.Value(deactivationCascadeKey{}).(bool)
	return v
}

// retiredStatus reports whether s ends an identity's authority, so that the
// identities below it must be deactivated too.
func retiredStatus(s domain.IdentityStatus) bool {
	return s == domain.IdentityStatusDeactivated || s == domain.IdentityStatusExpired
}

// deactivateDescendants deactivates every identity below identity, which has
// already been retired, in its registration tree. Each goes through
// UpdateIdentity, the path a direct deactivation takes, so it gets the same
// API-key sweep, credential revocation cascade and retirement signal, recorded
// with the reason parent_deactivated.
//
// The walk goes a level at a time, and lists a level's children only after
// every identity on it has been deactivated. A child registered under one of
// them before that committed is therefore found, and one registered after is
// refused (IdentityRepository.CreateUnderParent locks the parent row), so a
// concurrent registration cannot leave an active identity behind. Identities
// already deactivated are skipped, but the walk continues below them: an
// identity reactivated after its parent was deactivated is still reached when
// an identity above them both is.
//
// A failure is logged and the walk goes on, so one bad row does not stop the
// rest; ErrCascadeIncomplete reports what was missed. A canceled ctx stops the
// walk the same way. Every step is idempotent, so repeating the deactivation
// finishes the job. Called with a ctx already inside a walk it does nothing:
// that walk goes on below the identity itself.
func (s *IdentityService) deactivateDescendants(ctx context.Context, identity *domain.Identity) error {
	if inDeactivationCascade(ctx) {
		return nil
	}
	ctx = context.WithValue(ctx, deactivationCascadeKey{}, true)
	status := domain.IdentityStatusDeactivated
	seen := map[string]bool{identity.ID: true}
	var deactivated, failed int
	for level := []string{identity.ID}; len(level) > 0; {
		children, err := s.repo.ListChildren(ctx, level, identity.AccountID, identity.ProjectID)
		if err != nil {
			return fmt.Errorf("%w: list the identities below %s: %w", ErrCascadeIncomplete, identity.ID, err)
		}
		next := make([]string, 0, len(children))
		for _, c := range children {
			// A cycle, which the write path cannot create, ends here.
			if seen[c.ID] {
				continue
			}
			seen[c.ID] = true
			next = append(next, c.ID)
			if c.Status == domain.IdentityStatusDeactivated {
				continue
			}
			if ctx.Err() != nil {
				failed++
				continue
			}
			if _, err := s.UpdateIdentity(ctx, c.ID, c.AccountID, c.ProjectID, UpdateIdentityRequest{Status: &status}); err != nil {
				log.Error().Err(err).
					Str("identity_id", c.ID).
					Str("ancestor_id", identity.ID).
					Msg("identity tree: failed to deactivate an identity below a deactivated one")
				failed++
				continue
			}
			deactivated++
		}
		level = next
	}

	if deactivated > 0 {
		log.Info().
			Str("identity_id", identity.ID).
			Int("count", deactivated).
			Msg("identity tree: deactivated the identities below a deactivated identity")
	}
	if failed > 0 {
		return fmt.Errorf("%w: %d of %d identities below %s were not deactivated; repeat the deactivation to finish",
			ErrCascadeIncomplete, failed, deactivated+failed, identity.ID)
	}
	return nil
}
