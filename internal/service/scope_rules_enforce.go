package service

import (
	"errors"
	"slices"
	"strings"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// Enforce mode for the stricter scope rules (token.scope_rules=enforce).
//
// Enforcement is the shadow evaluation, applied. changes judges a request
// exactly as it does in shadow mode, and enforcedOutcome combines the changes
// it returns into the one outcome the request is given. A request with no
// change is untouched, so enforce changes a request exactly when shadow would
// record it. The outcome is applied where today's rules decide the request:
//
//   - IssueCredential, after every check today's rules make and before
//     anything is signed or stored (enforceScopes): the token's scopes, or
//     the refusal rules B and C make, or no default for a request rule A
//     covers.
//   - IssueAuthCode, where a code's scopes are decided (enforceScopes): rules
//     A and C. Rule B is judged when the code is redeemed, as in shadow mode.
//   - Token exchange, which refuses a delegation that names no scope before
//     anything is minted (issuesRefusedDelegation): rule C issues it with
//     none.
//   - The token and authorization endpoints, for every scope refusal
//     (answer): rule D answers invalid_scope, naming the first offending
//     scope and the ceiling that must list it.
//
// done then records each change, as in shadow mode, with mode=enforce and the
// outcome the request was given. Every other request refused today stays
// refused: enforcement never turns a refusal into a token, except the
// delegation rule C issues.

// scopeEnforcement is what a trace keeps in enforce mode.
type scopeEnforcement struct {
	// today is today's outcome, kept where enforcement changed it, so done
	// judges and records the change against it as shadow mode would.
	today *scopeOutcome
	// ceilings are the ceilings that narrowed or refused the request, in the
	// order they applied, for a refusal's description.
	ceilings []namedCeiling
	// listable names the deployer-controlled ceilings that apply to the
	// request: where a refusal by rule B says a scope can be listed.
	listable []string
}

// namedCeiling is a scope ceiling and the name a refusal gives it.
type namedCeiling struct {
	name   string
	scopes []string
	// strict says an empty ceiling grants nothing, where an empty ceiling
	// otherwise places no restriction.
	strict bool
}

// excludes reports whether the ceiling leaves sc out.
func (c namedCeiling) excludes(sc string) bool {
	return (c.strict || len(c.scopes) > 0) && !slices.Contains(c.scopes, sc)
}

// What a refusal names as the ceiling that must list a scope.
const (
	ceilingClientScopes     = "the client's registered scopes"
	ceilingClientDocument   = "the client metadata document's scope"
	ceilingIdentityScopes   = "the identity's allowed_scopes"
	ceilingAPIKeyScopes     = "the API key's scopes"
	ceilingSubjectToken     = "the subject token's scopes"
	ceilingActorScopes      = "the actor's allowed_scopes"
	ceilingPersonScopes     = "the person's scope ceiling"
	ceilingPrincipalScopes  = "the authenticated principal's scopes"
	ceilingRequestingToken  = "the requesting token's scopes"
	ceilingRequesterScopes  = "the requesting identity's allowed_scopes"
	ceilingBoundScopes      = "the bound identity's allowed_scopes"
	ceilingEveryApplicable  = "every scope ceiling that applies to the request"
	ownerIdentity           = "the identity's"
	ownerTenantDefault      = "the tenant's default"
	ownerAPIKey             = "the API key's"
	ownerActor              = "the actor's"
	ownerRequestingIdentity = "the requesting identity's"
	ownerBoundIdentity      = "the bound identity's"
)

// clientCeilingName names the scopes a client registered, as a refusal names
// them: a client identified by a metadata document publishes its own.
func clientCeilingName(c *domain.OAuthClient) string {
	if c != nil && c.RegistrationSource == domain.RegistrationSourceCIMD {
		return ceilingClientDocument
	}
	return ceilingClientScopes
}

// policyCeilingName names whose credential policy's scope ceiling: its
// user_grant_scopes when it caps a chain acting for a person, else its
// allowed_scopes (scopeCeiling).
func policyCeilingName(whose string, userGrant bool) string {
	if userGrant {
		return whose + " credential policy's user_grant_scopes"
	}
	return whose + " credential policy's allowed_scopes"
}

// identityPolicyOwner names whose credential policy governs identity: its
// own, or, for an identity with no row of its own, the tenant's default.
func identityPolicyOwner(identity *domain.Identity) string {
	if identity != nil && identity.ID != "" {
		return ownerIdentity
	}
	return ownerTenantDefault
}

// errScopeRulesRefusal marks a refusal the stricter rules make in enforce
// mode of a request today's rules would issue.
var errScopeRulesRefusal = errors.New("refused by the stricter scope rules")

// scopeRulesRefusal is the stricter rules' refusal: invalid_scope (RFC 6749
// §5.2).
func scopeRulesRefusal(description string) *OAuthError {
	return oauthBadRequestCause(oautherror.InvalidScope, description, errScopeRulesRefusal)
}

// scopeRulesRefusalIn returns the stricter rules' refusal err carries, or
// nil. A grant that wraps an issuance error keeps it as the cause, so the
// refusal is found wherever it sits in the chain.
func scopeRulesRefusalIn(err error) *OAuthError {
	if err == nil {
		return nil
	}
	if oe, ok := err.(*OAuthError); ok && oe.err == errScopeRulesRefusal { //nolint:errorlint // matching this exact node
		return oe
	}
	switch u := err.(type) { //nolint:errorlint // walking the chain by hand
	case interface{ Unwrap() error }:
		return scopeRulesRefusalIn(u.Unwrap())
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			if oe := scopeRulesRefusalIn(e); oe != nil {
				return oe
			}
		}
	}
	return nil
}

// scopeDenial is a refusal's description: the scope and what it takes to
// grant it. The scope is not quoted: RFC 6749 §5.2 keeps the double quote out
// of error_description, and no scope token contains one (§3.3).
func scopeDenial(scope, reason string) string {
	return "scope " + scope + " is not granted: " + reason
}

// enforcing reports whether the trace enforces the stricter rules.
func (t *scopeTrace) enforcing() bool {
	return t != nil && t.enf != nil
}

// mode is the mode the trace records under.
func (t *scopeTrace) mode() ScopeRulesMode {
	if t.enforcing() {
		return ScopeRulesModeEnforce
	}
	return ScopeRulesModeShadow
}

// priorOutcome returns today's outcome where enforcement changed it and the
// request ended as enforcement decided (err is nil or the rules' refusal), or
// nil. A nil enforcement (shadow mode) returns nil.
func (e *scopeEnforcement) priorOutcome(err error) *scopeOutcome {
	if e == nil || e.today == nil {
		return nil
	}
	if err == nil || scopeRulesRefusalIn(err) != nil {
		return e.today
	}
	return nil
}

// recorded returns the changes done records for a request whose outcome
// today is today: in shadow mode each rule's change as changes judges it; in
// enforce mode the changes enforcement makes, each with the outcome the
// request was given.
func (t *scopeTrace) recorded(today scopeOutcome) []scopeRuleChange {
	changes := t.changes(today)
	if !t.enforcing() {
		return changes
	}
	applied := t.applied(changes)
	given := t.enforcedOutcome(today, applied)
	for i := range applied {
		applied[i].would = given
	}
	return applied
}

// applied returns the changes enforcement makes: every change shadow mode
// records, less rule D's for a CIBA push client. A push client is sent a
// CIBA Core §12 error, whose codes do not include invalid_scope, so a
// refusal sent by push keeps its code.
func (t *scopeTrace) applied(changes []scopeRuleChange) []scopeRuleChange {
	var out []scopeRuleChange
	for _, c := range changes {
		if c.rule == scopeRuleOneCode && t.pushed {
			continue
		}
		out = append(out, c)
	}
	return out
}

// enforcedOutcome is the one outcome the stricter rules give a request whose
// outcome today is today, combined from changes: each rule's change as
// changes judges it on its own.
//
// No change leaves the outcome as it is. A request today's rules refuse stays
// refused, answered invalid_scope (rule D), unless rule C issues it: a
// delegation that names no scope is issued none. A request today's rules
// issue loses the default it was given when it named no scope (rule A,
// keeping openid and reserved scopes), and is then refused whole when a scope
// it is still to be issued is one no ceiling lists (rule B) or when it would
// be narrowed (rule C). No rule adds a scope, and none narrows silently.
func (t *scopeTrace) enforcedOutcome(today scopeOutcome, changes []scopeRuleChange) scopeOutcome {
	if len(changes) == 0 {
		return today
	}
	if today.refused {
		for _, c := range changes {
			if c.rule == scopeRuleAllOrNothing && !c.would.refused {
				return c.would
			}
		}
		return refusedInvalidScope
	}
	out := today.scopes
	for _, c := range changes {
		if c.rule == scopeRuleOmittedRequest {
			var kept []string
			for _, sc := range today.scopes {
				if sc == openIDScope || slices.Contains(c.would.scopes, sc) {
					kept = append(kept, sc)
				}
			}
			out = kept
		}
	}
	for _, c := range changes {
		switch c.rule {
		case scopeRuleListing:
			for _, sc := range c.unlisted {
				if slices.Contains(out, sc) {
					return refusedInvalidScope
				}
			}
		case scopeRuleAllOrNothing:
			if c.would.refused {
				return refusedInvalidScope
			}
		}
	}
	return scopeOutcome{scopes: out}
}

// enforceScopes decides, in enforce mode, the scopes today's rules would
// issue: IssueCredential calls it after every check and before anything is
// signed or stored, IssueAuthCode before the code is built. It returns scopes
// unchanged, the scopes the stricter rules issue instead, or their refusal.
// changes judges scopes exactly as done judges them in shadow mode, so the
// two modes cannot disagree about a request.
func (t *scopeTrace) enforceScopes(scopes []string) ([]string, error) {
	if !t.enforcing() || !t.asked {
		return scopes, nil
	}
	today := scopeOutcome{scopes: slices.Clone(scopes)}
	changes := t.applied(t.changes(today))
	if len(changes) == 0 {
		return scopes, nil
	}
	if t.enf.today == nil {
		t.enf.today = &today
	}
	given := t.enforcedOutcome(today, changes)
	if given.refused {
		return nil, scopeRulesRefusal(t.offense(scopes))
	}
	return given.scopes, nil
}

// issuesRefusedDelegation applies the stricter rules, in enforce mode, to a
// request today's rules refuse with err before anything is minted, and
// reports whether they issue it instead: rule C issues a delegation that
// names no scope with none. Every other refusal stays a refusal.
func (t *scopeTrace) issuesRefusedDelegation(err error) bool {
	if !t.enforcing() || !t.asked {
		return false
	}
	today, ok := t.todayOutcome(err)
	if !ok {
		return false
	}
	given := t.enforcedOutcome(today, t.applied(t.changes(today)))
	if given.refused {
		return false
	}
	t.enf.today = &today
	return true
}

// answer is rule D, in enforce mode, at the token and authorization
// endpoints: a refusal over the request's scopes is answered invalid_scope
// (RFC 6749 §5.2), with a description that names the first offending scope
// and the ceiling that must list it when a recorded ceiling excludes one, and
// otherwise the refusal's own description. The stricter rules' own refusal is
// returned as it was made, wherever a grant wrapped it. Every other error,
// every refusal by the reserved-scope rules, and every error in shadow mode,
// is returned unchanged. The request stays refused, and the original error
// stays the cause.
func (t *scopeTrace) answer(err error) error {
	if err == nil || !t.enforcing() || !t.asked {
		return err
	}
	if r := scopeRulesRefusalIn(err); r != nil {
		return r
	}
	today, ok := t.todayOutcome(err)
	if !ok || t.pushed {
		return err
	}
	desc, found := t.ceilingOffense(t.requested)
	if today.code == oautherror.InvalidScope && !found {
		return err
	}
	if !found {
		desc = refusalDescription(err)
	}
	return oauthBadRequestCause(oautherror.InvalidScope, desc, err)
}

// refusalDescription is the description a scope refusal reaches the client
// with today.
func refusalDescription(err error) string {
	var oe *OAuthError
	if errors.As(err, &oe) && oe.Description != "" {
		return oe.Description
	}
	if errors.Is(err, ErrPersonScopeDenied) {
		return ErrPersonScopeDenied.Error()
	}
	return err.Error()
}

// offense describes the first scope, in the order the request named them,
// that the stricter rules refuse to issue: one a ceiling left out (rule C),
// or one no deployer-controlled ceiling lists (rule B). scopes are the
// scopes today's rules would issue.
func (t *scopeTrace) offense(scopes []string) string {
	var unlisted []string
	if t.listed {
		_, unlisted = t.splitListed(scopes)
	}
	for _, sc := range authorityScopes(t.requested) {
		switch {
		case t.isReserved(sc):
		case !slices.Contains(scopes, sc):
			if c, ok := t.excludedBy(sc); ok {
				return scopeDenial(sc, c.name+" must list it")
			}
			return scopeDenial(sc, ceilingEveryApplicable+" must list it")
		case slices.Contains(unlisted, sc):
			return scopeDenial(sc, t.unlistedReason())
		}
	}
	if len(unlisted) > 0 {
		return scopeDenial(unlisted[0], t.unlistedReason())
	}
	return "the requested scopes are not granted"
}

// ceilingOffense describes the first of requested, in order, that a recorded
// ceiling leaves out, and the first ceiling that does.
func (t *scopeTrace) ceilingOffense(requested []string) (string, bool) {
	for _, sc := range authorityScopes(requested) {
		if t.isReserved(sc) {
			continue
		}
		if c, ok := t.excludedBy(sc); ok {
			return scopeDenial(sc, c.name+" must list it"), true
		}
	}
	return "", false
}

// excludedBy returns the first recorded ceiling that leaves sc out.
func (t *scopeTrace) excludedBy(sc string) (namedCeiling, bool) {
	for _, c := range t.enf.ceilings {
		if c.excludes(sc) {
			return c, true
		}
	}
	return namedCeiling{}, false
}

// unlistedReason says where a scope no deployer-controlled ceiling lists can
// be listed (rule B).
func (t *scopeTrace) unlistedReason() string {
	if len(t.enf.listable) == 0 {
		return "no scope ceiling an administrator controls applies to this request, so none lists it"
	}
	return "no scope ceiling an administrator controls lists it; list it in " + orList(t.enf.listable)
}

// ceiling records, in enforce mode, a ceiling that bounds the request, named
// what, for a refusal's description. An empty ceiling places no restriction.
// It decides nothing.
func (t *scopeTrace) ceiling(what string, scopes []string) {
	if t.enforcing() {
		t.enf.ceilings = append(t.enf.ceilings, namedCeiling{name: what, scopes: slices.Clone(scopes)})
	}
}

// strictCeiling is ceiling for one that grants nothing when empty: the
// subject token's scopes, a person's ceiling.
func (t *scopeTrace) strictCeiling(what string, scopes []string) {
	if t.enforcing() {
		t.enf.ceilings = append(t.enf.ceilings, namedCeiling{name: what, scopes: slices.Clone(scopes), strict: true})
	}
}

// identityCeiling records the identity's own allowed_scopes as a ceiling. An
// identity registered by another identity whose list is empty holds no scope,
// so its list is a strict ceiling that lists nothing; on any other identity an
// empty list places no restriction.
func (t *scopeTrace) identityCeiling(what string, identity *domain.Identity) {
	if identity.ListsNoScope() {
		t.strictCeiling(what, nil)
		return
	}
	t.ceiling(what, identity.AllowedScopes)
}

// listableIn records, in enforce mode, a deployer-controlled ceiling that
// applies to the request, where a refusal by rule B says a scope can be
// listed.
func (t *scopeTrace) listableIn(what string) {
	if t.enforcing() && !slices.Contains(t.enf.listable, what) {
		t.enf.listable = append(t.enf.listable, what)
	}
}

// listableAt records, by name, the ceilings IssueCredential applies that the
// deployer controls (scopeListings).
func (t *scopeTrace) listableAt(req IssueRequest, principal resolvedPrincipal, identityPolicy, keyPolicy *domain.CredentialPolicy) {
	if !t.enforcing() {
		return
	}
	if req.Identity.ID != "" {
		t.listableIn(ceilingIdentityScopes)
	}
	userGrant := req.UserGrantBounded && principal.Type == domain.PrincipalUser
	if identityPolicy != nil {
		t.listableIn(policyCeilingName(identityPolicyOwner(req.Identity), userGrant))
	}
	if keyPolicy != nil {
		t.listableIn(policyCeilingName(ownerAPIKey, userGrant))
	}
}

// policyRefused records, when err is policy's refusal on its scope axis
// (EnforcePolicy), policy's ceiling for req, named for whose policy it is.
func (t *scopeTrace) policyRefused(err error, policy *domain.CredentialPolicy, req EnforcePolicyRequest, whose string) {
	if t.enforcing() && isPolicyScopeViolation(err) {
		userGrant := req.UserGrantBounded && req.PrincipalType == domain.PrincipalUser
		t.ceiling(policyCeilingName(whose, userGrant), scopeCeiling(policy, req))
	}
}

// orList joins names as "a", "a or b", or "a, b or c".
func orList(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}
