package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// ScopeRulesMode says what the stricter scope issuance rules do. They are
// counted, never enforced, in this release. See docs/scope-ceilings.md,
// "Stricter scope rules".
type ScopeRulesMode string

const (
	// ScopeRulesModeOff evaluates nothing. The default.
	ScopeRulesModeOff ScopeRulesMode = "off"
	// ScopeRulesModeShadow evaluates the stricter rules on every grant and
	// records each request whose outcome they would change. Every token and
	// every response is exactly what it is with the mode off.
	ScopeRulesModeShadow ScopeRulesMode = "shadow"
)

// ParseScopeRulesMode returns the mode s names, with "" meaning off. Any
// other value is an error, so a typo or a mode this release does not have
// never runs as off unnoticed.
func ParseScopeRulesMode(s string) (ScopeRulesMode, error) {
	switch ScopeRulesMode(s) {
	case "", ScopeRulesModeOff:
		return ScopeRulesModeOff, nil
	case ScopeRulesModeShadow:
		return ScopeRulesModeShadow, nil
	case "enforce":
		return "", fmt.Errorf("scope rules mode %q is not available yet; use %q to count what it would change", s, ScopeRulesModeShadow)
	}
	return "", fmt.Errorf("unknown scope rules mode %q (want %q or %q)", s, ScopeRulesModeOff, ScopeRulesModeShadow)
}

// scopeRulesState holds the mode. Kept apart from the constructor's fields so
// the setter can run concurrently with issuance.
type scopeRulesState struct {
	shadow atomic.Bool
}

// SetScopeRulesMode sets the stricter scope rules' mode. An empty or unknown
// mode is rejected and leaves the mode unchanged.
func (s *CredentialService) SetScopeRulesMode(mode ScopeRulesMode) error {
	if mode == "" {
		return fmt.Errorf("scope rules mode is empty; use %q or %q", ScopeRulesModeOff, ScopeRulesModeShadow)
	}
	parsed, err := ParseScopeRulesMode(string(mode))
	if err != nil {
		return err
	}
	s.scopeRules.shadow.Store(parsed == ScopeRulesModeShadow)
	return nil
}

// The stricter scope rules, by the name each is recorded under.
const (
	// scopeRuleOmittedRequest (rule A): a request that names no scope is
	// issued an API key's stored scopes or an audience profile's scopes, and
	// otherwise none.
	scopeRuleOmittedRequest = "omitted_request"
	// scopeRuleListing (rule B): a scope is issued only when a ceiling the
	// deployer controls lists it. A client's own metadata is a request, not
	// a listing, and an empty ceiling neither lists nor excludes.
	scopeRuleListing = "listing"
	// scopeRuleAllOrNothing (rule C): a request that would be narrowed is
	// refused whole, and a delegation that names no scope is issued none.
	scopeRuleAllOrNothing = "all_or_nothing"
	// scopeRuleOneCode (rule D): every scope refusal answers invalid_scope.
	scopeRuleOneCode = "one_code"
)

// scopeRuleMsg is the stable log message for a request the stricter scope
// rules would change.
const scopeRuleMsg = "scope_rule_would_change"

// scopeTraceGrantIDJAG names an ID-JAG redemption, which shares the
// jwt-bearer grant type with an agent's self-signed assertion.
const scopeTraceGrantIDJAG = "id_jag"

// policyViolationCode is the error code the token endpoint answers a
// credential policy refusal with. No RFC defines it, so oautherror does not
// carry it; it mirrors the token handler's mapping.
const policyViolationCode = "policy_violation"

// openIDScope asks for authentication, not authority. The rules never count
// it as a scope that was dropped, unlisted or issued by default, the reading
// the person ceiling and CIBA already give it.
const openIDScope = "openid"

// registrationSourceInternal marks a client created through the admin API,
// the deployer's trusted registration path.
const registrationSourceInternal = "internal"

// clientListsScopes reports whether a client's registered scopes are a
// listing for rule B: the deployer's trusted path created the client. A
// dynamically registered client chose its own scope, and a metadata document
// is published by the client itself, so for those the scope is a request.
func clientListsScopes(c *domain.OAuthClient) bool {
	return c != nil && c.RegistrationSource == registrationSourceInternal
}

// scopeTraceGrant names a /oauth2/token grant in the stricter rules' records,
// or returns "" for a grant they do not evaluate: one an embedder registered
// with RegisterGrant, or an unknown one.
func scopeTraceGrant(grantType string) string {
	switch grantType {
	case "client_credentials":
		return string(domain.GrantTypeClientCredentials)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		return string(domain.GrantTypeJWTBearer)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		return string(domain.GrantTypeTokenExchange)
	case "api_key":
		return string(domain.GrantTypeAPIKey)
	case "authorization_code":
		return string(domain.GrantTypeAuthorizationCode)
	case "refresh_token":
		return string(domain.GrantTypeRefreshToken)
	case string(domain.GrantTypeCIBA):
		return string(domain.GrantTypeCIBA)
	}
	return ""
}

// scopeTraceKey carries a request's scopeTrace on its context.
type scopeTraceKey struct{}

// scopeTrace collects, while a grant runs, what the stricter scope rules need
// to know about one request: what it asked for, the ceilings the deployer
// controls, and what today's rules did with it. It exists only in shadow
// mode, and every method is a no-op on a nil trace, so a grant calls them
// unconditionally. A request runs on one goroutine, so it takes no lock.
type scopeTrace struct {
	grant      string
	clientID   string
	identityID string
	accountID  string
	projectID  string

	// requested is what the request named. asked says the grant recorded
	// it; a request that failed before its scopes mattered is not evaluated.
	requested []string
	asked     bool
	// omittedApplies says rule A can apply: the request chooses its own
	// scopes and nothing the deployer configured supplies its default. False
	// for a refresh (an omitted scope repeats the grant, RFC 6749 §6), for a
	// delegation (rule C covers it), for an API key with stored scopes and
	// for an audience profile (rule A keeps both).
	omittedApplies bool
	// delegation marks an RFC 8693 delegation.
	delegation bool

	// listings are the deployer-controlled ceilings that applied; allListed
	// says the scopes are server-defined (an audience profile). listed says
	// the issuance chokepoint added its ceilings, without which rule B
	// cannot be judged.
	listings  [][]string
	allListed bool
	listed    bool

	// issued is what today's rules issued, once known.
	issued      []string
	issuedKnown bool

	// refusalCode returns the code a refusal reaches the client with and
	// whether it is a scope refusal. nil means the token endpoint's mapping.
	refusalCode func(error) (string, bool)
}

// traceScopes returns ctx carrying a new scopeTrace for one request of grant,
// or ctx unchanged and a nil trace when the rules are off or grant is "".
func (s *CredentialService) traceScopes(ctx context.Context, grant string) (context.Context, *scopeTrace) {
	if s == nil || grant == "" || !s.scopeRules.shadow.Load() {
		return ctx, nil
	}
	t := &scopeTrace{grant: grant}
	return context.WithValue(ctx, scopeTraceKey{}, t), t
}

// scopeTraceFrom returns the request's trace, or nil.
func scopeTraceFrom(ctx context.Context) *scopeTrace {
	t, _ := ctx.Value(scopeTraceKey{}).(*scopeTrace)
	return t
}

// setGrant renames the grant, for a path that shares its grant type.
func (t *scopeTrace) setGrant(grant string) {
	if t != nil {
		t.grant = grant
	}
}

// ask records what the request named, and whether rule A can apply to it.
func (t *scopeTrace) ask(requested []string, omittedApplies bool) {
	if t == nil {
		return
	}
	t.requested = slices.Clone(requested)
	t.asked = true
	t.omittedApplies = omittedApplies
}

// markDelegation records that the request is an RFC 8693 delegation.
func (t *scopeTrace) markDelegation() {
	if t != nil {
		t.delegation = true
	}
}

// addListing records a deployer-controlled ceiling that applied.
func (t *scopeTrace) addListing(scopes []string) {
	if t != nil && len(scopes) > 0 {
		t.listings = append(t.listings, slices.Clone(scopes))
	}
}

// listAll records that the scopes are server-defined, so all are listed.
func (t *scopeTrace) listAll() {
	if t != nil {
		t.allListed = true
	}
}

// setClient records the client the token is issued to, and its registered
// scopes as a listing when the deployer's trusted path created it.
func (t *scopeTrace) setClient(c *domain.OAuthClient) {
	if t == nil || c == nil {
		return
	}
	t.setClientID(c.ClientID)
	if clientListsScopes(c) {
		t.addListing(c.Scopes)
	}
}

// setClientID records the client the token is issued to.
func (t *scopeTrace) setClientID(clientID string) {
	if t != nil && clientID != "" {
		t.clientID = clientID
	}
}

// setIdentity records the identity the token is for and its tenant.
func (t *scopeTrace) setIdentity(identity *domain.Identity) {
	if t == nil || identity == nil {
		return
	}
	t.setIdentityID(identity.ID)
	t.setTenant(identity.AccountID, identity.ProjectID)
}

// setIdentityID records the ID of the identity the token is for.
func (t *scopeTrace) setIdentityID(id string) {
	if t != nil && id != "" {
		t.identityID = id
	}
}

// setTenant records the request's tenant.
func (t *scopeTrace) setTenant(accountID, projectID string) {
	if t == nil {
		return
	}
	if accountID != "" {
		t.accountID = accountID
	}
	if projectID != "" {
		t.projectID = projectID
	}
}

// minted records, at the issuance chokepoint, the scopes a token was issued
// and the deployer-controlled ceilings the chokepoint applied.
func (t *scopeTrace) minted(scopes []string, listings ...[]string) {
	if t == nil {
		return
	}
	for _, l := range listings {
		t.addListing(l)
	}
	t.listed = true
	t.issued = slices.Clone(scopes)
	t.issuedKnown = true
}

// codeIssued records the scopes an authorization code carries. No token is
// minted, so rule B is judged when the code is redeemed.
func (t *scopeTrace) codeIssued(scopes []string) {
	if t == nil {
		return
	}
	t.issued = slices.Clone(scopes)
	t.issuedKnown = true
}

// deliveredByPush records that a refusal reaches a CIBA push client as a
// notification rather than a token response.
func (t *scopeTrace) deliveredByPush() {
	if t != nil {
		t.refusalCode = pushScopeRefusalCode
	}
}

// done compares the request's outcome, err or the scopes issued, with what
// the stricter rules would do, and records each rule that would change it.
// It never changes the outcome.
func (t *scopeTrace) done(ctx context.Context, err error) {
	if t == nil || !t.asked {
		return
	}
	var today scopeOutcome
	switch {
	case err != nil:
		codeOf := t.refusalCode
		if codeOf == nil {
			codeOf = scopeRefusalCode
		}
		code, ok := codeOf(err)
		if !ok {
			return
		}
		today = scopeOutcome{refused: true, code: code}
	case t.issuedKnown:
		today = scopeOutcome{scopes: t.issued}
	default:
		return
	}
	for _, c := range t.changes(today) {
		t.record(ctx, today, c)
	}
}

// scopeOutcome is how a request ends: issued scopes, or refused with code.
type scopeOutcome struct {
	refused bool
	code    string
	scopes  []string
}

// refusedInvalidScope is the stricter rules' only refusal.
var refusedInvalidScope = scopeOutcome{refused: true, code: oautherror.InvalidScope}

// scopeRuleChange is one rule's different outcome for a request.
type scopeRuleChange struct {
	rule  string
	would scopeOutcome
	// unlisted names the scopes no ceiling lists (rule B).
	unlisted []string
}

// changes returns each stricter rule whose outcome for the request differs
// from today's. Each rule is judged on its own against today's outcome.
func (t *scopeTrace) changes(today scopeOutcome) []scopeRuleChange {
	var out []scopeRuleChange
	named := len(t.requested) > 0

	// A: a request that names no scope gets none, unless the deployer
	// configured its default (omittedApplies is false then).
	// A request refused today stays refused: a token with no scopes claim is
	// never a stricter outcome than a refusal.
	if t.omittedApplies && !named && !today.refused && len(authorityScopes(today.scopes)) > 0 {
		out = append(out, scopeRuleChange{rule: scopeRuleOmittedRequest, would: scopeOutcome{}})
	}

	// B: a scope is issued only when a deployer-controlled ceiling lists it.
	if !today.refused && t.listed {
		if listed, unlisted := t.splitListed(today.scopes); len(unlisted) > 0 {
			would := scopeOutcome{scopes: listed}
			if len(authorityScopes(listed)) == 0 {
				would = refusedInvalidScope
			}
			out = append(out, scopeRuleChange{rule: scopeRuleListing, would: would, unlisted: unlisted})
		}
	}

	// C: a request is issued what it named, or refused.
	if named && !today.refused && len(droppedScopes(t.requested, today.scopes)) > 0 {
		out = append(out, scopeRuleChange{rule: scopeRuleAllOrNothing, would: refusedInvalidScope})
	}
	if t.delegation && !named && today.refused {
		out = append(out, scopeRuleChange{rule: scopeRuleAllOrNothing, would: scopeOutcome{}})
	}

	// D: a scope refusal answers invalid_scope.
	if today.refused && today.code != oautherror.InvalidScope {
		out = append(out, scopeRuleChange{rule: scopeRuleOneCode, would: refusedInvalidScope})
	}
	return out
}

// splitListed splits scopes into those a deployer-controlled ceiling lists
// and those none does. openid is always listed.
func (t *scopeTrace) splitListed(scopes []string) (listed, unlisted []string) {
	for _, sc := range scopes {
		ok := t.allListed || sc == openIDScope
		for _, l := range t.listings {
			ok = ok || slices.Contains(l, sc)
		}
		if ok {
			listed = append(listed, sc)
		} else {
			unlisted = append(unlisted, sc)
		}
	}
	return listed, unlisted
}

// authorityScopes returns scopes without openid.
func authorityScopes(scopes []string) []string {
	var out []string
	for _, sc := range scopes {
		if sc != openIDScope {
			out = append(out, sc)
		}
	}
	return out
}

// droppedScopes returns the scopes requested names that issued lacks,
// openid aside.
func droppedScopes(requested, issued []string) []string {
	var out []string
	for _, sc := range authorityScopes(requested) {
		if !slices.Contains(issued, sc) && !slices.Contains(out, sc) {
			out = append(out, sc)
		}
	}
	return out
}

// record counts one rule change and logs it. The log names the client, the
// identity and the scopes; never a token, a secret or a person.
func (t *scopeTrace) record(ctx context.Context, today scopeOutcome, c scopeRuleChange) {
	telemetry.ScopeRuleWouldChange.Add(ctx, 1, metric.WithAttributes(
		attribute.String("mode", string(ScopeRulesModeShadow)),
		attribute.String("rule", c.rule),
		attribute.String("grant_type", t.grant),
		attribute.String("account_id", t.accountID),
		attribute.String("project_id", t.projectID),
	))
	ev := log.Info().
		Str("mode", string(ScopeRulesModeShadow)).
		Str("rule", c.rule).
		Str("grant_type", t.grant).
		Str("client_id", t.clientID).
		Str("identity_id", t.identityID).
		Str("account_id", t.accountID).
		Str("project_id", t.projectID).
		Strs("requested_scopes", nonNilScopes(t.requested))
	ev = today.log(ev, "today")
	ev = c.would.log(ev, "would")
	if len(c.unlisted) > 0 {
		ev = ev.Strs("unlisted_scopes", c.unlisted)
	}
	ev.Msg(scopeRuleMsg)
}

// log adds the outcome to ev as prefix ("issued" or "refused"), with
// prefix_scopes or prefix_code.
func (o scopeOutcome) log(ev *zerolog.Event, prefix string) *zerolog.Event {
	if o.refused {
		return ev.Str(prefix, "refused").Str(prefix+"_code", o.code)
	}
	return ev.Str(prefix, "issued").Strs(prefix+"_scopes", nonNilScopes(o.scopes))
}

// nonNilScopes returns scopes, or an empty list for nil, so a log line always
// carries the field as an array.
func nonNilScopes(scopes []string) []string {
	if scopes == nil {
		return []string{}
	}
	return scopes
}

// scopeRefusalCode returns the error code the token endpoint answers err
// with, and whether err refuses the request over its scopes. Any other
// failure is outside what the stricter rules change. It mirrors the token
// handler's mapping: an OAuth error carries its own code, and the issuance
// sentinels map as the handler maps them.
func scopeRefusalCode(err error) (string, bool) {
	scopeCause := errors.Is(err, ErrScopesNotAllowed) || errors.Is(err, ErrPersonScopeDenied) || isPolicyScopeViolation(err)
	var oe *OAuthError
	if errors.As(err, &oe) {
		return oe.Code, oe.Code == oautherror.InvalidScope || scopeCause
	}
	switch {
	case errors.Is(err, ErrPolicyViolation):
		return policyViolationCode, isPolicyScopeViolation(err)
	case errors.Is(err, ErrScopesNotAllowed):
		return oautherror.InsufficientScope, true
	case errors.Is(err, ErrPersonScopeDenied):
		return oautherror.InvalidScope, true
	}
	return "", false
}

// pushScopeRefusalCode is scopeRefusalCode for a CIBA push client, which is
// sent a person-ceiling refusal as access_denied (CIBA Core §12).
func pushScopeRefusalCode(err error) (string, bool) {
	if errors.Is(err, ErrPersonScopeDenied) {
		return oautherror.AccessDenied, true
	}
	return scopeRefusalCode(err)
}

// scopeListings returns the ceilings IssueCredential applied that the
// deployer controls: the identity's allowed_scopes, its governing policy's
// ceiling (user_grant_scopes for a chain bounded by a person's grant), and
// the API key's own policy.
func scopeListings(req IssueRequest, principal resolvedPrincipal, identityPolicy, keyPolicy *domain.CredentialPolicy) [][]string {
	listings := [][]string{req.Identity.AllowedScopes}
	enforced := EnforcePolicyRequest{PrincipalType: principal.Type, UserGrantBounded: req.UserGrantBounded}
	for _, p := range []*domain.CredentialPolicy{identityPolicy, keyPolicy} {
		if p != nil {
			listings = append(listings, scopeCeiling(p, enforced))
		}
	}
	return listings
}
