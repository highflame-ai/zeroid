package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// enforceTrace returns a trace for grant in enforce mode, and its context.
func enforceTrace(t *testing.T, grant string) (context.Context, *scopeTrace) {
	t.Helper()
	svc := &CredentialService{}
	require.NoError(t, svc.SetScopeRulesMode(ScopeRulesModeEnforce))
	ctx, tr := svc.traceScopes(context.Background(), grant)
	require.NotNil(t, tr)
	require.True(t, tr.enforcing())
	return ctx, tr
}

// TestScopeRulesEnforce_Outcome combines each rule's change, as changes
// judges it, into the one outcome enforcement gives. Every case with no
// change keeps today's outcome, so enforce changes exactly what shadow
// records.
func TestScopeRulesEnforce_Outcome(t *testing.T) {
	issued := func(s ...string) scopeOutcome { return scopeOutcome{scopes: s} }
	refused := func(code string) scopeOutcome { return scopeOutcome{refused: true, code: code} }

	for _, tc := range []struct {
		name  string
		trace scopeTrace
		today scopeOutcome
		want  scopeOutcome
	}{
		{
			name:  "A: an omitted request loses its default and still succeeds",
			trace: scopeTrace{asked: true, omittedApplies: true, listed: true, listings: [][]string{{"a", "b"}}},
			today: issued("a", "b"),
			want:  issued(),
		},
		{
			name:  "A then B: a default no ceiling lists is dropped, not refused",
			trace: scopeTrace{asked: true, omittedApplies: true, listed: true},
			today: issued("a"),
			want:  issued(),
		},
		{
			name:  "A keeps openid",
			trace: scopeTrace{asked: true, omittedApplies: true, listed: true},
			today: issued("openid", "a"),
			want:  issued("openid"),
		},
		{
			name:  "A: an omitted request refused today stays refused",
			trace: scopeTrace{asked: true, omittedApplies: true},
			today: refused(oautherror.InvalidScope),
			want:  refused(oautherror.InvalidScope),
		},
		{
			name:  "an API key's own scopes are kept for an omitted request",
			trace: scopeTrace{asked: true, listed: true, listings: [][]string{{"a"}}},
			today: issued("a"),
			want:  issued("a"),
		},
		{
			name:  "B: one listed and one unlisted scope is refused whole",
			trace: scopeTrace{asked: true, requested: []string{"a", "b"}, listed: true, listings: [][]string{{"a"}}},
			today: issued("a", "b"),
			want:  refusedInvalidScope,
		},
		{
			name:  "B: empty ceilings everywhere list nothing",
			trace: scopeTrace{asked: true, requested: []string{"a"}, listed: true, listings: [][]string{{}}},
			today: issued("a"),
			want:  refusedInvalidScope,
		},
		{
			name:  "C: a narrowed request is refused whole",
			trace: scopeTrace{asked: true, requested: []string{"a", "b"}, listed: true, listings: [][]string{{"a", "b"}}},
			today: issued("a"),
			want:  refusedInvalidScope,
		},
		{
			name:  "C: a delegation that names no scope is issued none",
			trace: scopeTrace{asked: true, delegation: true},
			today: refused(oautherror.InvalidScope),
			want:  issued(),
		},
		{
			name:  "C: a delegation naming scopes none of which survive stays refused",
			trace: scopeTrace{asked: true, delegation: true, requested: []string{"a"}},
			today: refused(oautherror.InvalidScope),
			want:  refused(oautherror.InvalidScope),
		},
		{
			name:  "D: a scope refusal with another code answers invalid_scope",
			trace: scopeTrace{asked: true, requested: []string{"a"}},
			today: refused(policyViolationCode),
			want:  refusedInvalidScope,
		},
		{
			name:  "nothing changes a listed, unnarrowed request",
			trace: scopeTrace{asked: true, requested: []string{"a"}, listed: true, listings: [][]string{{"a"}}},
			today: issued("a"),
			want:  issued("a"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := tc.trace
			changes := tr.changes(tc.today)
			got := tr.enforcedOutcome(tc.today, changes)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, len(changes) == 0, assert.ObjectsAreEqual(tc.today, got),
				"enforce changes a request exactly when shadow records a change")
		})
	}
}

// Reserved scopes are exempt in enforce exactly as in shadow: an omitted
// request keeps the key's reserved scope, and a reserved scope is never
// judged unlisted or narrowed.
func TestScopeRulesEnforce_ReservedScopesExempt(t *testing.T) {
	r := &ReservedScopes{}
	require.NoError(t, r.Set([]string{"deployer."}, allowAll, 0))
	tr := scopeTrace{asked: true, omittedApplies: true, listed: true, reserved: r, enf: &scopeEnforcement{}}

	got, err := tr.enforceScopes([]string{"a", "deployer.admin"})
	require.NoError(t, err)
	assert.Equal(t, []string{"deployer.admin"}, got, "rule A keeps the key's reserved scope")

	named := scopeTrace{asked: true, requested: []string{"a", "deployer.admin"}, listed: true, listings: [][]string{{"a"}}, reserved: r, enf: &scopeEnforcement{}}
	got, err = named.enforceScopes([]string{"a"})
	require.NoError(t, err, "a dropped reserved scope is the reserved-scope rules' decision, not a narrowing")
	assert.Equal(t, []string{"a"}, got)
}

// enforceScopes refuses with invalid_scope, naming the first offending scope
// and the ceiling that must list it, and drops a default rule A removes.
func TestScopeRulesEnforce_Decide(t *testing.T) {
	t.Run("C names the ceiling that left the scope out", func(t *testing.T) {
		_, tr := enforceTrace(t, "jwt_bearer")
		tr.ask([]string{"a", "b", "c"}, true)
		tr.ceiling(policyCeilingName(ownerIdentity, false), []string{"a", "b"})
		tr.ceiling(ceilingIdentityScopes, []string{"a"})
		tr.chokepoint([][]string{{"a"}, {"a", "b"}})
		_, err := tr.enforceScopes([]string{"a"})
		var oe *OAuthError
		require.ErrorAs(t, err, &oe)
		assert.Equal(t, oautherror.InvalidScope, oe.Code)
		assert.Equal(t, "scope b is not granted: the identity's allowed_scopes must list it", oe.Description)
		assert.ErrorIs(t, err, errScopeRulesRefusal)
		assert.True(t, issuanceRefusal(err), "grants that wrap issuance errors pass it through")
	})

	t.Run("B names where the scope can be listed", func(t *testing.T) {
		_, tr := enforceTrace(t, "api_key")
		tr.ask([]string{"a", "b"}, true)
		tr.listableIn(ceilingAPIKeyScopes)
		tr.listableIn(ceilingIdentityScopes)
		tr.chokepoint([][]string{{"a"}})
		_, err := tr.enforceScopes([]string{"a", "b"})
		require.Error(t, err)
		assert.Equal(t, "scope b is not granted: no scope ceiling an administrator controls lists it; "+
			"list it in the API key's scopes or the identity's allowed_scopes", errorDescription(err))
	})

	t.Run("B with no ceiling that applies", func(t *testing.T) {
		_, tr := enforceTrace(t, "authorization_code")
		tr.ask([]string{"a"}, false)
		tr.chokepoint(nil)
		_, err := tr.enforceScopes([]string{"a"})
		assert.Equal(t, "scope a is not granted: no scope ceiling an administrator controls applies to this request, so none lists it", errorDescription(err))
	})

	t.Run("A drops the default", func(t *testing.T) {
		_, tr := enforceTrace(t, "client_credentials")
		tr.ask(nil, true)
		tr.chokepoint([][]string{{"a", "b"}})
		got, err := tr.enforceScopes([]string{"a", "b"})
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("shadow decides nothing", func(t *testing.T) {
		svc := &CredentialService{}
		require.NoError(t, svc.SetScopeRulesMode(ScopeRulesModeShadow))
		_, tr := svc.traceScopes(context.Background(), "jwt_bearer")
		tr.ask([]string{"a"}, true)
		tr.chokepoint(nil)
		got, err := tr.enforceScopes([]string{"a"})
		require.NoError(t, err)
		assert.Equal(t, []string{"a"}, got)
		var nilTrace *scopeTrace
		got, err = nilTrace.enforceScopes([]string{"a"})
		require.NoError(t, err)
		assert.Equal(t, []string{"a"}, got)
	})
}

// answer is rule D: every scope refusal is invalid_scope with a description
// naming the scope and its ceiling; other failures, reserved-scope refusals
// and every error outside enforce mode are untouched.
func TestScopeRulesEnforce_Answer(t *testing.T) {
	t.Run("an insufficient_scope refusal becomes invalid_scope", func(t *testing.T) {
		_, tr := enforceTrace(t, "token_exchange")
		tr.ask([]string{"a"}, false)
		tr.ceiling(ceilingIdentityScopes, []string{"b"})
		cause := fmt.Errorf("%w: %q not in allowed_scopes", ErrScopesNotAllowed, "a")
		err := tr.answer(cause)
		var oe *OAuthError
		require.ErrorAs(t, err, &oe)
		assert.Equal(t, oautherror.InvalidScope, oe.Code)
		assert.Equal(t, "scope a is not granted: the identity's allowed_scopes must list it", oe.Description)
		assert.ErrorIs(t, err, ErrScopesNotAllowed, "the original refusal stays the cause")
	})

	t.Run("a policy refusal with no recorded ceiling keeps its text", func(t *testing.T) {
		_, tr := enforceTrace(t, "external_principal")
		tr.ask([]string{"a"}, true)
		cause := policyScopeViolation{err: fmt.Errorf("%w: scope a not allowed", ErrPolicyViolation)}
		err := tr.answer(cause)
		var oe *OAuthError
		require.ErrorAs(t, err, &oe)
		assert.Equal(t, oautherror.InvalidScope, oe.Code)
		assert.Equal(t, cause.Error(), oe.Description)
	})

	t.Run("an invalid_scope refusal is renamed only when a ceiling explains it", func(t *testing.T) {
		_, tr := enforceTrace(t, "token_exchange")
		tr.ask([]string{"a"}, false)
		orig := oauthBadRequest(oautherror.InvalidScope, "no scopes were requested")
		assert.Same(t, orig, tr.answer(orig))
		tr.strictCeiling(ceilingSubjectToken, nil)
		assert.Equal(t, "scope a is not granted: the subject token's scopes must list it", errorDescription(tr.answer(orig)))
	})

	t.Run("the rules' own refusal is unwrapped from a grant's wrapper", func(t *testing.T) {
		_, tr := enforceTrace(t, "ciba")
		tr.ask([]string{"a"}, true)
		own := scopeRulesRefusal("scope a is not granted: x must list it")
		assert.Same(t, own, tr.answer(oauthServerError("wrapped", fmt.Errorf("mint: %w", own))))
	})

	t.Run("untouched", func(t *testing.T) {
		_, tr := enforceTrace(t, "client_credentials")
		tr.ask([]string{"a"}, true)
		grantErr := oauthBadRequest(oautherror.UnauthorizedClient, "client not authorized")
		assert.Same(t, grantErr, tr.answer(grantErr), "a refusal that is not over scopes")
		policyErr := fmt.Errorf("%w: trust level", ErrPolicyViolation)
		assert.Equal(t, policyErr, tr.answer(policyErr), "a policy refusal on another axis")

		tr.refusedByReservedScopes()
		reserved := fmt.Errorf("%w: reserved", ErrScopesNotAllowed)
		assert.Equal(t, reserved, tr.answer(reserved), "the reserved-scope rules' refusal")

		_, unasked := enforceTrace(t, "client_credentials")
		assert.Equal(t, reserved, unasked.answer(reserved), "a request the grant never described")

		svc := &CredentialService{}
		require.NoError(t, svc.SetScopeRulesMode(ScopeRulesModeShadow))
		_, shadow := svc.traceScopes(context.Background(), "client_credentials")
		shadow.ask([]string{"a"}, true)
		assert.Equal(t, reserved, shadow.answer(reserved), "shadow answers as off does")
	})
}

// issuesRefusedDelegation issues only a delegation that named no scope.
func TestScopeRulesEnforce_RefusedDelegation(t *testing.T) {
	denial := oauthBadRequest(oautherror.InvalidScope, "no scopes were requested")

	_, tr := enforceTrace(t, "token_exchange")
	tr.ask(nil, false)
	tr.markDelegation()
	assert.True(t, tr.issuesRefusedDelegation(denial))

	_, named := enforceTrace(t, "token_exchange")
	named.ask([]string{"a"}, false)
	named.markDelegation()
	assert.False(t, named.issuesRefusedDelegation(denial), "a delegation the ceilings cannot cover stays refused")

	_, notScope := enforceTrace(t, "token_exchange")
	notScope.ask(nil, false)
	notScope.markDelegation()
	assert.False(t, notScope.issuesRefusedDelegation(oauthBadRequest(oautherror.InvalidGrant, "bad")))
}

// In enforce, each change is recorded with mode=enforce and the outcome the
// request was given, judged against today's outcome as it stood before
// enforcement changed it, so the judgement is the one shadow records.
func TestScopeRulesEnforce_Records(t *testing.T) {
	points, lines := captureScopeRules(t)
	ctx, tr := enforceTrace(t, "client_credentials")
	tr.ask([]string{"a", "b"}, true)
	tr.setClient(&domain.OAuthClient{ClientID: "client-1", RegistrationSource: "dynamic", Scopes: []string{"a", "b"}})
	tr.setIdentity(&domain.Identity{ID: "identity-1", AccountID: "acct", ProjectID: "proj"})
	tr.chokepoint([][]string{{"a"}})
	_, err := tr.enforceScopes([]string{"a", "b"})
	require.Error(t, err)
	tr.done(ctx, oauthServerError("wrapped", err))

	assert.Equal(t, []map[string]string{{
		"mode": "enforce", "rule": "listing", "grant_type": "client_credentials",
		"account_id": "acct", "project_id": "proj",
	}}, points())
	got := lines()
	require.Len(t, got, 1)
	assert.Equal(t, "enforce", got[0]["mode"])
	assert.Equal(t, "issued", got[0]["today"])
	assert.Equal(t, []any{"a", "b"}, got[0]["today_scopes"])
	assert.Equal(t, "refused", got[0]["would"])
	assert.Equal(t, "invalid_scope", got[0]["would_code"])
	assert.Equal(t, []any{"b"}, got[0]["unlisted_scopes"])
}

// A CIBA push client is sent CIBA Core §12 codes, so rule D is not applied to
// it and not recorded in enforce mode, and a refusal by the rules is sent as
// access_denied with the rules' description.
func TestScopeRulesEnforce_Push(t *testing.T) {
	points, _ := captureScopeRules(t)
	ctx, tr := enforceTrace(t, "ciba")
	tr.deliveredByPush()
	tr.ask([]string{"a"}, true)
	tr.done(ctx, ErrPersonScopeDenied)
	assert.Empty(t, points())

	code, desc, ok := pushRefusal(oauthServerError("x", scopeRulesRefusal("scope a is not granted: y must list it")))
	assert.True(t, ok)
	assert.Equal(t, oautherror.AccessDenied, code)
	assert.Equal(t, "scope a is not granted: y must list it", desc)

	_, _, ok = pushRefusal(errors.New("lost race"))
	assert.False(t, ok)
}

func TestOrList(t *testing.T) {
	assert.Equal(t, "", orList(nil))
	assert.Equal(t, "a", orList([]string{"a"}))
	assert.Equal(t, "a or b", orList([]string{"a", "b"}))
	assert.Equal(t, "a, b or c", orList([]string{"a", "b", "c"}))
}
