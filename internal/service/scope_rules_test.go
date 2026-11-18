package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// captureScopeRules swaps the scope-rules counter and the global logger for
// capturing ones. It returns the counted data points, one map of attributes
// per count, and the decoded scope_rule_would_change log lines.
func captureScopeRules(t *testing.T) (points func() []map[string]string, lines func() []map[string]any) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	counter, err := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).
		Meter("test").Int64Counter("zeroid.scope.rule_would_change")
	require.NoError(t, err)
	origCounter := telemetry.ScopeRuleWouldChange
	telemetry.ScopeRuleWouldChange = counter

	buf := &bytes.Buffer{}
	origLogger, origLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(buf)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() {
		telemetry.ScopeRuleWouldChange = origCounter
		log.Logger = origLogger
		zerolog.SetGlobalLevel(origLevel)
	})

	points = func() []map[string]string {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		var out []map[string]string
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					continue
				}
				for _, dp := range sum.DataPoints {
					attrs := map[string]string{}
					for _, kv := range dp.Attributes.ToSlice() {
						attrs[string(kv.Key)] = kv.Value.AsString()
					}
					for range dp.Value {
						out = append(out, attrs)
					}
				}
			}
		}
		return out
	}
	lines = func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &m))
			if m["message"] == scopeRuleMsg {
				out = append(out, m)
			}
		}
		return out
	}
	return points, lines
}

func TestParseScopeRulesMode(t *testing.T) {
	for in, want := range map[string]ScopeRulesMode{"": ScopeRulesModeOff, "off": ScopeRulesModeOff, "shadow": ScopeRulesModeShadow} {
		got, err := ParseScopeRulesMode(in)
		require.NoError(t, err, "mode %q", in)
		assert.Equal(t, want, got, "mode %q", in)
	}

	_, err := ParseScopeRulesMode("enforce")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available yet", "enforce is named as not yet available, not as unknown")

	for _, in := range []string{"on", "Shadow", "count"} {
		_, err := ParseScopeRulesMode(in)
		assert.Error(t, err, "mode %q must be refused", in)
	}
}

// A wiring mistake never changes the mode, and only shadow creates a trace.
func TestSetScopeRulesMode(t *testing.T) {
	svc := &CredentialService{}
	ctx := context.Background()
	_, trace := svc.traceScopes(ctx, "client_credentials")
	assert.Nil(t, trace, "off by default")

	require.NoError(t, svc.SetScopeRulesMode(ScopeRulesModeShadow))
	traced, trace := svc.traceScopes(ctx, "client_credentials")
	require.NotNil(t, trace)
	assert.Same(t, trace, scopeTraceFrom(traced))

	_, untraced := svc.traceScopes(ctx, "")
	assert.Nil(t, untraced, "a grant the rules do not evaluate gets no trace")

	for _, bad := range []ScopeRulesMode{"", "enforce", "bogus"} {
		assert.Error(t, svc.SetScopeRulesMode(bad), "mode %q", bad)
		_, still := svc.traceScopes(ctx, "client_credentials")
		assert.NotNil(t, still, "a refused mode %q leaves shadow on", bad)
	}

	require.NoError(t, svc.SetScopeRulesMode(ScopeRulesModeOff))
	_, trace = svc.traceScopes(ctx, "client_credentials")
	assert.Nil(t, trace)

	var nilSvc *CredentialService
	_, trace = nilSvc.traceScopes(ctx, "client_credentials")
	assert.Nil(t, trace)
}

// With the mode off a grant holds a nil trace and calls it anyway.
func TestScopeTrace_NilIsANoOp(t *testing.T) {
	points, lines := captureScopeRules(t)
	var tr *scopeTrace
	assert.NotPanics(t, func() {
		tr.setGrant("x")
		tr.ask([]string{"a"}, true)
		tr.markDelegation()
		tr.addListing([]string{"a"})
		tr.listAll()
		tr.setClient(&domain.OAuthClient{ClientID: "c", RegistrationSource: "internal", Scopes: []string{"a"}})
		tr.setClientID("c")
		tr.setIdentity(&domain.Identity{ID: "i"})
		tr.setIdentityID("i")
		tr.setTenant("a", "p")
		tr.minted([]string{"a"}, []string{"a"})
		tr.codeIssued([]string{"a"})
		tr.deliveredByPush()
		tr.done(context.Background(), nil)
		tr.done(context.Background(), ErrScopesNotAllowed)
	})
	assert.Empty(t, points())
	assert.Empty(t, lines())
	assert.Nil(t, scopeTraceFrom(context.Background()))
}

func TestClientListsScopes(t *testing.T) {
	assert.True(t, clientListsScopes(&domain.OAuthClient{RegistrationSource: "internal"}), "the deployer's admin path")
	assert.False(t, clientListsScopes(&domain.OAuthClient{RegistrationSource: "dynamic"}), "a dynamically registered client chose its own scope")
	assert.False(t, clientListsScopes(&domain.OAuthClient{RegistrationSource: domain.RegistrationSourceCIMD}), "a metadata document is the client's own")
	assert.False(t, clientListsScopes(nil))
}

func TestScopeTraceGrant(t *testing.T) {
	for wire, want := range map[string]string{
		"client_credentials":                              "client_credentials",
		"urn:ietf:params:oauth:grant-type:jwt-bearer":     "jwt_bearer",
		"urn:ietf:params:oauth:grant-type:token-exchange": "token_exchange",
		"api_key":                           "api_key",
		"authorization_code":                "authorization_code",
		"refresh_token":                     "refresh_token",
		"urn:openid:params:grant-type:ciba": "urn:openid:params:grant-type:ciba",
		"urn:example:custom-grant":          "",
		"":                                  "",
	} {
		assert.Equal(t, want, scopeTraceGrant(wire), "grant %q", wire)
	}
}

// ruleOutcome renders a change as rule→outcome for compact assertions:
// "issued[a b]" or "refused/invalid_scope".
func ruleOutcome(c scopeRuleChange) string {
	if c.would.refused {
		return c.rule + "→refused/" + c.would.code
	}
	return c.rule + "→issued" + fmt.Sprint(nonNilScopes(c.would.scopes))
}

// TestScopeRules_Changes judges each rule on its own against today's outcome.
func TestScopeRules_Changes(t *testing.T) {
	issued := func(s ...string) scopeOutcome { return scopeOutcome{scopes: s} }
	refused := func(code string) scopeOutcome { return scopeOutcome{refused: true, code: code} }

	for _, tc := range []struct {
		name  string
		trace scopeTrace
		today scopeOutcome
		want  []string
	}{
		// Rule A, omitted request.
		{
			name:  "omitted request issued a default is issued none",
			trace: scopeTrace{asked: true, omittedApplies: true, listed: true, listings: [][]string{{"a", "b"}}},
			today: issued("a", "b"),
			want:  []string{"omitted_request→issued[]"},
		},
		{
			name:  "omitted request issued nothing changes nothing",
			trace: scopeTrace{asked: true, omittedApplies: true, listed: true},
			today: issued(),
		},
		{
			name:  "omitted request issued only openid changes nothing",
			trace: scopeTrace{asked: true, omittedApplies: true, listed: true},
			today: issued("openid"),
		},
		{
			name:  "an API key's stored scopes and an audience profile keep their default",
			trace: scopeTrace{asked: true, omittedApplies: false, listed: true, listings: [][]string{{"a"}}},
			today: issued("a"),
		},
		{
			name:  "an omitted request refused over its default would be issued none",
			trace: scopeTrace{asked: true, omittedApplies: true},
			today: refused(oautherror.InvalidScope),
			want:  []string{"omitted_request→issued[]"},
		},
		// Rule B, listing.
		{
			name:  "a scope no ceiling lists is dropped",
			trace: scopeTrace{asked: true, requested: []string{"a", "b"}, listed: true, listings: [][]string{{"a"}}},
			today: issued("a", "b"),
			want:  []string{"listing→issued[a]"},
		},
		{
			name:  "nothing listed is refused",
			trace: scopeTrace{asked: true, requested: []string{"a"}, listed: true},
			today: issued("a"),
			want:  []string{"listing→refused/invalid_scope"},
		},
		{
			name:  "openid alone left is refused, and openid is never unlisted",
			trace: scopeTrace{asked: true, requested: []string{"openid", "a"}, listed: true},
			today: issued("openid", "a"),
			want:  []string{"listing→refused/invalid_scope"},
		},
		{
			name:  "any one listing is enough",
			trace: scopeTrace{asked: true, requested: []string{"a", "b"}, listed: true, listings: [][]string{{"a"}, {"b"}}},
			today: issued("a", "b"),
		},
		{
			name:  "a server-defined profile lists everything",
			trace: scopeTrace{asked: true, requested: []string{"a"}, listed: true, allListed: true},
			today: issued("a"),
		},
		{
			name:  "listing is judged only where a token was minted",
			trace: scopeTrace{asked: true, requested: []string{"a"}},
			today: issued("a"),
		},
		// Rule C, all or nothing.
		{
			name:  "a narrowed request is refused whole",
			trace: scopeTrace{asked: true, requested: []string{"a", "b"}, listed: true, listings: [][]string{{"a", "b"}}},
			today: issued("a"),
			want:  []string{"all_or_nothing→refused/invalid_scope"},
		},
		{
			name:  "dropping openid is not narrowing",
			trace: scopeTrace{asked: true, requested: []string{"openid", "a"}, listed: true, listings: [][]string{{"a"}}},
			today: issued("a"),
		},
		{
			name:  "a delegation that names no scope is issued none",
			trace: scopeTrace{asked: true, delegation: true},
			today: refused(oautherror.InvalidScope),
			want:  []string{"all_or_nothing→issued[]"},
		},
		{
			name:  "a refused named request stays refused",
			trace: scopeTrace{asked: true, requested: []string{"a"}, delegation: true},
			today: refused(oautherror.InvalidScope),
		},
		// Rule D, one code.
		{
			name:  "policy_violation becomes invalid_scope",
			trace: scopeTrace{asked: true, requested: []string{"a"}},
			today: refused(policyViolationCode),
			want:  []string{"one_code→refused/invalid_scope"},
		},
		{
			name:  "invalid_scope stays",
			trace: scopeTrace{asked: true, requested: []string{"a"}},
			today: refused(oautherror.InvalidScope),
		},
		// Rules together, each judged on its own.
		{
			name:  "unlisted and narrowed",
			trace: scopeTrace{asked: true, requested: []string{"a", "b"}, listed: true},
			today: issued("a"),
			want:  []string{"listing→refused/invalid_scope", "all_or_nothing→refused/invalid_scope"},
		},
		{
			name:  "an omitted request refused with another code",
			trace: scopeTrace{asked: true, omittedApplies: true},
			today: refused(oautherror.InsufficientScope),
			want:  []string{"omitted_request→issued[]", "one_code→refused/invalid_scope"},
		},
		{
			name:  "a request the rules would not change",
			trace: scopeTrace{asked: true, omittedApplies: true, requested: []string{"a"}, listed: true, listings: [][]string{{"a", "b"}}},
			today: issued("a"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, c := range tc.trace.changes(tc.today) {
				got = append(got, ruleOutcome(c))
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestScopeRefusalCode mirrors the token handler: an OAuth error carries its
// own code, a sentinel maps as the handler maps it, and only refusals over
// scopes count.
func TestScopeRefusalCode(t *testing.T) {
	policyScope := policyScopeViolation{fmt.Errorf("%w: scope %q is not permitted by the policy's allowed_scopes", ErrPolicyViolation, "a")}
	policyTTL := fmt.Errorf("%w: requested TTL 10s exceeds policy maximum 5s", ErrPolicyViolation)

	for _, tc := range []struct {
		name      string
		err       error
		wantCode  string
		wantScope bool
	}{
		{"invalid_scope", oauthBadRequest(oautherror.InvalidScope, "no"), oautherror.InvalidScope, true},
		{"policy scope axis", policyScope, policyViolationCode, true},
		{"policy scope axis wrapped by the chokepoint's caller", fmt.Errorf("issue: %w", policyScope), policyViolationCode, true},
		{"policy TTL axis", policyTTL, "", false},
		{"identity allowed_scopes", fmt.Errorf("%w: %q not in allowed_scopes", ErrScopesNotAllowed, "a"), oautherror.InsufficientScope, true},
		{"person ceiling", ErrPersonScopeDenied, oautherror.InvalidScope, true},
		{"person ceiling at the token endpoint", personGrantOAuthError(ErrPersonScopeDenied, oautherror.InvalidGrant), oautherror.InvalidGrant, true},
		{"CIBA policy refusal", oauthBadRequestCause(oautherror.AccessDenied, "refused", policyScope), oautherror.AccessDenied, true},
		{"CIBA non-scope policy refusal", oauthBadRequestCause(oautherror.AccessDenied, "refused", policyTTL), oautherror.AccessDenied, false},
		{"person resolver failure", personGrantOAuthError(fmt.Errorf("%w: down", ErrPersonGrantUnavailable), oautherror.InvalidGrant), oautherror.ServerError, false},
		{"client authentication", oauthUnauthorized("bad secret", nil), oautherror.InvalidClient, false},
		{"anything else", errors.New("boom"), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, scope := scopeRefusalCode(tc.err)
			assert.Equal(t, tc.wantScope, scope)
			if tc.wantScope || tc.wantCode != "" {
				assert.Equal(t, tc.wantCode, code)
			}
		})
	}

	code, ok := pushScopeRefusalCode(ErrPersonScopeDenied)
	assert.True(t, ok)
	assert.Equal(t, oautherror.AccessDenied, code, "a push client is sent a person-ceiling refusal as access_denied")
	_, ok = pushScopeRefusalCode(ErrPersonGrantUnavailable)
	assert.False(t, ok, "a resolver failure is not a scope refusal")
}

// The scope-axis mark changes nothing a caller can see: the same text, and
// errors.Is still finds ErrPolicyViolation.
func TestEnforcePolicy_ScopeRefusalIsMarked(t *testing.T) {
	svc := &CredentialPolicyService{}
	policy := &domain.CredentialPolicy{
		Name: "p", IsActive: true, MaxTTLSeconds: 3600, MaxDelegationDepth: 1,
		AllowedGrantTypes: []string{"client_credentials"}, AllowedScopes: []string{"a"},
	}
	err := svc.EnforcePolicy(t.Context(), policy, EnforcePolicyRequest{TTL: 60, GrantType: domain.GrantTypeClientCredentials, Scopes: []string{"b"}})
	require.Error(t, err)
	assert.Equal(t, `credential policy violation: scope "b" is not permitted by the policy's allowed_scopes`, err.Error())
	assert.ErrorIs(t, err, ErrPolicyViolation)
	assert.True(t, isPolicyScopeViolation(err))

	err = svc.EnforcePolicy(t.Context(), policy, EnforcePolicyRequest{TTL: 7200, GrantType: domain.GrantTypeClientCredentials, Scopes: []string{"a"}})
	require.ErrorIs(t, err, ErrPolicyViolation)
	assert.False(t, isPolicyScopeViolation(err), "a refusal on another axis is not marked")
}

// TestScopeTrace_Records pins what one change records: a count with the
// low-cardinality attributes, and a log line naming the client, the identity
// and the scopes today and under the rule.
func TestScopeTrace_Records(t *testing.T) {
	points, lines := captureScopeRules(t)
	svc := &CredentialService{}
	require.NoError(t, svc.SetScopeRulesMode(ScopeRulesModeShadow))
	ctx, tr := svc.traceScopes(context.Background(), "client_credentials")

	tr.ask([]string{"a", "b"}, true)
	tr.setClient(&domain.OAuthClient{ClientID: "client-1", RegistrationSource: "dynamic", Scopes: []string{"a", "b"}})
	tr.setIdentity(&domain.Identity{ID: "identity-1", AccountID: "acct", ProjectID: "proj"})
	tr.minted([]string{"a", "b"}, []string{"a"})
	tr.done(ctx, nil)

	assert.Equal(t, []map[string]string{{
		"mode": "shadow", "rule": "listing", "grant_type": "client_credentials",
		"account_id": "acct", "project_id": "proj", "identity_id": "identity-1",
	}}, points())

	got := lines()
	require.Len(t, got, 1)
	line := got[0]
	assert.Equal(t, "warn", line["level"])
	assert.Equal(t, "shadow", line["mode"])
	assert.Equal(t, "listing", line["rule"])
	assert.Equal(t, "client_credentials", line["grant_type"])
	assert.Equal(t, "client-1", line["client_id"])
	assert.Equal(t, "identity-1", line["identity_id"])
	assert.Equal(t, "acct", line["account_id"])
	assert.Equal(t, "proj", line["project_id"])
	assert.Equal(t, []any{"a", "b"}, line["requested_scopes"])
	assert.Equal(t, "issued", line["today"])
	assert.Equal(t, []any{"a", "b"}, line["today_scopes"])
	assert.Equal(t, "issued", line["would"])
	assert.Equal(t, []any{"a"}, line["would_scopes"], "a dynamically registered client's scope is a request, not a listing")
	assert.Equal(t, []any{"b"}, line["unlisted_scopes"])
}

// A refusal is recorded with the code it answers today.
func TestScopeTrace_RecordsRefusalCode(t *testing.T) {
	points, lines := captureScopeRules(t)
	svc := &CredentialService{}
	require.NoError(t, svc.SetScopeRulesMode(ScopeRulesModeShadow))
	ctx, tr := svc.traceScopes(context.Background(), "api_key")
	tr.ask([]string{"a"}, true)
	tr.done(ctx, fmt.Errorf("%w: %q not in allowed_scopes", ErrScopesNotAllowed, "a"))

	require.Len(t, points(), 1)
	got := lines()
	require.Len(t, got, 1)
	assert.Equal(t, "one_code", got[0]["rule"])
	assert.Equal(t, "refused", got[0]["today"])
	assert.Equal(t, "insufficient_scope", got[0]["today_code"])
	assert.Equal(t, "refused", got[0]["would"])
	assert.Equal(t, "invalid_scope", got[0]["would_code"])
	assert.NotContains(t, got[0], "today_scopes")
}

// Nothing is recorded for a request the rules would not change, for a
// failure that is not about scopes, or for a request a grant never described.
func TestScopeTrace_RecordsNothingWithoutAChange(t *testing.T) {
	points, lines := captureScopeRules(t)
	svc := &CredentialService{}
	require.NoError(t, svc.SetScopeRulesMode(ScopeRulesModeShadow))

	ctx, unchanged := svc.traceScopes(context.Background(), "client_credentials")
	unchanged.ask([]string{"a"}, true)
	unchanged.setClient(&domain.OAuthClient{ClientID: "c", RegistrationSource: "internal", Scopes: []string{"a", "b"}})
	unchanged.minted([]string{"a"})
	unchanged.done(ctx, nil)

	ctx, notScope := svc.traceScopes(context.Background(), "client_credentials")
	notScope.ask(nil, true)
	notScope.done(ctx, oauthUnauthorized("bad secret", nil))

	ctx, undescribed := svc.traceScopes(context.Background(), "client_credentials")
	undescribed.done(ctx, ErrScopesNotAllowed)

	assert.Empty(t, points())
	assert.Empty(t, lines())
}
