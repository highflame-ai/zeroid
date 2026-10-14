package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// capturePersonCeiling swaps the person-ceiling counter and the global logger
// for capturing ones. It returns the counted outcomes (mode/outcome per data
// point, repeated by value) and the captured log lines.
func capturePersonCeiling(t *testing.T) (outcomes func() []string, logs *bytes.Buffer) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	counter, err := mp.Meter("test").Int64Counter("zeroid.person.scope_ceiling")
	require.NoError(t, err)
	origCounter := telemetry.PersonScopeCeiling
	telemetry.PersonScopeCeiling = counter

	logs = &bytes.Buffer{}
	origLogger, origLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(logs)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() {
		telemetry.PersonScopeCeiling = origCounter
		log.Logger = origLogger
		zerolog.SetGlobalLevel(origLevel)
	})

	return func() []string {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		var out []string
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					continue
				}
				for _, dp := range sum.DataPoints {
					mode, _ := dp.Attributes.Value(attribute.Key("mode"))
					outcome, _ := dp.Attributes.Value(attribute.Key("outcome"))
					for range dp.Value {
						out = append(out, mode.AsString()+"/"+outcome.AsString())
					}
				}
			}
		}
		return out
	}, logs
}

// personGrantLogs returns the decoded person_scope_ceiling_violation lines.
func personGrantLogs(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		if m["message"] == personGrantMsg {
			out = append(out, m)
		}
	}
	return out
}

// personGrantShapes are the six person grants as each builds its
// IssueRequest: the fields the guard and the resolver request read.
func personGrantShapes() map[string]IssueRequest {
	tenant := func() *domain.Identity { return &domain.Identity{AccountID: "acct", ProjectID: "proj"} }
	return map[string]IssueRequest{
		"authorization_code": {Identity: tenant(), GrantType: domain.GrantTypeAuthorizationCode, SubjectOverride: "alice", ClientID: "cli"},
		"refresh_token":      {Identity: tenant(), GrantType: domain.GrantTypeRefreshToken, SubjectOverride: "alice", ClientID: "cli", PrincipalIss: "https://zeroid.test"},
		"ciba_root":          {Identity: tenant(), GrantType: domain.GrantTypeCIBA, SubjectOverride: "alice", ClientID: "ciba-client"},
		"id_jag":             {Identity: tenant(), GrantType: domain.GrantTypeJWTBearer, SubjectOverride: "alice", ClientID: "agent", CustomClaims: map[string]any{"user_id_iss": "https://idp.test"}},
		"id_token_exchange":  {Identity: tenant(), GrantType: domain.GrantTypeTokenExchange, SubjectOverride: "alice", ClientID: "rp", CustomClaims: map[string]any{"user_id_iss": "https://idp.test"}},
		"broker_exchange":    {Identity: tenant(), GrantType: domain.GrantTypeTokenExchange, SubjectOverride: "alice", TrustedRole: "member", Audience: []string{"codeoid"}},
	}
}

// TestPersonGrant_SixGrants applies the ceiling to each person grant's
// request shape in both modes.
func TestPersonGrant_SixGrants(t *testing.T) {
	requested := []string{"sandbox:create", "sandbox:delete"}
	member := &PersonGrant{Scopes: []string{"sandbox:create", "sessions:read"}, Roles: []string{"member"}}
	boom := errors.New("role store unreachable")

	for _, tc := range []struct {
		name        string
		mode        PersonGrantMode
		grant       *PersonGrant
		err         error
		panic       bool
		wantErr     error
		wantScopes  []string
		wantRoles   []string
		wantCounted []string
	}{
		{name: "enforce narrows to the ceiling", mode: PersonGrantModeEnforce, grant: member,
			wantScopes: []string{"sandbox:create"}, wantRoles: []string{"member"}, wantCounted: []string{"enforce/narrowed"}},
		{name: "enforce within the ceiling is unchanged and uncounted", mode: PersonGrantModeEnforce,
			grant:      &PersonGrant{Scopes: requested, Roles: []string{"admin"}},
			wantScopes: requested, wantRoles: []string{"admin"}},
		{name: "enforce refuses a disjoint request", mode: PersonGrantModeEnforce, grant: &PersonGrant{Scopes: []string{"sessions:read"}},
			wantErr: ErrPersonScopeDenied, wantCounted: []string{"enforce/denied"}},
		{name: "enforce: an empty ceiling grants nothing", mode: PersonGrantModeEnforce, grant: &PersonGrant{Roles: []string{"viewer"}},
			wantErr: ErrPersonScopeDenied, wantCounted: []string{"enforce/denied"}},
		{name: "enforce: a nil grant is an empty ceiling", mode: PersonGrantModeEnforce,
			wantErr: ErrPersonScopeDenied, wantCounted: []string{"enforce/denied"}},
		{name: "enforce: a resolver error fails closed", mode: PersonGrantModeEnforce, err: boom,
			wantErr: ErrPersonGrantUnavailable, wantCounted: []string{"enforce/resolver_error"}},
		{name: "enforce: a resolver panic fails closed", mode: PersonGrantModeEnforce, panic: true,
			wantErr: ErrPersonGrantUnavailable, wantCounted: []string{"enforce/resolver_error"}},
		{name: "shadow leaves a narrowed request unchanged", mode: PersonGrantModeShadow, grant: member,
			wantScopes: requested, wantRoles: []string{"member"}, wantCounted: []string{"shadow/narrowed"}},
		{name: "shadow leaves a refused request unchanged", mode: PersonGrantModeShadow, grant: &PersonGrant{},
			wantScopes: requested, wantCounted: []string{"shadow/denied"}},
		{name: "shadow ignores a resolver error", mode: PersonGrantModeShadow, err: boom,
			wantScopes: requested, wantCounted: []string{"shadow/resolver_error"}},
	} {
		for grant, shape := range personGrantShapes() {
			t.Run(tc.name+"/"+grant, func(t *testing.T) {
				counted, logs := capturePersonCeiling(t)
				svc := &CredentialService{issuer: "https://zeroid.test"}
				var got []PersonGrantRequest
				require.NoError(t, svc.SetPersonGrantResolver(func(_ context.Context, r PersonGrantRequest) (*PersonGrant, error) {
					got = append(got, r)
					if tc.panic {
						panic("resolver bug")
					}
					return tc.grant, tc.err
				}, tc.mode))

				req := shape
				req.Scopes = append([]string(nil), requested...)
				err := svc.decidePersonGrant(context.Background(), &req)

				require.Len(t, got, 1, "the resolver is called once per person mint")
				assert.Equal(t, string(shape.GrantType), got[0].GrantType)
				assert.Equal(t, "acct", got[0].AccountID)
				assert.Equal(t, "alice", got[0].UserID)
				assert.Equal(t, requested, got[0].RequestedScopes)
				assert.Equal(t, shape.ClientID, got[0].ClientID)
				assert.Equal(t, shape.Audience, got[0].Audience)
				if grant == "broker_exchange" {
					assert.Equal(t, "member", got[0].TrustedRole, "the broker's asserted role reaches the resolver")
				} else {
					assert.Empty(t, got[0].TrustedRole, "only the broker asserts a role")
				}
				wantIss := "https://zeroid.test"
				if grant == "id_jag" || grant == "id_token_exchange" {
					wantIss = "https://idp.test"
				}
				assert.Equal(t, wantIss, got[0].UserIss, "the person's issuer is the one that vouched for them")

				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
				} else {
					require.NoError(t, err)
					assert.Equal(t, tc.wantScopes, req.Scopes)
					if tc.err != nil {
						assert.Nil(t, req.personGrant, "a failed resolver decides nothing, so no roles")
					} else {
						require.NotNil(t, req.personGrant)
						assert.Equal(t, tc.wantRoles, req.personGrant.roles)
					}
				}
				assert.Equal(t, tc.wantCounted, counted())

				lines := personGrantLogs(t, logs)
				require.Len(t, lines, len(tc.wantCounted), "one person_scope_ceiling_violation line per counted outcome")
				for _, l := range lines {
					assert.Equal(t, string(tc.mode), l["mode"])
					assert.Equal(t, string(shape.GrantType), l["grant_type"])
					if tc.mode == PersonGrantModeShadow {
						assert.Equal(t, "warn", l["level"], "shadow findings are warnings")
					}
				}
			})
		}
	}
}

// TestPersonGrant_NotPersonRoots pins the guard: only a person's own token
// consults the resolver. Token exchange and a CIBA step-up carry their
// chain's principal; a workload grant has no person.
func TestPersonGrant_NotPersonRoots(t *testing.T) {
	tenant := &domain.Identity{AccountID: "acct", ProjectID: "proj", WIMSEURI: "spiffe://zeroid.test/acct/proj/agent/a"}
	for name, req := range map[string]IssueRequest{
		"token exchange in a person's chain": {Identity: tenant, GrantType: domain.GrantTypeTokenExchange,
			PrincipalType: domain.PrincipalUser, PrincipalSub: "alice", DelegationDepth: 1},
		"CIBA step-up into a person's chain": {Identity: tenant, GrantType: domain.GrantTypeCIBA, SubjectOverride: "alice",
			PrincipalType: domain.PrincipalUser, PrincipalSub: "alice"},
		"CIBA step-up into a workload chain": {Identity: tenant, GrantType: domain.GrantTypeCIBA, SubjectOverride: tenant.WIMSEURI,
			PrincipalType: domain.PrincipalWorkload, PrincipalSub: tenant.WIMSEURI},
		"client_credentials":    {Identity: tenant, GrantType: domain.GrantTypeClientCredentials},
		"api_key":               {Identity: tenant, GrantType: domain.GrantTypeAPIKey},
		"NHI jwt_bearer":        {Identity: tenant, GrantType: domain.GrantTypeJWTBearer},
		"workload exchange":     {Identity: tenant, GrantType: domain.GrantTypeTokenExchange, PrincipalType: domain.PrincipalWorkload},
		"unknown-principal hop": {Identity: tenant, GrantType: domain.GrantTypeTokenExchange, PrincipalType: domain.PrincipalUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &CredentialService{issuer: "https://zeroid.test"}
			called := false
			require.NoError(t, svc.SetPersonGrantResolver(func(context.Context, PersonGrantRequest) (*PersonGrant, error) {
				called = true
				return nil, nil
			}, PersonGrantModeEnforce))
			req.Scopes = []string{"data:read"}
			require.NoError(t, svc.decidePersonGrant(context.Background(), &req))
			assert.False(t, called, "the resolver must not be consulted")
			assert.Equal(t, []string{"data:read"}, req.Scopes)
			assert.Nil(t, req.personGrant)
			assert.False(t, isPersonRoot(req, svc.resolvePrincipal(req)), "no roles claim either")
		})
	}
}

// TestPersonGrant_DecisionReused pins that a grant which decides before a
// burn is not asked twice, and that a decision is not reused for other scopes.
func TestPersonGrant_DecisionReused(t *testing.T) {
	svc := &CredentialService{issuer: "https://zeroid.test"}
	calls := 0
	require.NoError(t, svc.SetPersonGrantResolver(func(context.Context, PersonGrantRequest) (*PersonGrant, error) {
		calls++
		return &PersonGrant{Scopes: []string{"a"}}, nil
	}, PersonGrantModeEnforce))

	req := personGrantShapes()["ciba_root"]
	req.Scopes = []string{"a", "b"}
	require.NoError(t, svc.decidePersonGrant(context.Background(), &req))
	require.NoError(t, svc.decidePersonGrant(context.Background(), &req))
	assert.Equal(t, 1, calls, "the chokepoint reuses the pre-burn decision")
	assert.Equal(t, []string{"a"}, req.Scopes)

	// A refresh hands the decision over with the family's scopes, unnarrowed.
	refresh := personGrantShapes()["refresh_token"]
	refresh.Scopes = []string{"a", "b"}
	require.NoError(t, svc.decidePersonGrant(context.Background(), &refresh))
	carried := refresh.personGrant
	next := personGrantShapes()["refresh_token"]
	next.Scopes, next.personGrant = []string{"a", "b"}, carried
	require.NoError(t, svc.decidePersonGrant(context.Background(), &next))
	assert.Equal(t, 2, calls)
	assert.Equal(t, []string{"a"}, next.Scopes)

	// Different scopes: decided afresh.
	other := personGrantShapes()["refresh_token"]
	other.Scopes, other.personGrant = []string{"b", "c"}, carried
	assert.ErrorIs(t, svc.decidePersonGrant(context.Background(), &other), ErrPersonScopeDenied)
	assert.Equal(t, 3, calls)
}

func TestApplyPersonCeiling(t *testing.T) {
	for _, tc := range []struct {
		name               string
		requested, ceiling []string
		want               []string
		outcome            string
	}{
		{"nothing requested", nil, nil, nil, ""},
		{"within", []string{"a", "b"}, []string{"b", "a", "c"}, []string{"a", "b"}, ""},
		{"narrowed, request order kept", []string{"b", "x", "a"}, []string{"a", "b"}, []string{"b", "a"}, "narrowed"},
		{"denied", []string{"x"}, []string{"a"}, nil, "denied"},
		{"empty ceiling denies", []string{"a"}, nil, nil, "denied"},
		{"openid alone needs no ceiling", []string{"openid"}, nil, []string{"openid"}, ""},
		{"openid survives a narrowing", []string{"openid", "a", "x"}, []string{"a"}, []string{"openid", "a"}, "narrowed"},
		{"openid does not save a refusal", []string{"openid", "x"}, []string{"a"}, []string{"openid"}, "denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, outcome := applyPersonCeiling(tc.requested, tc.ceiling)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.outcome, outcome)
		})
	}
}

func TestSetPersonGrantResolver(t *testing.T) {
	svc := &CredentialService{}
	fn := func(context.Context, PersonGrantRequest) (*PersonGrant, error) { return nil, nil }

	require.NoError(t, svc.SetPersonGrantResolver(fn, PersonGrantModeEnforce))
	assert.True(t, svc.personGrantEnforced())
	require.Error(t, svc.SetPersonGrantResolver(fn, "strict"), "unknown modes are rejected")
	assert.True(t, svc.personGrantEnforced(), "a rejected call leaves the hook unchanged")

	require.NoError(t, svc.SetPersonGrantResolver(fn, PersonGrantModeShadow))
	assert.False(t, svc.personGrantEnforced())
	require.NoError(t, svc.SetPersonGrantResolver(nil, PersonGrantModeEnforce))
	assert.Nil(t, svc.personGrant.hook.Load(), "a nil resolver removes the hook")
	require.NoError(t, svc.SetPersonGrantResolver(fn, PersonGrantModeOff))
	assert.Nil(t, svc.personGrant.hook.Load(), "off removes the hook")

	var nilSvc *CredentialService
	assert.False(t, nilSvc.personGrantEnforced())
}

func TestPersonGrantOAuthError(t *testing.T) {
	var oe *OAuthError
	require.ErrorAs(t, personGrantOAuthError(ErrPersonScopeDenied, oautherror.InvalidGrant), &oe)
	assert.Equal(t, oautherror.InvalidGrant, oe.Code)
	assert.Equal(t, http.StatusBadRequest, oe.HTTPStatus)

	require.ErrorAs(t, personGrantOAuthError(ErrPersonScopeDenied, oautherror.InvalidScope), &oe)
	assert.Equal(t, oautherror.InvalidScope, oe.Code)

	require.ErrorAs(t, personGrantOAuthError(errors.Join(ErrPersonGrantUnavailable, errors.New("x")), oautherror.InvalidScope), &oe)
	assert.Equal(t, oautherror.ServerError, oe.Code)
	assert.Equal(t, http.StatusInternalServerError, oe.HTTPStatus)

	other := errors.New("unrelated")
	assert.Same(t, other, personGrantOAuthError(other, oautherror.InvalidScope))
}

// TestRolesIsReserved: only the person-grant resolver may set `roles`.
func TestRolesIsReserved(t *testing.T) {
	assert.True(t, reservedClaims["roles"])
}
