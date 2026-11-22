package service

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

const stIssuer = "https://issuer.test"

func stService() *OAuthService {
	clients := &OAuthClientService{}
	clients.SetReservedClientIDs(nil, []string{"svc-"})
	s := &OAuthService{issuer: stIssuer, wimseDomain: "zeroid.dev", oauthClientSvc: clients}
	s.SetServiceTokens(ServiceTokenSettings{
		AccountID:             "platform",
		ProjectID:             "services",
		AssertedTenantClients: []string{"svc-jobs"},
		SessionBrokerClients:  []string{"svc-broker"},
		ServedResources:       map[string][]string{"svc-gw": {"https://mcp.test/", "urn:svc:exact"}},
	})
	return s
}

func stToken(t *testing.T, claims map[string]any) jwt.Token {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	return tok
}

func TestSetServiceTokens_EmptyTenantDisables(t *testing.T) {
	s := &OAuthService{}
	s.SetServiceTokens(ServiceTokenSettings{AccountID: "a"})
	assert.Nil(t, s.serviceTokenCfg(), "half a tenant disables")
	s.SetServiceTokens(ServiceTokenSettings{AccountID: "a", ProjectID: "p"})
	require.NotNil(t, s.serviceTokenCfg())
	s.SetServiceTokens(ServiceTokenSettings{})
	assert.Nil(t, s.serviceTokenCfg(), "the zero value turns it back off")
}

func TestServiceTokenConfig_Serves(t *testing.T) {
	cfg := stService().serviceTokenCfg()
	assert.True(t, cfg.serves("svc-gw", "https://mcp.test/a/b"))
	assert.True(t, cfg.serves("svc-gw", "urn:svc:exact"))
	assert.False(t, cfg.serves("svc-gw", "urn:svc:exact2"), "an entry without a trailing slash matches exactly")
	assert.False(t, cfg.serves("svc-gw", "https://mcp.test.evil/"), "a prefix match needs the trailing slash")
	assert.False(t, cfg.serves("svc-broker", "https://mcp.test/a"), "a client serves only its own entries")
	var none *serviceTokenConfig
	assert.False(t, none.serves("svc-gw", "https://mcp.test/a"))
}

func TestRequestRouting(t *testing.T) {
	s := stService()
	assert.True(t, s.isSessionBrokerRequest(TokenRequest{ClientID: "svc-broker", UserID: "alice"}))
	assert.False(t, s.isSessionBrokerRequest(TokenRequest{ClientID: "svc-broker"}), "a broker naming no person is not a session request")
	assert.False(t, s.isSessionBrokerRequest(TokenRequest{ClientID: "SVC-BROKER", UserID: "alice"}), "exact client id only")
	assert.False(t, s.isSessionBrokerRequest(TokenRequest{ClientID: "svc-gw", UserID: "alice"}))

	assert.True(t, s.isOnBehalfRequest(TokenRequest{ClientID: "x", SubjectTokenType: TokenTypeAccessToken}))
	assert.True(t, s.isOnBehalfRequest(TokenRequest{ClientAssertion: "a", SubjectTokenType: TokenTypeAccessToken}))
	assert.False(t, s.isOnBehalfRequest(TokenRequest{SubjectTokenType: TokenTypeAccessToken}), "no client authentication")
	assert.False(t, s.isOnBehalfRequest(TokenRequest{ClientID: "x", SubjectTokenType: SubjectTokenTypeJWT}), "only an access_token subject")

	off := &OAuthService{}
	assert.False(t, off.isOnBehalfRequest(TokenRequest{ClientID: "x", SubjectTokenType: TokenTypeAccessToken}), "disabled by default")
	assert.False(t, off.isSessionBrokerRequest(TokenRequest{ClientID: "svc-broker", UserID: "alice"}))
}

func TestRequireServiceClient_RefusesBeforeTheStore(t *testing.T) {
	s := stService()
	cfg := s.serviceTokenCfg()
	id := "00000000-0000-0000-0000-000000000001"
	good := domain.OAuthClient{
		ClientID: "svc-gw", TokenEndpointAuthMethod: clientAuthMethodPrivateKeyJWT,
		RegistrationSource: domain.RegistrationSourceSeed, IdentityID: &id,
	}
	cases := map[string]func(c *domain.OAuthClient) *serviceTokenConfig{
		"disabled": func(*domain.OAuthClient) *serviceTokenConfig { return nil },
		"client secret": func(c *domain.OAuthClient) *serviceTokenConfig {
			c.TokenEndpointAuthMethod = "client_secret_post"
			return cfg
		},
		"public":                 func(c *domain.OAuthClient) *serviceTokenConfig { c.TokenEndpointAuthMethod = "none"; return cfg },
		"not reserved":           func(c *domain.OAuthClient) *serviceTokenConfig { c.ClientID = "gw"; return cfg },
		"registered by a tenant": func(c *domain.OAuthClient) *serviceTokenConfig { c.RegistrationSource = "internal"; return cfg },
		"registered dynamically": func(c *domain.OAuthClient) *serviceTokenConfig { c.RegistrationSource = "dynamic"; return cfg },
		"not linked":             func(c *domain.OAuthClient) *serviceTokenConfig { c.IdentityID = nil; return cfg },
		"linked to an empty id":  func(c *domain.OAuthClient) *serviceTokenConfig { empty := ""; c.IdentityID = &empty; return cfg },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := good
			cfg := mutate(&c)
			_, err := s.requireServiceClient(context.Background(), &c, cfg)
			var oe *OAuthError
			require.True(t, errors.As(err, &oe), "%v", err)
			assert.Equal(t, oautherror.UnauthorizedClient, oe.Code)
		})
	}
}

func TestIsInternalServiceToken(t *testing.T) {
	s := stService()
	cfg := s.serviceTokenCfg()
	tenant := &domain.IssuedCredential{AccountID: "acct", ProjectID: "proj"}
	cases := []struct {
		name   string
		claims map[string]any
		cred   *domain.IssuedCredential
		want   bool
	}{
		{"an ordinary token", map[string]any{"sub": "alice"}, tenant, false},
		{"a delegated tenant chain", map[string]any{"act": map[string]any{"sub": "spiffe://zeroid.dev/acct/proj/agent/a", "act": map[string]any{"sub": "spiffe://zeroid.dev/acct/proj/agent/b"}}}, tenant, false},
		{"in the service tenant", map[string]any{"sub": "x"}, &domain.IssuedCredential{AccountID: "platform", ProjectID: "other"}, true},
		{"asserted tenant row", map[string]any{}, &domain.IssuedCredential{AccountID: "acct", GrantType: domain.GrantTypeAssertedTenant}, true},
		{"asserted tenant claim", map[string]any{"grant_type": "asserted_tenant"}, tenant, true},
		{"tenant_source present", map[string]any{"tenant_source": ""}, tenant, true},
		{"an on-behalf token", map[string]any{"token_exchange": "on_behalf"}, tenant, true},
		{"act.client_id outermost", map[string]any{"act": map[string]any{"sub": "x", "client_id": "c"}}, tenant, true},
		{"act.client_id nested", map[string]any{"act": map[string]any{"sub": "x", "act": map[string]any{"sub": "y", "client_id": "c"}}}, tenant, true},
		{"a service actor nested", map[string]any{"act": map[string]any{"sub": "x", "act": map[string]any{"sub": "spiffe://zeroid.dev/platform/services/service/gw"}}}, tenant, true},
		{"a malformed act", map[string]any{"act": "alice"}, tenant, true},
		{"a malformed nested act", map[string]any{"act": map[string]any{"sub": "x", "act": "y"}}, tenant, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isInternalServiceToken(stToken(t, tc.claims), tc.cred, cfg, s.parseWIMSEURI))
		})
	}
	t.Run("claims that only the grants write still count with the feature off", func(t *testing.T) {
		tok := stToken(t, map[string]any{"token_exchange": "on_behalf"})
		assert.True(t, isInternalServiceToken(tok, tenant, nil, s.parseWIMSEURI))
		assert.False(t, isInternalServiceToken(stToken(t, map[string]any{"sub": "x"}),
			&domain.IssuedCredential{AccountID: "platform"}, nil, s.parseWIMSEURI), "no service tenant when off")
	})
}

func TestIsPersonSession(t *testing.T) {
	s := stService()
	cfg := s.serviceTokenCfg()
	broker := func(extra map[string]any) map[string]any {
		c := map[string]any{
			"sub": "alice", "grant_type": "token_exchange", "token_exchange": "external_principal",
			"client_id": "svc-broker", "trusted_by": "svc-broker", "identity_type": "service",
			"aud": []string{stIssuer},
		}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	assert.True(t, s.isPersonSession(stToken(t, broker(nil)), cfg))
	assert.True(t, s.isPersonSession(stToken(t, map[string]any{
		"sub": "alice", "grant_type": "token_exchange", "token_exchange": "external_id_token", "aud": []string{stIssuer},
	}), cfg), "the ID-token exchange verified the person itself")

	for name, extra := range map[string]map[string]any{
		"validator path (no client_id)": {"client_id": nil},
		"client not a broker":           {"client_id": "svc-gw"},
		"trusted_by alone":              {"client_id": nil, "trusted_by": "svc-broker"},
		"an act":                        {"act": map[string]any{"sub": "spiffe://zeroid.dev/a/p/agent/x"}},
		"a resource":                    {"resource": []string{"https://mcp.test/x"}},
		"another audience":              {"aud": []string{"codeoid"}},
		"an external_id":                {"external_id": "agent-1"},
		"an agent identity type":        {"identity_type": "agent"},
		"a workload sub":                {"sub": "spiffe://zeroid.dev/a/p/agent/x"},
		"another grant":                 {"grant_type": "authorization_code"},
		"another exchange":              {"token_exchange": "id_jag"},
	} {
		t.Run(name, func(t *testing.T) {
			c := broker(extra)
			for k, v := range extra {
				if v == nil {
					delete(c, k)
				}
			}
			assert.False(t, s.isPersonSession(stToken(t, c), cfg))
		})
	}
	assert.False(t, s.isPersonSession(stToken(t, broker(nil)), nil), "no brokers while off")
}

func TestResolveUser(t *testing.T) {
	const spiffe = "spiffe://zeroid.dev/a/p/agent/x"
	agent := &domain.Identity{IdentityType: domain.IdentityTypeAgent, OwnerUserID: "owner"}
	cred := &domain.IssuedCredential{GrantType: domain.GrantTypeClientCredentials}
	cases := []struct {
		name       string
		claims     map[string]any
		person     bool
		cred       *domain.IssuedCredential
		identity   *domain.Identity
		wantUser   string
		wantSource string
	}{
		{"person session", map[string]any{"sub": "alice"}, true, cred, nil, "alice", ResolvedUserSourceSubject},
		{"person session with a workload sub", map[string]any{"sub": spiffe}, true, cred, nil, "", ""},
		{"rfc8693 person principal", map[string]any{"sub": "alice", "principal_type": "user"}, false, cred, agent, "alice", ResolvedUserSourceSubject},
		{"rfc8693 person principal never reads user_id", map[string]any{"sub": spiffe, "principal_type": "user", "user_id": "bob"}, false, cred, agent, "owner", ResolvedUserSourceOwner},
		{"rfc8693 workload falls to the owner", map[string]any{"sub": spiffe, "principal_type": "workload", "user_id": "bob"}, false, cred, agent, "owner", ResolvedUserSourceOwner},
		{"legacy user_id", map[string]any{"sub": spiffe, "user_id": "bob"}, false, cred, agent, "bob", ResolvedUserSourceOnBehalf},
		{"legacy workload user_id refused", map[string]any{"sub": spiffe, "user_id": spiffe}, false, cred, agent, "owner", ResolvedUserSourceOwner},
		{"legacy delegated act.sub", map[string]any{"sub": spiffe, "delegation_depth": 1, "act": map[string]any{"sub": "carol"}}, false, cred, agent, "carol", ResolvedUserSourceOnBehalf},
		{"legacy undelegated act.sub is a key creator", map[string]any{"sub": spiffe, "act": map[string]any{"sub": "creator"}}, false, cred, agent, "owner", ResolvedUserSourceOwner},
		{"legacy delegated workload act.sub", map[string]any{"sub": spiffe, "delegation_depth": 2, "act": map[string]any{"sub": spiffe}}, false, cred, agent, "owner", ResolvedUserSourceOwner},
		{"legacy person sub alone is not enough", map[string]any{"sub": "alice"}, false, cred, nil, "", ""},
		{"workload owner is a workload", map[string]any{"sub": spiffe}, false, cred, &domain.Identity{IdentityType: domain.IdentityTypeAgent, OwnerUserID: spiffe}, "", ""},
		{"api key on a service identity: owner not consulted", map[string]any{"sub": spiffe}, false,
			&domain.IssuedCredential{GrantType: domain.GrantTypeAPIKey}, &domain.Identity{IdentityType: domain.IdentityTypeService, OwnerUserID: "first-creator"}, "", ""},
		{"api key on an agent: the agent's owner", map[string]any{"sub": spiffe}, false,
			&domain.IssuedCredential{GrantType: domain.GrantTypeAPIKey}, agent, "owner", ResolvedUserSourceOwner},
		{"nothing", map[string]any{"sub": spiffe}, false, cred, nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, source := resolveUser(stToken(t, tc.claims), tc.person, tc.cred, tc.identity)
			assert.Equal(t, tc.wantUser, user)
			assert.Equal(t, tc.wantSource, source)
		})
	}
}

func TestTruncateActChain(t *testing.T) {
	chain := map[string]any{"sub": "a", "x": 1, "act": map[string]any{"sub": "b", "act": map[string]any{"sub": "c"}}}
	got := truncateActChain(chain, 2)
	assert.Equal(t, map[string]any{"sub": "a", "x": 1, "act": map[string]any{"sub": "b"}}, got)
	assert.Equal(t, chain, truncateActChain(chain, 5), "a short chain is kept whole")
	assert.Nil(t, truncateActChain(nil, 3))
	assert.Nil(t, truncateActChain(chain, 0))
	// The input is not modified.
	assert.Contains(t, chain["act"].(map[string]any), "act")
}

func TestServiceActor(t *testing.T) {
	act := serviceActor(&domain.Identity{
		WIMSEURI: "spiffe://zeroid.dev/platform/services/service/gw", IdentityType: domain.IdentityTypeService,
		TrustLevel: domain.TrustLevelFirstParty, ExternalID: "svc-gw",
	}, &domain.OAuthClient{ClientID: "svc-gw"})
	assert.Equal(t, "spiffe://zeroid.dev/platform/services/service/gw", act["sub"])
	assert.Equal(t, "svc-gw", act["client_id"])
	assert.NotContains(t, act, "act")
}

func TestRefuseServiceGrantParams(t *testing.T) {
	ok := TokenRequest{Resource: []string{"urn:svc:authz"}}
	require.NoError(t, refuseServiceGrantParams(ok, "x", false))
	cases := map[string]struct {
		req  TokenRequest
		code string
	}{
		"tenant":            {TokenRequest{Resource: ok.Resource, AccountID: "a"}, oautherror.InvalidRequest},
		"user":              {TokenRequest{Resource: ok.Resource, UserID: "u"}, oautherror.InvalidRequest},
		"application":       {TokenRequest{Resource: ok.Resource, ApplicationID: "a"}, oautherror.InvalidRequest},
		"additional_claims": {TokenRequest{Resource: ok.Resource, AdditionalClaims: map[string]any{"subject_kind": "person"}}, oautherror.InvalidRequest},
		"role":              {TokenRequest{Resource: ok.Resource, Role: "admin"}, oautherror.InvalidRequest},
		"audience":          {TokenRequest{Resource: ok.Resource, Audience: "codeoid"}, oautherror.InvalidRequest},
		"refresh":           {TokenRequest{Resource: ok.Resource, IssueRefreshToken: true}, oautherror.InvalidRequest},
		"scope":             {TokenRequest{Resource: ok.Resource, Scope: "a"}, oautherror.InvalidScope},
		"no resource":       {TokenRequest{}, oautherror.InvalidTarget},
		"two resources":     {TokenRequest{Resource: []string{"urn:a", "urn:b"}}, oautherror.InvalidTarget},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := refuseServiceGrantParams(tc.req, "x", false)
			var oe *OAuthError
			require.True(t, errors.As(err, &oe), "%v", err)
			assert.Equal(t, tc.code, oe.Code)
		})
	}
	assert.NoError(t, refuseServiceGrantParams(TokenRequest{Resource: ok.Resource, AccountID: "a", ProjectID: "p"}, "x", true),
		"the asserted-tenant grant takes a tenant")
}

func TestReservedSubjectKind(t *testing.T) {
	assert.True(t, reservedClaims["subject_kind"])
}

func TestTokenResources(t *testing.T) {
	r, ok := tokenResources(stToken(t, map[string]any{}))
	assert.True(t, ok)
	assert.Empty(t, r)
	r, ok = tokenResources(stToken(t, map[string]any{"resource": "urn:a"}))
	assert.True(t, ok)
	assert.Equal(t, []string{"urn:a"}, r)
	r, ok = tokenResources(stToken(t, map[string]any{"resource": []any{"urn:a", "urn:b"}}))
	assert.True(t, ok)
	assert.Equal(t, []string{"urn:a", "urn:b"}, r)
	_, ok = tokenResources(stToken(t, map[string]any{"resource": []any{"urn:a", 3}}))
	assert.False(t, ok)
}
