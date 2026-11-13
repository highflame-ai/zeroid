package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/domain"
)

// The person-grant ceiling (ADR 0041 D15): every grant that mints for a person
// issues request ∩ the deployer's ceiling for that person and refuses a
// request that leaves nothing; token exchange and a CIBA step-up do not
// consult it. See docs/scope-ceilings.md, "A person's ceiling".

// personGrants is a test PersonGrantResolver keyed by user id. A user with no
// entry gets their request back as the ceiling and no roles, so tests that
// never set one see no change.
type personGrants struct {
	mu     sync.Mutex
	byUser map[string]personGrantEntry
	calls  []zeroid.PersonGrantRequest
}

type personGrantEntry struct {
	grant *zeroid.PersonGrant
	err   error
}

func (p *personGrants) set(user string, grant *zeroid.PersonGrant, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byUser[user] = personGrantEntry{grant, err}
}

func (p *personGrants) resolve(_ context.Context, r zeroid.PersonGrantRequest) (*zeroid.PersonGrant, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, r)
	e, ok := p.byUser[r.UserID]
	if !ok {
		return &zeroid.PersonGrant{Scopes: r.RequestedScopes}, nil
	}
	return e.grant, e.err
}

func (p *personGrants) callsFor(user string) []zeroid.PersonGrantRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []zeroid.PersonGrantRequest
	for _, c := range p.calls {
		if c.UserID == user {
			out = append(out, c)
		}
	}
	return out
}

// installPersonGrants installs one recorder on every server given, in mode,
// and removes it when the test ends.
func installPersonGrants(t *testing.T, mode zeroid.PersonGrantMode, servers ...*zeroid.Server) *personGrants {
	t.Helper()
	p := &personGrants{byUser: map[string]personGrantEntry{}}
	for _, srv := range servers {
		require.NoError(t, srv.SetPersonGrantResolver(p.resolve, mode))
	}
	t.Cleanup(func() {
		for _, srv := range servers {
			require.NoError(t, srv.SetPersonGrantResolver(nil, zeroid.PersonGrantModeOff))
		}
	})
	return p
}

// personMint mints a token for user requesting scopes. arm installs the
// user's ceiling; a grant whose mint follows an earlier one (refresh) arms it
// in between.
type personMint func(t *testing.T, user string, scopes []string, arm func()) (int, map[string]any)

// personGrantFederation is a federation server for the ID-JAG and ID-token
// mints, with the clients they authenticate as.
type personGrantFederation struct {
	srv           *zeroid.Server
	url           string
	cfg           federationServerCfg
	upstream      *fakeUpstreamIdP
	iss, aud      string
	jagClient, rp oauthClientResp
}

func newPersonGrantFederation(t *testing.T) *personGrantFederation {
	t.Helper()
	f := &personGrantFederation{iss: "https://corp-idp.person-grant.test", aud: "https://zeroid.person-grant.test"}
	f.upstream = newFakeUpstreamIdP(t)
	t.Cleanup(f.upstream.Close)
	srv, httpSrv, cfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          f.iss,
		JWKSURI:         f.upstream.JWKSURL(),
		Audience:        f.aud,
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	f.srv, f.url, f.cfg = srv, httpSrv.URL, cfg
	f.jagClient = registerTenantBoundClient(t, cfg.AccountID, cfg.ProjectID, []string{"pg:a", "pg:b", "pg:c"})
	f.rp = rpClient(t, f.aud)
	return f
}

func federationResult(resp tokenResponse) (int, map[string]any) {
	body := map[string]any{"error": resp.Error}
	if resp.AccessToken != "" {
		body = map[string]any{"access_token": resp.AccessToken}
	}
	return resp.StatusCode, body
}

// personMints returns the six grants that mint for a person.
func personMints(f *personGrantFederation) map[string]personMint {
	return map[string]personMint{
		"authorization_code": func(t *testing.T, user string, scopes []string, arm func()) (int, map[string]any) {
			arm()
			verifier, challenge := buildPKCEPair(t)
			resp := post(t, "/oauth2/token", map[string]any{
				"grant_type":    "authorization_code",
				"client_id":     testCLIClientID,
				"code":          buildAuthCode(t, testCLIClientID, user, testRedirectURI, challenge, scopes),
				"code_verifier": verifier,
				"redirect_uri":  testRedirectURI,
			}, nil)
			return resp.StatusCode, decode(t, resp)
		},
		"refresh_token": func(t *testing.T, user string, scopes []string, arm func()) (int, map[string]any) {
			verifier, challenge := buildPKCEPair(t)
			resp := post(t, "/oauth2/token", map[string]any{
				"grant_type":    "authorization_code",
				"client_id":     testMCPClientID,
				"code":          buildAuthCode(t, testMCPClientID, user, testRedirectURI, challenge, scopes),
				"code_verifier": verifier,
				"redirect_uri":  testRedirectURI,
			}, nil)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			rt, _ := decode(t, resp)["refresh_token"].(string)
			require.NotEmpty(t, rt)
			arm()
			resp = post(t, "/oauth2/token", map[string]any{
				"grant_type": "refresh_token", "refresh_token": rt, "client_id": testMCPClientID,
			}, nil)
			return resp.StatusCode, decode(t, resp)
		},
		"external_principal_exchange": func(t *testing.T, user string, scopes []string, arm func()) (int, map[string]any) {
			arm()
			resp := post(t, "/oauth2/token", map[string]any{
				"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token": "external-principal-assertion",
				"account_id":    testAccountID,
				"project_id":    testProjectID,
				"user_id":       user,
				"scope":         strings.Join(scopes, " "),
			}, map[string]string{testTrustedServiceHeader: "trusted-service"})
			return resp.StatusCode, decode(t, resp)
		},
		"ciba_root": func(t *testing.T, user string, scopes []string, arm func()) (int, map[string]any) {
			arm()
			c := newConfidentialCIBAClient(t)
			resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": user, "scope": strings.Join(scopes, " ")})
			body := decode(t, resp)
			require.Equal(t, http.StatusOK, resp.StatusCode, "bc-authorize: %v", body)
			id := body["auth_req_id"].(string)
			approveInTenant(t, id, user, adminHeaders())
			return pollCIBARaw(t, c, id)
		},
		"id_jag": func(t *testing.T, user string, scopes []string, arm func()) (int, map[string]any) {
			arm()
			now := time.Now()
			idjag := f.upstream.SignTokenWithTyp(t, idJAGTyp, map[string]any{
				"iss": f.iss, "aud": f.aud, "sub": user,
				"client_id": f.jagClient.ClientID, "jti": uid("pg-jti"),
				"resource": "https://mcp.person-grant.test",
				"scope":    strings.Join(scopes, " "),
				"iat":      now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			})
			return federationResult(postFederation(t, f.url, map[string]any{
				"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
				"assertion":     idjag,
				"account_id":    f.cfg.AccountID,
				"project_id":    f.cfg.ProjectID,
				"client_id":     f.jagClient.ClientID,
				"client_secret": f.jagClient.ClientSecret,
			}))
		},
		"id_token_exchange": func(t *testing.T, user string, scopes []string, arm func()) (int, map[string]any) {
			arm()
			now := time.Now()
			idToken := f.upstream.SignToken(t, map[string]any{
				"iss": f.iss, "aud": f.aud, "sub": user,
				"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			})
			return federationResult(postFederation(t, f.url, map[string]any{
				"grant_type":            "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token":         idToken,
				"subject_token_type":    "urn:ietf:params:oauth:token-type:id_token",
				"client_id":             f.rp.ClientID,
				"client_assertion":      rpAssertion(t, f.rp),
				"client_assertion_type": clientAssertionType,
				"account_id":            f.cfg.AccountID,
				"project_id":            f.cfg.ProjectID,
				"scope":                 strings.Join(scopes, " "),
			}))
		},
	}
}

// personGrantTypes is the GrantType the resolver sees for each person mint.
var personGrantTypes = map[string]string{
	"authorization_code":          zeroid.PersonGrantAuthorizationCode,
	"refresh_token":               zeroid.PersonGrantRefreshToken,
	"external_principal_exchange": zeroid.PersonGrantExternalPrincipal,
	"ciba_root":                   zeroid.PersonGrantCIBA,
	"id_jag":                      zeroid.PersonGrantIDJAG,
	"id_token_exchange":           zeroid.PersonGrantExternalIDToken,
}

// TestPersonGrant_SixGrants runs each person grant end to end against the
// ceiling in both modes.
func TestPersonGrant_SixGrants(t *testing.T) {
	f := newPersonGrantFederation(t)
	requested := []string{"pg:a", "pg:b"}
	deniedCode := map[string]string{"authorization_code": "invalid_grant", "refresh_token": "invalid_grant"}

	for _, tc := range []struct {
		name       string
		mode       zeroid.PersonGrantMode
		grant      *zeroid.PersonGrant
		err        error
		wantStatus int
		wantScopes []any
		wantRoles  []any
	}{
		{"enforce narrows to the ceiling", zeroid.PersonGrantModeEnforce,
			&zeroid.PersonGrant{Scopes: []string{"pg:a", "pg:z"}, Roles: []string{"member"}}, nil,
			http.StatusOK, []any{"pg:a"}, []any{"member"}},
		{"enforce refuses a request the ceiling leaves empty", zeroid.PersonGrantModeEnforce,
			&zeroid.PersonGrant{Scopes: []string{"pg:c"}, Roles: []string{"viewer"}}, nil,
			http.StatusBadRequest, nil, nil},
		{"enforce fails closed when the resolver fails", zeroid.PersonGrantModeEnforce,
			nil, errors.New("role store unreachable"),
			http.StatusInternalServerError, nil, nil},
		{"shadow issues the request unchanged", zeroid.PersonGrantModeShadow,
			&zeroid.PersonGrant{Scopes: []string{"pg:c"}, Roles: []string{"member"}}, nil,
			http.StatusOK, []any{"pg:a", "pg:b"}, []any{"member"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grants := installPersonGrants(t, tc.mode, testZeroIDServer, f.srv)
			for name, mint := range personMints(f) {
				t.Run(name, func(t *testing.T) {
					user := uid("pg-" + name)
					status, body := mint(t, user, requested, func() { grants.set(user, tc.grant, tc.err) })
					require.Equal(t, tc.wantStatus, status, "body=%v", body)

					calls := grants.callsFor(user)
					require.NotEmpty(t, calls, "the resolver is consulted")
					assert.Equal(t, requested, calls[len(calls)-1].RequestedScopes)
					assert.Equal(t, personGrantTypes[name], calls[len(calls)-1].GrantType)

					switch tc.wantStatus {
					case http.StatusOK:
						claims := decodeJWTPayload(t, body["access_token"].(string))
						assert.ElementsMatch(t, tc.wantScopes, claims["scopes"])
						assert.Equal(t, tc.wantRoles, claims["roles"], "roles is stamped on the person's token")
					case http.StatusBadRequest:
						want := deniedCode[name]
						if want == "" {
							want = "invalid_scope"
						}
						assert.Equal(t, want, body["error"])
						assert.Empty(t, body["access_token"])
					default:
						assert.Equal(t, "server_error", body["error"])
					}
				})
			}
		})
	}
}

// TestPersonGrant_AuthorizeRefusesEarly: in enforce mode a refusal reaches
// the client at /oauth2/authorize (RFC 6749 §4.1.2.1) instead of at the token
// endpoint, where it would burn the code.
func TestPersonGrant_AuthorizeRefusesEarly(t *testing.T) {
	// authorize runs the browser (GET) leg for user and returns the
	// redirect's query.
	authorize := func(t *testing.T, user string) url.Values {
		t.Helper()
		query, _ := authorizeGETQuery(t)
		query.Set("scope", "pg:a pg:b")
		headers := principalHeaders()
		headers["X-Test-Principal-User"] = user
		resp := getAuthorize(t, query, headers)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		u, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		return u.Query()
	}

	t.Run("enforce: a request the ceiling leaves empty redirects invalid_scope", func(t *testing.T) {
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
		user := uid("pg-authz")
		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:c"}}, nil)
		q := authorize(t, user)
		assert.Equal(t, "invalid_scope", q.Get("error"))
		assert.Empty(t, q.Get("code"))
		calls := grants.callsFor(user)
		require.Len(t, calls, 1)
		assert.Equal(t, zeroid.PersonGrantAuthorizationCode, calls[0].GrantType)
		assert.Equal(t, []string{"pg:a", "pg:b"}, calls[0].RequestedScopes)
	})

	t.Run("enforce: the POST leg answers invalid_scope as JSON", func(t *testing.T) {
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
		user := uid("pg-authz-post")
		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:c"}}, nil)
		form, _ := authorizeBaseForm(t)
		form.Set("test_principal_user", user)
		form.Set("scope", "pg:a")
		resp := postAuthorize(t, form)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_scope", decode(t, resp)["error"])
	})

	t.Run("enforce: a resolver failure redirects server_error", func(t *testing.T) {
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
		user := uid("pg-authz-err")
		grants.set(user, nil, errors.New("role store unreachable"))
		assert.Equal(t, "server_error", authorize(t, user).Get("error"))
	})

	t.Run("enforce: a narrowed request still gets a code", func(t *testing.T) {
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
		user := uid("pg-authz-ok")
		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a"}}, nil)
		assert.NotEmpty(t, authorize(t, user).Get("code"))
	})

	t.Run("shadow refuses nothing and is not consulted at authorize", func(t *testing.T) {
		grants := installPersonGrants(t, zeroid.PersonGrantModeShadow, testZeroIDServer)
		user := uid("pg-authz-shadow")
		grants.set(user, &zeroid.PersonGrant{}, nil)
		assert.NotEmpty(t, authorize(t, user).Get("code"))
		assert.Empty(t, grants.callsFor(user), "shadow counts once, at the mint")
	})
}

// TestPersonGrant_RefreshFollowsTheRole: a refresh family keeps its consented
// scopes and each refresh applies the person's current ceiling, so a demotion
// takes effect on the next refresh, a refused refresh does not burn the
// token, and a restored role restores the scopes.
func TestPersonGrant_RefreshFollowsTheRole(t *testing.T) {
	grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
	user := uid("pg-demoted")
	grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a", "pg:b"}, Roles: []string{"admin"}}, nil)

	verifier, challenge := buildPKCEPair(t)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          buildAuthCode(t, testMCPClientID, user, testRedirectURI, challenge, []string{"pg:a", "pg:b"}),
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, []any{"admin"}, decodeJWTPayload(t, body["access_token"].(string))["roles"])
	rt := body["refresh_token"].(string)

	refresh := func(t *testing.T) (int, map[string]any) {
		t.Helper()
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type": "refresh_token", "refresh_token": rt, "client_id": testMCPClientID,
		}, nil)
		return resp.StatusCode, decode(t, resp)
	}

	grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a"}, Roles: []string{"member"}}, nil)
	status, body := refresh(t)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	claims := decodeJWTPayload(t, body["access_token"].(string))
	assert.ElementsMatch(t, []any{"pg:a"}, claims["scopes"], "the demotion takes effect on the next refresh")
	assert.Equal(t, []any{"member"}, claims["roles"])
	assert.Equal(t, "pg:a", body["scope"], "the response names the issued scope (RFC 6749 §5.1)")
	rt = body["refresh_token"].(string)

	grants.set(user, &zeroid.PersonGrant{Roles: []string{"viewer"}}, nil)
	status, body = refresh(t)
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])

	grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a", "pg:b"}, Roles: []string{"admin"}}, nil)
	status, body = refresh(t)
	require.Equal(t, http.StatusOK, status, "the refused refresh did not burn the token; body=%v", body)
	assert.ElementsMatch(t, []any{"pg:a", "pg:b"}, decodeJWTPayload(t, body["access_token"].(string))["scopes"],
		"a restored role restores the family's consented scopes")
}

// TestPersonGrant_ChainsDoNotConsultIt: token exchange and a CIBA step-up
// extend the person's chain rather than minting for the person, so they
// neither call the resolver nor carry `roles`.
func TestPersonGrant_ChainsDoNotConsultIt(t *testing.T) {
	grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
	tn := newTenant(t, "rfc8693")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)
	alice := uid("pg-alice")
	grants.set(alice, &zeroid.PersonGrant{Scopes: scopes, Roles: []string{"member"}}, nil)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": "external-principal-assertion",
		"account_id":    tn.account,
		"project_id":    tn.project,
		"user_id":       alice,
		"scope":         "data:read",
		"role":          "member",
	}, map[string]string{testTrustedServiceHeader: "trusted-service"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	root := decode(t, resp)["access_token"].(string)
	assert.Equal(t, []any{"member"}, decodeJWTPayload(t, root)["roles"], "the person's root carries roles")
	calls := grants.callsFor(alice)
	require.Len(t, calls, 1)
	assert.Equal(t, "member", calls[0].TrustedRole, "the broker's asserted role reaches the resolver")
	assert.Equal(t, zeroid.PersonGrantExternalPrincipal, calls[0].GrantType)

	child, _ := tn.exchange(t, policyID, uid("pg-agent"), scopes, root)
	childClaims := decodeJWTPayload(t, child["access_token"].(string))
	assert.Equal(t, alice, childClaims["sub"])
	assert.NotContains(t, childClaims, "roles", "a delegated token does not inherit roles")

	status, stepped := stepUp(t, tn.account, tn.project, tn.headers, root, "")
	require.Equal(t, http.StatusOK, status, "step-up: %v", stepped)
	steppedClaims := decodeJWTPayload(t, stepped["access_token"].(string))
	assert.Equal(t, alice, steppedClaims["sub"])
	assert.NotContains(t, steppedClaims, "roles", "a step-up is not a person mint")

	assert.Len(t, grants.callsFor(alice), 1, "neither the exchange nor the step-up consulted the resolver")
	assert.Empty(t, grants.callsFor("user-a"), "the step-up approver is evidence only")
}

// TestPersonGrant_LegacyExchangeDoesNotInheritRoles: under the legacy token
// profile too, a token exchanged from a person's root carries no roles and
// does not consult the resolver.
func TestPersonGrant_LegacyExchangeDoesNotInheritRoles(t *testing.T) {
	grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
	tn := newTenant(t, "legacy")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)
	bob := uid("pg-bob")
	grants.set(bob, &zeroid.PersonGrant{Scopes: scopes, Roles: []string{"member"}}, nil)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": "external-principal-assertion",
		"account_id":    tn.account,
		"project_id":    tn.project,
		"user_id":       bob,
		"scope":         "data:read",
	}, map[string]string{testTrustedServiceHeader: "trusted-service"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	root := decode(t, resp)["access_token"].(string)
	rootClaims := decodeJWTPayload(t, root)
	assert.NotContains(t, rootClaims, "principal_type", "the tenant is on the legacy profile")
	assert.Equal(t, []any{"member"}, rootClaims["roles"])

	child, _ := tn.exchange(t, policyID, uid("pg-legacy-agent"), scopes, root)
	childClaims := decodeJWTPayload(t, child["access_token"].(string))
	assert.NotContains(t, childClaims, "roles", "a delegated token does not inherit roles under legacy either")
	assert.Len(t, grants.callsFor(bob), 1, "the exchange did not consult the resolver")
}

// TestPersonGrant_RolesIsReserved: a caller cannot set `roles`; it comes only
// from the resolver.
func TestPersonGrant_RolesIsReserved(t *testing.T) {
	mint := func(t *testing.T, user string) map[string]any {
		t.Helper()
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":        "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":     "external-principal-assertion",
			"account_id":        testAccountID,
			"project_id":        testProjectID,
			"user_id":           user,
			"additional_claims": map[string]any{"roles": []string{"superadmin"}},
		}, map[string]string{testTrustedServiceHeader: "trusted-service"})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
	}

	t.Run("without a resolver no token carries roles", func(t *testing.T) {
		assert.NotContains(t, mint(t, uid("pg-noroles")), "roles")
	})
	t.Run("with a resolver the resolver's roles win", func(t *testing.T) {
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
		user := uid("pg-roles")
		grants.set(user, &zeroid.PersonGrant{Roles: []string{"member"}}, nil)
		assert.Equal(t, []any{"member"}, mint(t, user)["roles"])
	})
}

// TestPersonGrant_RefusedCodeIsNotConsumed: a code refused at the token
// endpoint (the role changed after authorize) can be redeemed once the role
// is restored, within the code's lifetime.
func TestPersonGrant_RefusedCodeIsNotConsumed(t *testing.T) {
	grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
	user := uid("pg-code")
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testCLIClientID, user, testRedirectURI, challenge, []string{"pg:a"})
	redeem := func(t *testing.T) (int, map[string]any) {
		t.Helper()
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type": "authorization_code", "client_id": testCLIClientID,
			"code": code, "code_verifier": verifier, "redirect_uri": testRedirectURI,
		}, nil)
		return resp.StatusCode, decode(t, resp)
	}

	grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:c"}}, nil)
	status, body := redeem(t)
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])

	grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a"}}, nil)
	status, body = redeem(t)
	require.Equal(t, http.StatusOK, status, "the refused redemption did not consume the code; body=%v", body)
	assert.ElementsMatch(t, []any{"pg:a"}, decodeJWTPayload(t, body["access_token"].(string))["scopes"])
}

// TestPersonGrant_CIBARefusalKeepsTheApproval: a root CIBA grant refused by
// the ceiling does not consume the person's approval; the same auth_req_id
// redeems once the role is restored.
func TestPersonGrant_CIBARefusalKeepsTheApproval(t *testing.T) {
	grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
	user := uid("pg-ciba-retry")
	c := newConfidentialCIBAClient(t)
	resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": user, "scope": "pg:a"})
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "bc-authorize: %v", body)
	id := body["auth_req_id"].(string)
	approveInTenant(t, id, user, adminHeaders())

	grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:c"}}, nil)
	status, polled := pollCIBARaw(t, c, id)
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_scope", polled["error"])

	grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a"}}, nil)
	status, polled = pollCIBARaw(t, c, id)
	require.Equal(t, http.StatusOK, status, "the refusal did not consume the approval; body=%v", polled)
	assert.ElementsMatch(t, []any{"pg:a"}, decodeJWTPayload(t, polled["access_token"].(string))["scopes"])
}

// TestPersonGrant_IDJAGRefusalKeepsTheJTI: an ID-JAG refused by the ceiling
// does not burn its single-use jti, and a replay is refused before the
// resolver is called.
func TestPersonGrant_IDJAGRefusalKeepsTheJTI(t *testing.T) {
	f := newPersonGrantFederation(t)
	grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, f.srv)
	user := uid("pg-jag-retry")
	now := time.Now()
	idjag := f.upstream.SignTokenWithTyp(t, idJAGTyp, map[string]any{
		"iss": f.iss, "aud": f.aud, "sub": user,
		"client_id": f.jagClient.ClientID, "jti": uid("pg-jti"),
		"resource": "https://mcp.person-grant.test", "scope": "pg:a",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	redeem := func(t *testing.T) tokenResponse {
		t.Helper()
		return postFederation(t, f.url, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":     idjag,
			"account_id":    f.cfg.AccountID,
			"project_id":    f.cfg.ProjectID,
			"client_id":     f.jagClient.ClientID,
			"client_secret": f.jagClient.ClientSecret,
		})
	}

	grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:c"}}, nil)
	resp := redeem(t)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_scope", resp.Error)

	grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a"}}, nil)
	resp = redeem(t)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the refusal did not burn the jti; body=%s", resp.RawBody)

	resp = redeem(t)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_grant", resp.Error)
	assert.Contains(t, resp.RawBody, "already been redeemed")
	assert.Len(t, grants.callsFor(user), 2, "the replay never reached the resolver")
}

// TestPersonGrant_CIBAPushRefusalIsDelivered: a push-mode client cannot poll,
// so a ceiling refusal is delivered to its notification endpoint as a CIBA
// Core §12 error (access_denied; transaction_failed when the resolver fails).
func TestPersonGrant_CIBAPushRefusalIsDelivered(t *testing.T) {
	grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
	capt := newCapturingRoundTripper()
	testZeroIDServer.SetBackchannelPingTransport(capt)
	testZeroIDServer.SetBackchannelPingDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelPingDispatchSync(false)
		testZeroIDServer.SetBackchannelPingTransport(nil)
	})

	for _, tc := range []struct {
		name     string
		grant    *zeroid.PersonGrant
		err      error
		wantCode string
	}{
		{"refused", &zeroid.PersonGrant{Scopes: []string{"pg:c"}}, nil, "access_denied"},
		{"resolver failed", nil, errors.New("role store unreachable"), "transaction_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientID := uid("pg-push")
			endpoint := "https://push.example.test/" + clientID
			require.NoError(t, testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
				ClientID:                     clientID,
				Name:                         clientID,
				GrantTypes:                   []string{"client_credentials"},
				RedirectURIs:                 []string{testRedirectURI},
				ClientNotificationEndpoint:   endpoint,
				BackchannelTokenDeliveryMode: "push",
			}))
			user := uid("pg-push-user")
			grants.set(user, tc.grant, tc.err)

			resp := post(t, "/oauth2/bc-authorize", map[string]any{
				"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
				"login_hint": user, "scope": "pg:a", "client_notification_token": "push-bearer",
			}, nil)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			id := decode(t, resp)["auth_req_id"].(string)
			approveInTenant(t, id, user, adminHeaders())

			var delivered []map[string]any
			for _, cb := range capt.requests() {
				if cb.URL != endpoint {
					continue
				}
				var payload map[string]any
				require.NoError(t, json.Unmarshal([]byte(cb.Body), &payload))
				delivered = append(delivered, payload)
			}
			require.Len(t, delivered, 1, "the refusal is delivered exactly once")
			assert.Equal(t, tc.wantCode, delivered[0]["error"])
			assert.Equal(t, id, delivered[0]["auth_req_id"])
			assert.NotContains(t, delivered[0], "access_token")
		})
	}
}
