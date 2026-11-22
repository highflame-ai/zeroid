// Internal service tokens: the on-behalf exchange, the asserted-tenant grant,
// a session broker's external-principal exchange, and client_credentials
// into the service tenant. Every refusal here is a check a receiver relies on
// ZeroID to have made.
package integration_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/domain"
)

// The service tenant and the services configured on the test server
// (runTests). Every client id is under testReservedClientPrefix.
const (
	testServiceAccount       = "acct-svc-platform"
	testServiceProject       = "proj-svc-platform"
	testOnBehalfClient       = "reserved-svc-gateway"
	testBrokerClient         = "reserved-svc-broker"
	testAssertingClient      = "reserved-svc-jobs"
	testServedResourcePrefix = "https://mcp.example.test/"

	testUserSessionResourceGrant = "test_user_session_resource"

	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	assertedGrant      = "urn:highflame:params:oauth:grant-type:asserted-tenant"
	receiverResource   = "urn:example:svc:receiver"
)

// svcClient is one of the deployment's services, seeded the way an operator
// does: a service identity in the service tenant and a private_key_jwt client
// linked to it.
type svcClient struct {
	id       string
	key      *ecdsa.PrivateKey
	identity *domain.Identity
}

var (
	svcClientsMu sync.Mutex
	svcClients   = map[string]svcClient{}
)

// serviceClient seeds (once) and returns the service whose client id is id.
func serviceClient(t *testing.T, id string, grantTypes ...string) svcClient {
	t.Helper()
	svcClientsMu.Lock()
	defer svcClientsMu.Unlock()
	if c, ok := svcClients[id]; ok {
		return c
	}
	ctx := context.Background()
	identity, err := testZeroIDServer.EnsureServiceIdentity(ctx, zeroid.ServiceIdentityConfig{
		AccountID: testServiceAccount, ProjectID: testServiceProject, ExternalID: id, OwnerUserID: "operator",
	})
	require.NoError(t, err)
	key := generateKey(t)
	jwks, err := json.Marshal(clientJWKS(t, key))
	require.NoError(t, err)
	require.NoError(t, testZeroIDServer.EnsureClient(ctx, zeroid.OAuthClientConfig{
		ClientID:                id,
		Name:                    id,
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKS:                    jwks,
		GrantTypes:              grantTypes,
		Scopes:                  []string{"svc:call"},
		IdentityID:              identity.ID,
	}))
	c := svcClient{id: id, key: key, identity: identity}
	svcClients[id] = c
	return c
}

func gateway(t *testing.T) svcClient {
	return serviceClient(t, testOnBehalfClient, tokenExchangeGrant, "client_credentials", assertedGrant)
}

func broker(t *testing.T) svcClient {
	return serviceClient(t, testBrokerClient, tokenExchangeGrant, "client_credentials")
}

func jobs(t *testing.T) svcClient {
	return serviceClient(t, testAssertingClient, assertedGrant, tokenExchangeGrant)
}

// auth adds the client's private_key_jwt authentication to body.
func (c svcClient) auth(t *testing.T, body map[string]any) map[string]any {
	body["client_id"] = c.id
	body["client_assertion"] = clientAssertionFor(t, c.key, c.id)
	body["client_assertion_type"] = clientAssertionType
	return body
}

// onBehalf is the on-behalf exchange request for subject.
func onBehalf(subject string, resource ...string) map[string]any {
	body := map[string]any{
		"grant_type":         tokenExchangeGrant,
		"subject_token":      subject,
		"subject_token_type": issuedTokenTypeAccessToken,
	}
	if len(resource) == 1 {
		body["resource"] = resource[0]
	} else if len(resource) > 1 {
		body["resource"] = resource
	}
	return body
}

// brokerSession mints a person's session through the session broker: the
// external-principal exchange, authenticated as the broker client.
func brokerSession(t *testing.T, accountID, projectID, userID string, extra map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{
		"grant_type": testUserSessionResourceGrant, "account_id": accountID, "project_id": projectID, "user_id": userID,
	}
	for k, v := range extra {
		body[k] = v
	}
	code, got := postStatus(t, "/oauth2/token", broker(t).auth(t, body), nil)
	require.Equal(t, http.StatusOK, code, "%v", got)
	return got
}

func requireSvcRefused(t *testing.T, status int, code string, body map[string]any, got int) {
	t.Helper()
	assert.Equal(t, status, got, "%v", body)
	assert.Equal(t, code, body["error"], "%v", body)
	assert.Empty(t, body["access_token"])
}

func lifetime(t *testing.T, claims map[string]any) time.Duration {
	t.Helper()
	iat, exp := claims["iat"].(float64), claims["exp"].(float64)
	return time.Duration(exp-iat) * time.Second
}

// ── Session broker ───────────────────────────────────────────────────────────

func TestSessionBroker_AuthenticatesAsItsClient(t *testing.T) {
	user := uid("sb-user")

	t.Run("the token names the broker in client_id and trusted_by", func(t *testing.T) {
		got := brokerSession(t, testAccountID, testProjectID, user, nil)
		claims := decodeJWTPayload(t, got["access_token"].(string))
		assert.Equal(t, testBrokerClient, claims["client_id"])
		assert.Equal(t, testBrokerClient, claims["trusted_by"])
		assert.Equal(t, user, claims["sub"])
	})

	t.Run("through the token-exchange form as well", func(t *testing.T) {
		body := broker(t).auth(t, brokerExchange(personToken(t, testAccountID, testProjectID, user), testAccountID, testProjectID, user))
		code, got := postStatus(t, "/oauth2/token", body, nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		assert.Equal(t, testBrokerClient, decodeJWTPayload(t, got["access_token"].(string))["client_id"])
	})

	t.Run("a bad client authentication is refused, with no fallback to the validator", func(t *testing.T) {
		body := map[string]any{
			"grant_type": testUserSessionGrant, "account_id": testAccountID, "project_id": testProjectID, "user_id": user,
			"client_id": testBrokerClient, "client_assertion": clientAssertionFor(t, generateKey(t), testBrokerClient),
			"client_assertion_type": clientAssertionType,
		}
		code, got := postStatus(t, "/oauth2/token", body, trustedServiceHeaders)
		assert.Equal(t, http.StatusUnauthorized, code, "%v", got)
		assert.Empty(t, got["access_token"])
	})

	t.Run("the validator path writes no client_id", func(t *testing.T) {
		claims := decodeJWTPayload(t, personToken(t, testAccountID, testProjectID, user))
		assert.NotContains(t, claims, "client_id")
		assert.Equal(t, "trusted-service", claims["trusted_by"])
	})

	t.Run("a resource-bound session lives five minutes", func(t *testing.T) {
		got := brokerSession(t, testAccountID, testProjectID, user, map[string]any{"resource": receiverResource})
		claims := decodeJWTPayload(t, got["access_token"].(string))
		assert.Equal(t, []any{receiverResource}, claims["resource"])
		assert.LessOrEqual(t, lifetime(t, claims), 5*time.Minute)
	})

	t.Run("no session is minted in the service tenant", func(t *testing.T) {
		body := broker(t).auth(t, map[string]any{
			"grant_type": testUserSessionResourceGrant, "account_id": testServiceAccount,
			"project_id": testServiceProject, "user_id": user,
		})
		code, got := postStatus(t, "/oauth2/token", body, nil)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_request", got, code)
		code, got = postStatus(t, "/oauth2/token", map[string]any{
			"grant_type": testUserSessionGrant, "account_id": testServiceAccount,
			"project_id": testServiceProject, "user_id": user,
		}, trustedServiceHeaders)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_request", got, code)
	})

	t.Run("a custom grant registered without resource still refuses it", func(t *testing.T) {
		code, got := postStatus(t, "/oauth2/token", map[string]any{
			"grant_type": testUserSessionGrant, "account_id": testAccountID, "project_id": testProjectID,
			"user_id": user, "resource": receiverResource,
		}, trustedServiceHeaders)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_target", got, code)
	})
}

// ── On-behalf exchange ───────────────────────────────────────────────────────

func TestOnBehalf_PersonSession(t *testing.T) {
	gw := gateway(t)
	user := uid("obo-person")
	subject := brokerSession(t, testAccountID, testProjectID, user, nil)["access_token"].(string)

	code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(subject, receiverResource)), nil)
	require.Equal(t, http.StatusOK, code, "%v", got)
	tok := got["access_token"].(string)
	claims := decodeJWTPayload(t, tok)

	assert.Equal(t, testAccountID, claims["account_id"], "tenant from the subject")
	assert.Equal(t, testProjectID, claims["project_id"])
	assert.Equal(t, user, claims["sub"])
	assert.Equal(t, "person", claims["subject_kind"])
	assert.Equal(t, user, claims["resolved_user_id"])
	assert.Equal(t, "subject", claims["resolved_user_source"])
	assert.Equal(t, "on_behalf", claims["token_exchange"])
	assert.Equal(t, testOnBehalfClient, claims["client_id"])
	assert.Equal(t, []any{receiverResource}, claims["aud"])
	assert.Equal(t, []any{receiverResource}, claims["resource"])
	assert.NotContains(t, claims, "scopes", "an internal service token carries no scopes")
	assert.NotContains(t, claims, "tenant_source", "the tenant was proven, not asserted")
	assert.LessOrEqual(t, lifetime(t, claims), 5*time.Minute)

	act, ok := claims["act"].(map[string]any)
	require.True(t, ok, "%v", claims)
	assert.Equal(t, gw.identity.WIMSEURI, act["sub"])
	assert.Equal(t, testOnBehalfClient, act["client_id"])
	assert.NotContains(t, act, "act", "a person's session has no actor of its own")
	assert.Equal(t, true, introspect(t, tok)["active"])

	t.Run("revoking the subject revokes the exchanged token", func(t *testing.T) {
		rv := post(t, "/oauth2/token/revoke", map[string]string{"token": subject}, nil)
		require.Less(t, rv.StatusCode, 300)
		_ = rv.Body.Close()
		assert.Equal(t, false, introspect(t, tok)["active"])
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(subject, receiverResource)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_grant", got, code)
	})
}

func TestOnBehalf_WorkloadSubjects(t *testing.T) {
	gw := gateway(t)
	scopes := []string{"data:read"}

	t.Run("rfc8693: an agent acting for a person keeps its chain and resolves to the person", func(t *testing.T) {
		tn := newTenant(t, "rfc8693")
		policyID := tn.policy(t, scopes)
		root, person := tn.userRoot(t, scopes)
		child, agentWIMSE := tn.exchange(t, policyID, uid("obo-agent"), scopes, root)
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(child["access_token"].(string), receiverResource)), nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		claims := decodeJWTPayload(t, got["access_token"].(string))
		assert.Equal(t, tn.account, claims["account_id"])
		assert.Equal(t, "workload", claims["subject_kind"], "an agent-held token is not the person's own session")
		assert.Equal(t, person, claims["resolved_user_id"])
		assert.Equal(t, "subject", claims["resolved_user_source"])
		act := claims["act"].(map[string]any)
		assert.Equal(t, gw.identity.WIMSEURI, act["sub"])
		assert.Equal(t, testOnBehalfClient, act["client_id"])
		nested, ok := act["act"].(map[string]any)
		require.True(t, ok, "the subject's chain is nested, not overwritten: %v", act)
		assert.Equal(t, agentWIMSE, nested["sub"])
		assert.NotContains(t, nested, "client_id")
	})

	t.Run("legacy: a delegated agent resolves to the person in act.sub", func(t *testing.T) {
		tn := newTenant(t, "legacy")
		policyID := tn.policy(t, scopes)
		root, person := tn.userRoot(t, scopes)
		child, _ := tn.exchange(t, policyID, uid("obo-legacy"), scopes, root)
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(child["access_token"].(string), receiverResource)), nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		claims := decodeJWTPayload(t, got["access_token"].(string))
		assert.Equal(t, person, claims["resolved_user_id"])
		assert.Equal(t, "on_behalf", claims["resolved_user_source"])
		act := claims["act"].(map[string]any)
		assert.Equal(t, testOnBehalfClient, act["client_id"], "same act shape under the legacy profile")
		assert.Equal(t, person, act["act"].(map[string]any)["sub"], "the legacy act is preserved beneath")
	})

	t.Run("an agent's own token resolves to its owner", func(t *testing.T) {
		tn := newTenant(t, "rfc8693")
		token, _ := tn.apiKeyRoot(t, scopes)
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(token, receiverResource)), nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		claims := decodeJWTPayload(t, got["access_token"].(string))
		assert.Equal(t, "workload", claims["subject_kind"])
		assert.Equal(t, "test-user", claims["resolved_user_id"])
		assert.Equal(t, "owner", claims["resolved_user_source"])
	})

	t.Run("a suspended subject identity is refused", func(t *testing.T) {
		tn := newTenant(t, "rfc8693")
		reg := registerAgentInTenant(t, uid("obo-susp"), tn.headers)
		code, got := postStatus(t, "/oauth2/token", map[string]any{"grant_type": "api_key", "api_key": reg.APIKey}, nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		token := got["access_token"].(string)
		_, err := testDB.NewUpdate().Table("identities").Set("status = ?", "suspended").
			Where("id = ?", reg.AgentID).Exec(context.Background())
		require.NoError(t, err)
		code, got = postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(token, receiverResource)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_grant", got, code)
	})
}

func TestOnBehalf_RefusesSubjects(t *testing.T) {
	gw := gateway(t)
	user := uid("obo-refuse")
	exchange := func(subject string) (int, map[string]any) {
		return postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(subject, receiverResource)), nil)
	}
	refused := func(t *testing.T, subject string) {
		t.Helper()
		code, got := exchange(subject)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_grant", got, code)
	}

	t.Run("an external-principal token not issued to a session broker", func(t *testing.T) {
		refused(t, personToken(t, testAccountID, testProjectID, user))
	})
	t.Run("an on-behalf token (no laundering)", func(t *testing.T) {
		code, got := exchange(brokerSession(t, testAccountID, testProjectID, user, nil)["access_token"].(string))
		require.Equal(t, http.StatusOK, code, "%v", got)
		refused(t, got["access_token"].(string))
	})
	t.Run("an asserted-tenant token", func(t *testing.T) {
		refused(t, assertTenant(t, jobs(t), testAccountID, testProjectID))
	})
	t.Run("a service's own client_credentials token", func(t *testing.T) {
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, map[string]any{
			"grant_type": "client_credentials", "resource": receiverResource,
		}), nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		refused(t, got["access_token"].(string))
	})
	t.Run("any token in the service tenant", func(t *testing.T) {
		// Carries no client_id: only the service-tenant check refuses it.
		reg := registerAgentInTenant(t, uid("svc-tenant-agent"),
			map[string]string{"X-Account-ID": testServiceAccount, "X-Project-ID": testServiceProject})
		code, got := postStatus(t, "/oauth2/token", map[string]any{"grant_type": "api_key", "api_key": reg.APIKey}, nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		require.NotContains(t, decodeJWTPayload(t, got["access_token"].(string)), "client_id")
		refused(t, got["access_token"].(string))
	})
	t.Run("a revoked subject", func(t *testing.T) {
		tok := brokerSession(t, testAccountID, testProjectID, uid("obo-rv"), nil)["access_token"].(string)
		rv := post(t, "/oauth2/token/revoke", map[string]string{"token": tok}, nil)
		require.Less(t, rv.StatusCode, 300)
		_ = rv.Body.Close()
		refused(t, tok)
	})
	t.Run("an expired, a foreign and a non-token subject", func(t *testing.T) {
		now := time.Now()
		expired := signTestToken(t, testServerPrivKey, testKeyID, testIssuer, now.Add(-time.Hour), now.Add(-time.Minute))
		foreignKey := signTestToken(t, generateKey(t), testKeyID, testIssuer, now, now.Add(time.Minute))
		foreignIssuer := signTestToken(t, testServerPrivKey, testKeyID, "https://other.example.test", now, now.Add(time.Minute))
		for _, tok := range []string{expired, foreignKey, foreignIssuer, "not-a-token"} {
			refused(t, tok)
		}
	})
	t.Run("a resource-bound subject is exchanged only by the service that serves it", func(t *testing.T) {
		served := brokerSession(t, testAccountID, testProjectID, user,
			map[string]any{"resource": testServedResourcePrefix + "server-1"})["access_token"].(string)
		code, got := exchange(served)
		require.Equal(t, http.StatusOK, code, "%v", got)
		assert.Equal(t, "workload", decodeJWTPayload(t, got["access_token"].(string))["subject_kind"],
			"a resource-bound token is not a person's own session")

		code, got = postStatus(t, "/oauth2/token", broker(t).auth(t, onBehalf(served, receiverResource)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_grant", got, code)

		other := brokerSession(t, testAccountID, testProjectID, user,
			map[string]any{"resource": "https://elsewhere.example.test/x"})["access_token"].(string)
		refused(t, other)
	})
}

func TestOnBehalf_RefusesClients(t *testing.T) {
	subject := func(t *testing.T) string {
		return brokerSession(t, testAccountID, testProjectID, uid("obo-cl"), nil)["access_token"].(string)
	}

	t.Run("no client authentication", func(t *testing.T) {
		body := onBehalf(subject(t), receiverResource)
		body["client_id"] = testOnBehalfClient
		code, got := postStatus(t, "/oauth2/token", body, nil)
		assert.Equal(t, http.StatusUnauthorized, code, "%v", got)
		assert.Empty(t, got["access_token"])
	})

	t.Run("a tenant's own private_key_jwt client", func(t *testing.T) {
		ext := uid("obo-tenant")
		reg := registerAgent(t, ext)
		key := generateKey(t)
		resp := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id": ext, "name": ext, "token_endpoint_auth_method": "private_key_jwt",
			"jwks": clientJWKS(t, key), "grant_types": []string{tokenExchangeGrant}, "scopes": []string{"data:read"},
			"identity_id": reg.AgentID,
		}, adminHeaders())
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		_ = resp.Body.Close()
		c := svcClient{id: ext, key: key}
		code, got := postStatus(t, "/oauth2/token", c.auth(t, onBehalf(subject(t), receiverResource)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "unauthorized_client", got, code)
	})

	t.Run("a tenant cannot register a reserved-looking id", func(t *testing.T) {
		resp := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id": "Reserved-Svc-Gateway2", "name": "x", "grant_types": []string{tokenExchangeGrant},
		}, adminHeaders())
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("an unreserved client linked to a service identity", func(t *testing.T) {
		id, err := testZeroIDServer.EnsureServiceIdentity(context.Background(), zeroid.ServiceIdentityConfig{
			AccountID: testServiceAccount, ProjectID: testServiceProject, ExternalID: uid("unreserved"), OwnerUserID: "operator",
		})
		require.NoError(t, err)
		key := generateKey(t)
		clientID := uid("unreserved-client")
		resp := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id": clientID, "name": clientID, "token_endpoint_auth_method": "private_key_jwt",
			"jwks": clientJWKS(t, key), "grant_types": []string{tokenExchangeGrant}, "scopes": []string{"svc:call"},
			"identity_id": id.ID,
		}, map[string]string{"X-Account-ID": testServiceAccount, "X-Project-ID": testServiceProject})
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		_ = resp.Body.Close()
		c := svcClient{id: clientID, key: key}
		code, got := postStatus(t, "/oauth2/token", c.auth(t, onBehalf(subject(t), receiverResource)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "unauthorized_client", got, code)
	})

	t.Run("a seeded client whose id is not reserved", func(t *testing.T) {
		// Linked to a service identity by the operator's own seeding path:
		// only the reservation is missing.
		c := serviceClient(t, uid("unreserved-seed"), tokenExchangeGrant)
		code, got := postStatus(t, "/oauth2/token", c.auth(t, onBehalf(subject(t), receiverResource)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "unauthorized_client", got, code)
	})

	t.Run("a reserved, seeded client linked to an identity outside the service tenant", func(t *testing.T) {
		ctx := context.Background()
		id, err := testZeroIDServer.EnsureServiceIdentity(ctx, zeroid.ServiceIdentityConfig{
			AccountID: testAccountID, ProjectID: testProjectID, ExternalID: uid("svc-in-tenant"), OwnerUserID: "operator",
		})
		require.NoError(t, err)
		key := generateKey(t)
		jwks, err := json.Marshal(clientJWKS(t, key))
		require.NoError(t, err)
		clientID := testReservedClientPrefix + uid("elsewhere")
		require.NoError(t, testZeroIDServer.EnsureClient(ctx, zeroid.OAuthClientConfig{
			ClientID: clientID, Name: clientID, TokenEndpointAuthMethod: "private_key_jwt", JWKS: jwks,
			GrantTypes: []string{tokenExchangeGrant}, Scopes: []string{"svc:call"}, IdentityID: id.ID,
		}))
		c := svcClient{id: clientID, key: key}
		code, got := postStatus(t, "/oauth2/token", c.auth(t, onBehalf(subject(t), receiverResource)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "unauthorized_client", got, code)
	})

	t.Run("a service client not registered for token exchange", func(t *testing.T) {
		c := serviceClient(t, "reserved-svc-ccnly", "client_credentials")
		code, got := postStatus(t, "/oauth2/token", c.auth(t, onBehalf(subject(t), receiverResource)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "unauthorized_client", got, code)
	})

	t.Run("a suspended service identity", func(t *testing.T) {
		c := serviceClient(t, "reserved-svc-suspended", tokenExchangeGrant)
		_, err := testDB.NewUpdate().Table("identities").Set("status = ?", "suspended").
			Where("id = ?", c.identity.ID).Exec(context.Background())
		require.NoError(t, err)
		code, got := postStatus(t, "/oauth2/token", c.auth(t, onBehalf(subject(t), receiverResource)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_grant", got, code)
	})
}

func TestOnBehalf_RequestShape(t *testing.T) {
	gw := gateway(t)
	subject := brokerSession(t, testAccountID, testProjectID, uid("obo-shape"), nil)["access_token"].(string)

	t.Run("a resource is required, and only one", func(t *testing.T) {
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(subject)), nil)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_target", got, code)
		code, got = postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(subject, receiverResource, "urn:example:svc:other")), nil)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_target", got, code)
	})
	for name, extra := range map[string]map[string]any{
		"additional_claims": {"additional_claims": map[string]any{"subject_kind": "person", "resolved_user_id": "victim", "tenant_source": ""}},
		"a tenant":          {"account_id": uid("other"), "project_id": "p"},
		"a user":            {"user_id": "victim"},
		"a role":            {"role": "admin"},
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			body := onBehalf(subject, receiverResource)
			for k, v := range extra {
				body[k] = v
			}
			code, got := postStatus(t, "/oauth2/token", gw.auth(t, body), nil)
			requireSvcRefused(t, http.StatusBadRequest, "invalid_request", got, code)
		})
	}
	t.Run("a scope is refused", func(t *testing.T) {
		body := onBehalf(subject, receiverResource)
		body["scope"] = "data:read"
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, body), nil)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_scope", got, code)
	})

	t.Run("exp is the earlier of five minutes and the subject's", func(t *testing.T) {
		short := brokerSession(t, testAccountID, testProjectID, uid("obo-exp"),
			map[string]any{"resource": testServedResourcePrefix + "s"})["access_token"].(string)
		subjectExp := decodeJWTPayload(t, short)["exp"].(float64)
		time.Sleep(1100 * time.Millisecond)
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(short, receiverResource)), nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		assert.LessOrEqual(t, decodeJWTPayload(t, got["access_token"].(string))["exp"].(float64), subjectExp)
	})

	t.Run("an on-behalf token is never delegated further", func(t *testing.T) {
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(subject, receiverResource)), nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		tn := hrdTenant{account: testAccountID, project: testProjectID, headers: adminHeaders()}
		status, body := tn.exchangeAttempt(t, "", []string{"data:read"}, got["access_token"].(string))
		requireSvcRefused(t, http.StatusBadRequest, "invalid_grant", body, status)
	})

	t.Run("nor used to start a CIBA chain", func(t *testing.T) {
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(subject, receiverResource)), nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		c := newConfidentialCIBAClient(t)
		resp := post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id": c.ID, "client_secret": c.Secret, "account_id": testAccountID, "project_id": testProjectID,
			"login_hint": "user-a", "requesting_token": got["access_token"].(string),
		}, cibaInitiatorHeaders())
		body := decode(t, resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
		assert.Empty(t, body["auth_req_id"])
	})

	t.Run("nor presented as an external-principal subject", func(t *testing.T) {
		code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(subject, receiverResource)), nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		user := decodeJWTPayload(t, subject)["sub"].(string)
		code, refusedBody := postStatus(t, "/oauth2/token",
			brokerExchange(got["access_token"].(string), testAccountID, testProjectID, user), trustedServiceHeaders)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_grant", refusedBody, code)
	})
}

func TestServiceTokens_Disabled(t *testing.T) {
	subject := brokerSession(t, testAccountID, testProjectID, uid("off"), nil)["access_token"].(string)
	gw := gateway(t)
	jb := jobs(t)
	testZeroIDServer.SetServiceTokens(zeroid.ServiceTokensConfig{})
	t.Cleanup(func() {
		testZeroIDServer.SetServiceTokens(zeroid.ServiceTokensConfig{
			AccountID: testServiceAccount, ProjectID: testServiceProject,
			AssertedTenantClients: []string{testAssertingClient}, SessionBrokerClients: []string{testBrokerClient},
			ServedResources: map[string][]string{testOnBehalfClient: {testServedResourcePrefix}},
		})
	})

	code, got := postStatus(t, "/oauth2/token", gw.auth(t, onBehalf(subject, receiverResource)), nil)
	assert.NotEqual(t, http.StatusOK, code, "%v", got)
	assert.Empty(t, got["access_token"])

	code, got = postStatus(t, "/oauth2/token", jb.auth(t, map[string]any{
		"grant_type": assertedGrant, "account_id": testAccountID, "project_id": testProjectID, "resource": receiverResource,
	}), nil)
	requireSvcRefused(t, http.StatusBadRequest, "unsupported_grant_type", got, code)
}

// ── Asserted-tenant grant ────────────────────────────────────────────────────

func assertTenant(t *testing.T, c svcClient, accountID, projectID string) string {
	t.Helper()
	code, got := postStatus(t, "/oauth2/token", c.auth(t, map[string]any{
		"grant_type": assertedGrant, "account_id": accountID, "project_id": projectID, "resource": receiverResource,
	}), nil)
	require.Equal(t, http.StatusOK, code, "%v", got)
	return got["access_token"].(string)
}

func TestAssertedTenant(t *testing.T) {
	jb := jobs(t)
	tn := newTenant(t, "")

	t.Run("issues a marked, audited, five-minute token", func(t *testing.T) {
		tok := assertTenant(t, jb, tn.account, tn.project)
		claims := decodeJWTPayload(t, tok)
		assert.Equal(t, tn.account, claims["account_id"])
		assert.Equal(t, tn.project, claims["project_id"])
		assert.Equal(t, "asserted", claims["tenant_source"])
		assert.Equal(t, "asserted_tenant", claims["grant_type"])
		assert.Equal(t, jb.identity.WIMSEURI, claims["sub"])
		assert.Equal(t, testAssertingClient, claims["client_id"])
		assert.Equal(t, []any{receiverResource}, claims["resource"])
		assert.NotContains(t, claims, "scopes")
		assert.NotContains(t, claims, "resolved_user_id")
		assert.LessOrEqual(t, lifetime(t, claims), 5*time.Minute)
		act := claims["act"].(map[string]any)
		assert.Equal(t, jb.identity.WIMSEURI, act["sub"])
		assert.Equal(t, testAssertingClient, act["client_id"])

		var actions []string
		err := testDB.NewSelect().Table("identity_audit_logs").Column("action").
			Where("account_id = ?", tn.account).Where("project_id = ?", tn.project).
			Where("new_data->>'jti' = ?", claims["jti"]).Scan(context.Background(), &actions)
		require.NoError(t, err)
		assert.Equal(t, []string{"ASSERT_TENANT"}, actions)
	})

	t.Run("only for the configured clients", func(t *testing.T) {
		// The gateway is a service and lists the grant, but is not configured.
		code, got := postStatus(t, "/oauth2/token", gateway(t).auth(t, map[string]any{
			"grant_type": assertedGrant, "account_id": tn.account, "project_id": tn.project, "resource": receiverResource,
		}), nil)
		requireSvcRefused(t, http.StatusBadRequest, "unauthorized_client", got, code)
	})

	for name, tc := range map[string]struct {
		body map[string]any
		code string
	}{
		"no tenant":          {map[string]any{"resource": receiverResource}, "invalid_request"},
		"the service tenant": {map[string]any{"account_id": testServiceAccount, "project_id": "x", "resource": receiverResource}, "invalid_request"},
		"no resource":        {map[string]any{"account_id": tn.account, "project_id": tn.project}, "invalid_target"},
		"a scope":            {map[string]any{"account_id": tn.account, "project_id": tn.project, "resource": receiverResource, "scope": "a"}, "invalid_scope"},
		"additional_claims":  {map[string]any{"account_id": tn.account, "project_id": tn.project, "resource": receiverResource, "additional_claims": map[string]any{"tenant_source": "proven"}}, "invalid_request"},
		"a subject_token":    {map[string]any{"account_id": tn.account, "project_id": tn.project, "resource": receiverResource, "subject_token": "x"}, "invalid_request"},
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			body := map[string]any{"grant_type": assertedGrant}
			for k, v := range tc.body {
				body[k] = v
			}
			code, got := postStatus(t, "/oauth2/token", jb.auth(t, body), nil)
			requireSvcRefused(t, http.StatusBadRequest, tc.code, got, code)
		})
	}

	t.Run("an unauthenticated caller is refused", func(t *testing.T) {
		code, got := postStatus(t, "/oauth2/token", map[string]any{
			"grant_type": assertedGrant, "client_id": testAssertingClient,
			"account_id": tn.account, "project_id": tn.project, "resource": receiverResource,
		}, nil)
		assert.Equal(t, http.StatusUnauthorized, code, "%v", got)
		assert.Empty(t, got["access_token"])
	})

	t.Run("tenant_source cannot be set on any other grant", func(t *testing.T) {
		claims := decodeJWTPayload(t, brokerSession(t, tn.account, tn.project, uid("ts"),
			map[string]any{"additional_claims": map[string]any{"tenant_source": "asserted", "subject_kind": "person"}})["access_token"].(string))
		assert.NotContains(t, claims, "tenant_source")
		assert.NotContains(t, claims, "subject_kind")
	})
}

// ── client_credentials into the service tenant ──────────────────────────────

func TestServiceTenant_ClientCredentials(t *testing.T) {
	t.Run("a service's own client mints a five-minute token", func(t *testing.T) {
		code, got := postStatus(t, "/oauth2/token", gateway(t).auth(t, map[string]any{
			"grant_type": "client_credentials", "resource": receiverResource,
		}), nil)
		require.Equal(t, http.StatusOK, code, "%v", got)
		claims := decodeJWTPayload(t, got["access_token"].(string))
		assert.Equal(t, testServiceAccount, claims["account_id"])
		assert.Equal(t, testOnBehalfClient, claims["client_id"])
		assert.LessOrEqual(t, lifetime(t, claims), 5*time.Minute)
	})

	t.Run("exactly one resource is required", func(t *testing.T) {
		code, got := postStatus(t, "/oauth2/token", gateway(t).auth(t, map[string]any{"grant_type": "client_credentials"}), nil)
		requireSvcRefused(t, http.StatusBadRequest, "invalid_target", got, code)
	})

	t.Run("an unlinked client cannot name the service tenant", func(t *testing.T) {
		client := registerOAuthClient(t, uid("svc-squat"), []string{"svc:call"})
		code, got := postStatus(t, "/oauth2/token", map[string]any{
			"grant_type": "client_credentials", "client_id": client.ClientID, "client_secret": client.ClientSecret,
			"account_id": testServiceAccount, "project_id": testServiceProject,
		}, nil)
		requireSvcRefused(t, http.StatusBadRequest, "unauthorized_client", got, code)
	})
}

// signTestToken signs a minimal access token with key, for subjects ZeroID
// must refuse: expired, foreign-signed, or from another issuer.
func signTestToken(t *testing.T, key *ecdsa.PrivateKey, kid, issuer string, iat, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().Issuer(issuer).Subject("alice").IssuedAt(iat).Expiration(exp).
		JwtID(uid("forged")).Audience([]string{issuer}).Build()
	require.NoError(t, err)
	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.KeyIDKey, kid))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return strings.TrimSpace(string(signed))
}
