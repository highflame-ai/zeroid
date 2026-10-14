package integration_test

// Per-account trusted issuers (ADR 0042 D3a, D4, D5, D5a, D6, D7): the admin
// API, then both person paths end to end against the mock IdP, then every
// INV-IDN-014 negative. CAP-IDN-028 and INV-IDN-014 in
// highflame-architecture capabilities.yaml.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/mockidp"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// dbFederation is a ZeroID with federation.issuer_store=db, a mock IdP it
// trusts through rows, and a person resolver standing in for Admin.
type dbFederation struct {
	srv    *zeroid.Server
	http   *httptest.Server
	idp    *mockidp.IdP
	idpSrv *httptest.Server

	mu            sync.Mutex
	members       map[string]string // IdP subject -> Highflame user id
	resolverCalls atomic.Int64
	lastPerson    zeroid.FederatedPersonRequest
}

func newDBFederation(t *testing.T) *dbFederation {
	t.Helper()
	idp, err := mockidp.New("https://placeholder")
	require.NoError(t, err)
	idpSrv := httptest.NewTLSServer(idp.Handler())
	t.Cleanup(idpSrv.Close)
	idp.SetBaseURL(idpSrv.URL)

	f := &dbFederation{idp: idp, idpSrv: idpSrv, members: map[string]string{}}
	// One mock Entra tenant stands in for a shared issuer (like
	// accounts.google.com), beside the built-in list.
	f.srv, f.http = newDBFederationServer(t, append(slices.Clone(domain.DefaultSharedIssuers), idp.EntraIssuer(sharedTenant))...)
	f.srv.SetFederatedPersonResolver(func(_ context.Context, r zeroid.FederatedPersonRequest) (string, error) {
		f.resolverCalls.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastPerson = r
		if id, ok := f.members[r.Issuer+"|"+r.Subject]; ok {
			return id, nil
		}
		return "", zeroid.ErrPersonNotMember
	})
	return f
}

// newDBFederationServer starts a ZeroID reading issuer rows, on the shared
// database, as federationIssuer.
func newDBFederationServer(t *testing.T, sharedIssuers ...string) (*zeroid.Server, *httptest.Server) {
	t.Helper()
	require.NoError(t, initFederationKeyMaterial())
	cfg := zeroid.Config{
		Server:   zeroid.ServerConfig{Port: "0", Env: "test", ShutdownTimeoutSeconds: 5},
		Database: zeroid.DatabaseConfig{URL: sharedDBURL, MaxOpenConns: 5, MaxIdleConns: 2},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath: fedKeyPaths.privPath, PublicKeyPath: fedKeyPaths.pubPath, KeyID: "fed-test-key-1",
			RSAPrivateKeyPath: fedKeyPaths.rsaPriv, RSAPublicKeyPath: fedKeyPaths.rsaPub, RSAKeyID: "fed-test-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer: federationIssuer, DefaultTTL: 3600, MaxTTL: 90 * 24 * 3600,
			HMACSecret: testHMACSecret, AuthCodeIssuer: federationIssuer,
		},
		Telemetry:   zeroid.TelemetryConfig{Enabled: false},
		Logging:     zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain: testWIMSE,
		Federation:  zeroid.FederationConfig{IssuerStore: "db", AllowPrivateEndpoints: true, SharedIssuers: sharedIssuers},
	}
	insecure := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	srv, err := zeroid.NewServer(cfg,
		zeroid.WithExternalIssuerHTTPClient(insecure),
		zeroid.WithExternalIssuerJWKSOption(authjwt.WithHTTPClient(insecure)))
	require.NoError(t, err)
	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	return srv, httpSrv
}

func (f *dbFederation) member(iss, subject, userID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.members[iss+"|"+subject] = userID
}

// call sends an admin request to the federation server and decodes the body.
func (f *dbFederation) call(t *testing.T, method, path string, body any, headers map[string]string) (int, map[string]any) {
	t.Helper()
	return callJSON(t, f.http.URL, method, path, body, headers)
}

func callJSON(t *testing.T, base, method, path string, body any, headers map[string]string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+adminPath(path), r)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func (f *dbFederation) mint(t *testing.T, profile string, claims map[string]any) string {
	t.Helper()
	tok, _, err := f.idp.Mint(mockidp.MintRequest{Profile: profile, Claims: claims})
	require.NoError(t, err)
	return tok
}

// tiTenant is one account and project with the headers that select it.
type tiTenant struct {
	account, project string
	headers          map[string]string
}

func newTITenant(t *testing.T) tiTenant {
	t.Helper()
	tn := tiTenant{account: uid("ti-acct"), project: "ti-proj"}
	tn.headers = map[string]string{"X-Account-ID": tn.account, "X-Project-ID": tn.project, "X-User-ID": "admin@" + tn.account}
	return tn
}

type tiAgent struct {
	id, wimse, extID string
	key              *ecdsa.PrivateKey
}

// agent registers an active agent with a key and a policy allowing both
// person grants and delegation.
func (tn tiTenant) agent(t *testing.T) tiAgent {
	t.Helper()
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ti-policy"),
		"allowed_grant_types":  []string{"token_exchange", "jwt_bearer"},
		"allowed_scopes":       []string{"tools:read"},
		"user_grant_scopes":    []string{"tools:read"},
		"max_delegation_depth": 5,
		"max_ttl_seconds":      3600,
	}, tn.headers)
	key := generateKey(t)
	extID := uid("ti-agent")
	resp := post(t, adminPath("/identities"), map[string]any{
		"external_id":          extID,
		"identity_type":        "agent",
		"trust_level":          "unverified",
		"owner_user_id":        "user-test-owner",
		"credential_policy_id": policyID,
		"public_key_pem":       ecPublicKeyPEM(t, key),
	}, tn.headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	got := decode(t, resp)
	_ = resp.Body.Close()
	return tiAgent{id: got["id"].(string), wimse: got["wimse_uri"].(string), extID: extID, key: key}
}

// discoveredAgent ingests a discovered (unadopted) agent into the tenant.
func (tn tiTenant) discoveredAgent(t *testing.T) string {
	t.Helper()
	resp := post(t, adminPath("/identities/discovered"), map[string]any{
		"external_id": uid("ti-discovered"), "origin": "okta", "name": "unadopted agent",
	}, tn.headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decode(t, resp)
	_ = resp.Body.Close()
	return out["identity"].(map[string]any)["id"].(string)
}

func (f *dbFederation) entraRow(t *testing.T, tn tiTenant, tenantID string, audiences []string) map[string]any {
	t.Helper()
	status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
		"kind":              "person",
		"display_name":      "Mock Entra",
		"issuer":            f.idp.EntraIssuer(tenantID),
		"audiences":         audiences,
		"algorithms":        []string{"RS256"},
		"claim_mapping":     map[string]string{"user_id": "oid", "email": "email", "email_verified": "xms_edov", "name": "name"},
		"claim_constraints": map[string][]string{"tid": {tenantID}},
	}, tn.headers)
	require.Equal(t, http.StatusCreated, status, "create entra row: %v", body)
	return body
}

func (f *dbFederation) oktaRow(t *testing.T, tn tiTenant) map[string]any {
	t.Helper()
	status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
		"kind":   "person",
		"issuer": f.idp.OktaIssuer(),
		// No audiences: an ID-JAG's audience is ZeroID's issuer.
		"claim_mapping": map[string]string{"user_id": "sub", "email": "email", "email_verified": "email_verified"},
	}, tn.headers)
	require.Equal(t, http.StatusCreated, status, "create okta row: %v", body)
	return body
}

// bind binds subjectKey under the row to the agent and creates the agent's
// private_key_jwt client (client_id defaults to subjectKey).
func (f *dbFederation) bind(t *testing.T, tn tiTenant, rowID, subjectKey, identityID string, client bool) (int, map[string]any) {
	t.Helper()
	body := map[string]any{"subject_key": subjectKey, "identity_id": identityID}
	if client {
		body["oauth_client"] = map[string]any{}
	}
	return f.call(t, http.MethodPost, "/external-issuers/"+rowID+"/bindings", body, tn.headers)
}

// keyClient registers a private_key_jwt client in tn, linked to identityID
// when it is non-empty, and returns its key.
func keyClient(t *testing.T, tn tiTenant, clientID, identityID string) *ecdsa.PrivateKey {
	t.Helper()
	key := generateKey(t)
	body := map[string]any{
		"client_id":                  clientID,
		"name":                       clientID,
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       clientJWKS(t, key),
		"grant_types":                []string{"urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
	}
	if identityID != "" {
		body["identity_id"] = identityID
	}
	resp := post(t, adminPath("/oauth/clients"), body, tn.headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "register client %s", clientID)
	_ = resp.Body.Close()
	return key
}

func clientCreds(t *testing.T, clientID string, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	return map[string]any{
		"client_id":             clientID,
		"client_assertion":      rpAssertion(t, oauthClientResp{ClientID: clientID, Key: key}),
		"client_assertion_type": clientAssertionType,
	}
}

func merged(maps ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func idTokenExchangeBody(idToken string) map[string]any {
	return map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      idToken,
		"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
	}
}

// actorAssertion is the agent's self-signed RFC 7523 assertion for the
// federation server.
func actorAssertion(t *testing.T, key *ecdsa.PrivateKey, wimse string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().Issuer(wimse).Subject(wimse).Audience([]string{federationIssuer}).
		IssuedAt(now).Expiration(now.Add(5 * time.Minute)).JwtID(uid("actor")).Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

func requireRefused(t *testing.T, resp tokenResponse, code string) {
	t.Helper()
	assert.Equal(t, code, resp.Error, "body=%s", resp.RawBody)
	assert.Empty(t, resp.AccessToken, "a refused grant mints nothing")
}

// ── Admin API ────────────────────────────────────────────────────────────────

func TestTrustedIssuers_AdminAPI(t *testing.T) {
	f := newDBFederation(t)
	a, b := newTITenant(t), newTITenant(t)
	tid := uid("tid")
	iss := f.idp.EntraIssuer(tid)
	app1, app2, app3 := uid("app-1"), uid("app-2"), uid("app-3")

	row := f.entraRow(t, a, tid, []string{app1})
	id := row["id"].(string)
	assert.Equal(t, a.account, row["account_id"])
	assert.Equal(t, "admin", row["source"])
	assert.Equal(t, "admin@"+a.account, row["created_by"])
	check := row["jwks_check"].(map[string]any)
	assert.Equal(t, true, check["reachable"])
	assert.EqualValues(t, 1, check["key_count"])

	t.Run("the same issuer and kind again in the account is refused", func(t *testing.T) {
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": iss, "audiences": []string{"x"},
			"claim_mapping": map[string]string{"user_id": "oid"},
		}, a.headers)
		assert.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "issuer_already_trusted", body["code"])
	})
	t.Run("a second account trusting the same unique issuer is refused, without naming the first", func(t *testing.T) {
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": iss, "audiences": []string{"x"},
			"claim_mapping": map[string]string{"user_id": "oid"},
		}, b.headers)
		assert.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "issuer_already_trusted", body["code"])
		assert.NotContains(t, fmt.Sprint(body), a.account)
	})
	t.Run("a second account cannot hold the issuer under the other kind either", func(t *testing.T) {
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "workload", "issuer": iss, "audiences": []string{"x"},
		}, b.headers)
		assert.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "issuer_already_trusted", body["code"])
	})
	t.Run("the same issuer as a workload issuer of the same account is allowed", func(t *testing.T) {
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "workload", "issuer": iss, "audiences": []string{federationIssuer},
		}, a.headers)
		assert.Equal(t, http.StatusCreated, status, "%v", body)
	})
	t.Run("another account's row is not found", func(t *testing.T) {
		status, body := f.call(t, http.MethodGet, "/external-issuers/"+id, nil, b.headers)
		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "not_found", body["code"])
		status, _ = f.call(t, http.MethodPatch, "/external-issuers/"+id, map[string]any{"enabled": false}, b.headers)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = f.call(t, http.MethodDelete, "/external-issuers/"+id, nil, b.headers)
		assert.Equal(t, http.StatusNotFound, status)
		_, list := f.call(t, http.MethodGet, "/external-issuers", nil, b.headers)
		assert.Empty(t, list["items"])
	})
	t.Run("a malformed id is not found, not a server error", func(t *testing.T) {
		for _, path := range []string{"/external-issuers/abc", "/external-issuers/abc/bindings", "/external-issuers/abc/bindings/def"} {
			status, body := f.call(t, http.MethodGet, path, nil, a.headers)
			assert.Equal(t, http.StatusNotFound, status, "%s: %v", path, body)
		}
	})
	t.Run("list is the account's rows", func(t *testing.T) {
		status, list := f.call(t, http.MethodGet, "/external-issuers", nil, a.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, "db", list["issuer_store"])
		assert.Len(t, list["items"], 2)
	})
	for name, tc := range map[string]struct {
		body   map[string]any
		status int
		code   string
	}{
		"not a URL":                 {map[string]any{"kind": "person", "issuer": "ftp://x", "audiences": []string{"a"}, "claim_mapping": map[string]string{"user_id": "sub"}}, 400, "invalid_issuer"},
		"HS256":                     {map[string]any{"kind": "person", "issuer": "https://hs.example", "audiences": []string{"a"}, "algorithms": []string{"HS256"}, "claim_mapping": map[string]string{"user_id": "sub"}}, 400, "invalid_algorithms"},
		"workload with no audience": {map[string]any{"kind": "workload", "issuer": "https://na.example"}, 400, "invalid_audiences"},
		"entra common":              {map[string]any{"kind": "person", "preset": "entra", "issuer": "https://login.microsoftonline.com/common/v2.0", "audiences": []string{"a"}}, 400, "invalid_issuer"},
		"shared issuer without constraints": {map[string]any{"kind": "person", "issuer": "https://accounts.google.com",
			"audiences": []string{"a"}, "claim_mapping": map[string]string{"user_id": "sub"}}, 422, "shared_issuer_requires_constraints"},
		"unreachable discovery": {map[string]any{"kind": "person", "issuer": "https://127.0.0.1:1",
			"audiences": []string{"a"}, "claim_mapping": map[string]string{"user_id": "sub"}}, 422, "discovery_unreachable"},
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			status, body := f.call(t, http.MethodPost, "/external-issuers", tc.body, a.headers)
			assert.Equal(t, tc.status, status, "%v", body)
			assert.Equal(t, tc.code, body["code"])
		})
	}
	t.Run("check probes a JWKS and reports keys only", func(t *testing.T) {
		status, body := f.call(t, http.MethodPost, "/external-issuers/check", map[string]any{"issuer": f.idp.OktaIssuer()}, a.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["reachable"])
		assert.Equal(t, []any{"okta-mock-key"}, body["kids"])
		status, body = f.call(t, http.MethodPost, "/external-issuers/check", map[string]any{"issuer": "https://127.0.0.1:1"}, a.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, false, body["reachable"])
		assert.Equal(t, "discovery_unreachable", body["error"])
	})
	t.Run("patch changes mutable fields only", func(t *testing.T) {
		status, body := f.call(t, http.MethodPatch, "/external-issuers/"+id, map[string]any{
			"display_name": "renamed", "audiences": []string{app1, app2},
		}, a.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, "renamed", body["display_name"])
		assert.Equal(t, []any{app1, app2}, body["audiences"])
		status, _ = f.call(t, http.MethodPatch, "/external-issuers/"+id, map[string]any{"issuer": "https://other"}, a.headers)
		assert.Equal(t, http.StatusUnprocessableEntity, status, "issuer is not patchable (unknown field)")
	})

	t.Run("bindings", func(t *testing.T) {
		agent := a.agent(t)
		status, body := f.bind(t, a, id, app1, agent.id, true)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		assert.Equal(t, true, body["enabled"], "an active agent's binding is enabled when written")
		assert.Equal(t, map[string]any{"client_id": app1, "created": true}, body["oauth_client"])
		bindingID := body["id"].(string)

		other := a.agent(t)
		status, body = f.bind(t, a, id, app1, other.id, false)
		assert.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "binding_conflict", body["code"], "one enabled binding per (issuer, subject key)")

		status, body = f.bind(t, a, id, app2, other.id, true)
		assert.Equal(t, http.StatusCreated, status, "%v", body)
		status, body = f.bind(t, a, id, app3, agent.id, true)
		assert.Equal(t, http.StatusCreated, status, "a second subject key may bind the same agent: %v", body)
		assert.Equal(t, true, body["oauth_client"].(map[string]any)["created"], "client app-3 is new")

		discovered := a.discoveredAgent(t)
		status, body = f.bind(t, a, id, "app-discovered", discovered, false)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		assert.Equal(t, false, body["enabled"], "a discovered agent's binding is created disabled (D6)")
		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+id+"/bindings/"+body["id"].(string), map[string]any{"enabled": true}, a.headers)
		assert.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "identity_not_active", body["code"])

		foreign := b.agent(t)
		status, body = f.bind(t, a, id, "app-foreign", foreign.id, false)
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		assert.Equal(t, "identity_not_found", body["code"], "an identity in another account cannot be bound")

		status, list := f.call(t, http.MethodGet, "/external-issuers/"+id+"/bindings", nil, a.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Len(t, list["items"], 4)
		status, _ = f.call(t, http.MethodGet, "/external-issuers/"+id+"/bindings", nil, b.headers)
		assert.Equal(t, http.StatusNotFound, status)

		status, body = f.call(t, http.MethodPatch, "/external-issuers/"+id+"/bindings/"+bindingID, map[string]any{"enabled": false}, a.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, false, body["enabled"])
		status, _ = f.call(t, http.MethodDelete, "/external-issuers/"+id+"/bindings/"+bindingID, nil, a.headers)
		assert.Equal(t, http.StatusNoContent, status)
	})

	t.Run("delete removes the row and its bindings", func(t *testing.T) {
		status, _ := f.call(t, http.MethodDelete, "/external-issuers/"+id, nil, a.headers)
		require.Equal(t, http.StatusNoContent, status)
		status, _ = f.call(t, http.MethodGet, "/external-issuers/"+id, nil, a.headers)
		assert.Equal(t, http.StatusNotFound, status)
		n, err := testDB.NewSelect().Table("external_issuer_bindings").Where("issuer_id = ?", id).Count(context.Background())
		require.NoError(t, err)
		assert.Zero(t, n)
	})

	t.Run("every write is audited with its actor", func(t *testing.T) {
		var actions []string
		err := testDB.NewSelect().Table("identity_audit_logs").Column("action").
			Where("account_id = ?", a.account).Where("caller_user_id = ?", "admin@"+a.account).
			Where("table_name IN ('external_issuers', 'external_issuer_bindings')").
			Scan(context.Background(), &actions)
		require.NoError(t, err)
		for _, want := range []string{"INSERT_EXTERNAL_ISSUER", "UPDATE_EXTERNAL_ISSUER", "DELETE_EXTERNAL_ISSUER", "INSERT_ISSUER_BINDING", "DELETE_ISSUER_BINDING"} {
			assert.Contains(t, actions, want)
		}
	})

	t.Run("a config-mode server refuses writes", func(t *testing.T) {
		status, body := callJSON(t, testServer.URL, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": "https://cfg.example", "audiences": []string{"a"},
			"claim_mapping": map[string]string{"user_id": "sub"},
		}, a.headers)
		assert.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "issuer_store_config", body["code"])
	})
}

// TestTrustedIssuers_UniquenessRace pins that the per-issuer lock, not
// request timing, decides who trusts an issuer: two accounts adding the same
// issuer at once get exactly one row. They ask for different kinds, which no
// unique index separates, so only the lock can.
func TestTrustedIssuers_UniquenessRace(t *testing.T) {
	f := newDBFederation(t)
	tid := uid("race-tid")
	for round := 0; round < 10; round++ {
		tid := fmt.Sprintf("%s-%d", tid, round)
		var wg sync.WaitGroup
		statuses := make([]int, 2)
		for i := range statuses {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				tn := newTITenant(t)
				kind := []string{"person", "workload"}[i]
				statuses[i], _ = f.call(t, http.MethodPost, "/external-issuers", map[string]any{
					"kind": kind, "issuer": f.idp.EntraIssuer(tid),
					"audiences": []string{"a"}, "claim_mapping": map[string]string{"user_id": "oid"},
				}, tn.headers)
			}(i)
		}
		wg.Wait()
		assert.ElementsMatch(t, []int{http.StatusCreated, http.StatusConflict}, statuses, "round %d", round)
		n, err := testDB.NewSelect().Table("external_issuers").Where("issuer = ?", f.idp.EntraIssuer(tid)).Count(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 1, n)
	}
}

// ── P1c: Entra-shaped ID token ───────────────────────────────────────────────

type p1cFixture struct {
	f        *dbFederation
	tn       tiTenant
	tid      string
	rowID    string
	appID    string
	agent    tiAgent
	aliceOID string
}

func newP1C(t *testing.T) *p1cFixture {
	t.Helper()
	p := &p1cFixture{f: newDBFederation(t), tn: newTITenant(t), tid: uid("p1c-tid"), appID: uid("app"), aliceOID: uid("oid-alice")}
	// No row audiences: the agent's binding is the audience rule (D3a, D6),
	// so the app id is written once, as the binding's subject key.
	p.rowID = p.f.entraRow(t, p.tn, p.tid, nil)["id"].(string)
	p.agent = p.tn.agent(t)
	status, body := p.f.bind(t, p.tn, p.rowID, p.appID, p.agent.id, true)
	require.Equal(t, http.StatusCreated, status, "%v", body)
	p.f.member(p.f.idp.EntraIssuer(p.tid), p.aliceOID, "user_hf_alice")
	return p
}

func (p *p1cFixture) idToken(t *testing.T, profile string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{"aud": p.appID, "oid": p.aliceOID, "tid": p.tid}
	for k, v := range extra {
		claims[k] = v
	}
	tok, _, err := p.f.idp.Mint(mockidp.MintRequest{Profile: profile, Tenant: p.tid, Claims: claims})
	require.NoError(t, err)
	return tok
}

func (p *p1cFixture) exchange(t *testing.T, idToken string, extra map[string]any) tokenResponse {
	t.Helper()
	return postFederation(t, p.f.http.URL, merged(idTokenExchangeBody(idToken), clientCreds(t, p.appID, p.agent.key), extra))
}

func TestTrustedIssuers_P1C_EntraIDTokenEndToEnd(t *testing.T) {
	p := newP1C(t)
	const resource = "https://gateway.example/mcp/github"

	resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, nil), map[string]any{"resource": resource, "scope": "tools:read"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	claims := decodeIssuedTokenClaims(t, resp.AccessToken)

	assert.Equal(t, "user_hf_alice", claims["sub"], "sub is the person's Highflame user id (D5a)")
	assert.Equal(t, federationIssuer, claims["user_id_iss"], "sub's issuer is ZeroID's, as on authorization_code")
	assert.Equal(t, p.aliceOID, claims["user_idp_sub"], "the IdP subject (Entra oid) rides in user_idp_sub")
	assert.Equal(t, p.f.idp.EntraIssuer(p.tid), claims["user_idp_iss"], "with the IdP's issuer in user_idp_iss")
	assert.Equal(t, "user", claims["principal_type"])
	assert.Equal(t, p.tn.account, claims["account_id"], "account from the issuer row (D5)")
	assert.Equal(t, p.tn.project, claims["project_id"], "project from the bound agent (D5)")
	assert.Equal(t, p.appID, claims["client_id"])
	assert.Equal(t, []string{p.agent.wimse}, actChain(t, claims), "the bound agent is the current actor")
	assert.Equal(t, p.agent.extID, claims["act"].(map[string]any)["external_id"])
	assert.ElementsMatch(t, []any{resource}, claims["aud"], "audience-restricted to resource (ADR 0041 D4)")
	assert.ElementsMatch(t, []any{"tools:read"}, claims["scopes"])

	p.f.mu.Lock()
	seen := p.f.lastPerson
	p.f.mu.Unlock()
	assert.Equal(t, zeroid.PersonGrantExternalIDToken, seen.GrantType)
	assert.Equal(t, p.aliceOID, seen.Subject, "the user key is oid, not the pairwise sub")
	assert.True(t, seen.EmailVerified, "xms_edov marks the Entra email verified")
	assert.Equal(t, p.tn.account, seen.AccountID)
	assert.Equal(t, p.agent.id, seen.AgentIdentityID)

	t.Run("the agent exchanges the person token with its actor_token (RFC 8693)", func(t *testing.T) {
		ex := postFederation(t, p.f.http.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": resp.AccessToken,
			"actor_token":   actorAssertion(t, p.agent.key, p.agent.wimse),
			"scope":         "tools:read",
		})
		require.Equal(t, http.StatusOK, ex.StatusCode, "body=%s", ex.RawBody)
		child := decodeIssuedTokenClaims(t, ex.AccessToken)
		assert.Equal(t, "user_hf_alice", child["sub"], "the chain's principal is the person")
		assert.Equal(t, federationIssuer, child["user_id_iss"], "the chain keeps sub's issuer")
		assert.Equal(t, "user", child["principal_type"])
		assert.Equal(t, []string{p.agent.wimse}, actChain(t, child), "the same agent re-scoping adds no actor level")
		assert.Nil(t, child["delegation_depth"], "nor any delegation depth")
		assert.Equal(t, p.aliceOID, child["user_idp_sub"], "the principal's IdP pair travels with sub")
		assert.Equal(t, p.f.idp.EntraIssuer(p.tid), child["user_idp_iss"])
		assert.Equal(t, p.tn.account, child["account_id"])
	})
	t.Run("a different agent is a new actor and a new level", func(t *testing.T) {
		sub := p.tn.agent(t)
		ex := postFederation(t, p.f.http.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": resp.AccessToken,
			"actor_token":   actorAssertion(t, sub.key, sub.wimse),
			"scope":         "tools:read",
		})
		require.Equal(t, http.StatusOK, ex.StatusCode, "body=%s", ex.RawBody)
		child := decodeIssuedTokenClaims(t, ex.AccessToken)
		assert.Equal(t, []string{sub.wimse, p.agent.wimse}, actChain(t, child))
		assert.EqualValues(t, 1, child["delegation_depth"])
		assert.Equal(t, p.aliceOID, child["user_idp_sub"])
		assert.Equal(t, p.f.idp.EntraIssuer(p.tid), child["user_idp_iss"])
		assert.Equal(t, "user_hf_alice", child["sub"])
	})
}

// TestTrustedIssuers_ReScopeLegacyProfile: the legacy profile is frozen
// (ADR 0043 D1), so the same agent exchanging its person token delegates
// exactly as before, and the IdP pair is not stamped on a token whose sub
// is the agent.
func TestTrustedIssuers_ReScopeLegacyProfile(t *testing.T) {
	p := newP1B(t)
	resp := doRequest(t, http.MethodPut, adminPath("/tenant-settings"), map[string]any{"token_profile": "legacy"}, p.tn.headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	person := p.redeem(t, p.idJAG(t, nil), nil)
	require.Equal(t, http.StatusOK, person.StatusCode, "body=%s", person.RawBody)
	root := decodeIssuedTokenClaims(t, person.AccessToken)
	assert.Equal(t, "user_hf_alice", root["sub"])
	assert.Equal(t, p.aliceSub, root["user_idp_sub"], "a legacy person root carries the pair: its sub is the person")
	assert.NotContains(t, root, "principal_type")

	exchange := func(key *ecdsa.PrivateKey, wimse string) map[string]any {
		ex := postFederation(t, p.f.http.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": person.AccessToken,
			"actor_token":   actorAssertion(t, key, wimse),
			"scope":         "tools:read",
		})
		require.Equal(t, http.StatusOK, ex.StatusCode, "body=%s", ex.RawBody)
		return decodeIssuedTokenClaims(t, ex.AccessToken)
	}
	same := exchange(p.agent.key, p.agent.wimse)
	assert.EqualValues(t, 1, same["delegation_depth"], "legacy is unchanged: every exchange adds a level")
	assert.Equal(t, p.agent.wimse, same["sub"], "legacy puts the actor in sub")
	assert.Equal(t, map[string]any{"sub": "user_hf_alice"}, same["act"], "legacy act names the delegating parent's sub, as before")
	assert.NotContains(t, same, "user_idp_sub", "the IdP pair describes the person, not a legacy sub")
	assert.NotContains(t, same, "user_idp_iss")

	other := p.tn.agent(t)
	child := exchange(other.key, other.wimse)
	assert.EqualValues(t, 1, child["delegation_depth"], "a different agent is a delegation")
}

func TestTrustedIssuers_P1C_Refusals(t *testing.T) {
	p := newP1C(t)
	good := func() string { return p.idToken(t, mockidp.ProfileEntraIDToken, nil) }

	t.Run("an Entra app-only token (workload subject)", func(t *testing.T) {
		requireRefused(t, p.exchange(t, p.idToken(t, mockidp.ProfileEntraAppOnly, map[string]any{"oid": nil}), nil), "invalid_grant")
	})
	t.Run("a Kubernetes service-account subject from a person issuer", func(t *testing.T) {
		requireRefused(t, p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"oid": "system:serviceaccount:ns:sa"}), nil), "invalid_grant")
	})
	t.Run("a SPIFFE subject from a person issuer", func(t *testing.T) {
		requireRefused(t, p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"sub": "spiffe://corp/agent"}), nil), "invalid_grant")
	})
	t.Run("an access token presented as an ID token (scp)", func(t *testing.T) {
		requireRefused(t, p.exchange(t, p.idToken(t, mockidp.ProfileAccessTokenLookalike, nil), nil), "invalid_grant")
	})
	t.Run("an access token presented as an ID token (typ at+jwt)", func(t *testing.T) {
		typ := "at+jwt"
		tok, _, err := p.f.idp.Mint(mockidp.MintRequest{Profile: mockidp.ProfileEntraIDToken, Tenant: p.tid, HeaderTyp: &typ,
			Claims: map[string]any{"aud": p.appID, "oid": p.aliceOID}})
		require.NoError(t, err)
		requireRefused(t, p.exchange(t, tok, nil), "invalid_grant")
	})
	t.Run("an Entra access token without scp (azpacr marks it)", func(t *testing.T) {
		requireRefused(t, p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"azpacr": "2", "roles": []string{"Agent.Run"}}), nil), "invalid_grant")
	})
	t.Run("an ID-JAG presented as an ID token", func(t *testing.T) {
		typ := "oauth-id-jag+jwt"
		tok, _, err := p.f.idp.Mint(mockidp.MintRequest{Profile: mockidp.ProfileEntraIDToken, Tenant: p.tid, HeaderTyp: &typ,
			Claims: map[string]any{"aud": p.appID, "oid": p.aliceOID}})
		require.NoError(t, err)
		requireRefused(t, p.exchange(t, tok, nil), "invalid_grant")
	})
	t.Run("an ID token carrying the person's app roles is accepted", func(t *testing.T) {
		resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"roles": []string{"Approver"}}), nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	})
	t.Run("an ID token presented by a client that is not its audience", func(t *testing.T) {
		other := p.tn.agent(t)
		otherApp := uid("app-other")
		_, _ = p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, map[string]any{"audiences": []string{p.appID, otherApp}}, p.tn.headers)
		status, body := p.f.bind(t, p.tn, p.rowID, otherApp, other.id, true)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		resp := postFederation(t, p.f.http.URL, merged(idTokenExchangeBody(good()), clientCreds(t, otherApp, other.key)))
		requireRefused(t, resp, "invalid_grant")
	})
	t.Run("a relying party authenticating with a secret", func(t *testing.T) {
		secretRP := registerOAuthClient(t, uid("ti-secret"), nil)
		resp := postFederation(t, p.f.http.URL, merged(idTokenExchangeBody(p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"aud": secretRP.ClientID})),
			map[string]any{"client_id": secretRP.ClientID, "client_secret": secretRP.ClientSecret}))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		requireRefused(t, resp, "invalid_client")
	})
	t.Run("a person who is not a member of the account", func(t *testing.T) {
		requireRefused(t, p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"oid": uid("oid-stranger")}), nil), "invalid_grant")
	})
	t.Run("a mismatched account_id", func(t *testing.T) {
		requireRefused(t, p.exchange(t, good(), map[string]any{"account_id": "acct-evil"}), "invalid_grant")
	})
	t.Run("a mismatched project_id", func(t *testing.T) {
		requireRefused(t, p.exchange(t, good(), map[string]any{"account_id": p.tn.account, "project_id": "proj-evil"}), "invalid_grant")
	})
	t.Run("the derived tenant, sent explicitly, is accepted", func(t *testing.T) {
		resp := p.exchange(t, good(), map[string]any{"account_id": p.tn.account, "project_id": p.tn.project})
		assert.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	})
	t.Run("a presenting client with no binding is an unmatched agent, before its token is read", func(t *testing.T) {
		app := uid("app-unbound")
		rp := rpClient(t, app)
		resp := postFederation(t, p.f.http.URL, merged(idTokenExchangeBody(p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"aud": app})),
			clientCreds(t, app, rp.Key)))
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
	})
	t.Run("a disabled binding no longer admits its client", func(t *testing.T) {
		other := p.tn.agent(t)
		app := uid("app-disabled")
		status, body := p.f.bind(t, p.tn, p.rowID, app, other.id, true)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		exchange := func() tokenResponse {
			return postFederation(t, p.f.http.URL, merged(idTokenExchangeBody(p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"aud": app})),
				clientCreds(t, app, other.key)))
		}
		require.Equal(t, http.StatusOK, exchange().StatusCode, "bound and enabled")
		status, _ = p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID+"/bindings/"+body["id"].(string), map[string]any{"enabled": false}, p.tn.headers)
		require.Equal(t, http.StatusOK, status)
		resp := exchange()
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
	})
	t.Run("a presenting client with no binding", func(t *testing.T) {
		loneApp := uid("app-lone")
		_, _ = p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, map[string]any{"audiences": []string{p.appID, loneApp}}, p.tn.headers)
		lone := rpClient(t, loneApp)
		resp := postFederation(t, p.f.http.URL, merged(idTokenExchangeBody(p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"aud": loneApp})),
			clientCreds(t, loneApp, lone.Key)))
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
	})
	t.Run("an unadopted (discovered) agent", func(t *testing.T) {
		discovered := p.tn.discoveredAgent(t)
		app := uid("app-unadopted")
		_, _ = p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, map[string]any{"audiences": []string{p.appID, app}}, p.tn.headers)
		// The binding is created disabled (D6) until the deployer enables it at
		// adoption; the mint still names the state (D7).
		status, body := p.f.bind(t, p.tn, p.rowID, app, discovered, false)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		require.Equal(t, false, body["enabled"])
		key := keyClient(t, p.tn, app, discovered)
		resp := postFederation(t, p.f.http.URL, merged(idTokenExchangeBody(p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"aud": app})),
			clientCreds(t, app, key)))
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "discovered", "the refusal names the state")
	})
	t.Run("a token from a workload-kind issuer", func(t *testing.T) {
		status, body := p.f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "workload", "issuer": p.f.idp.K8sIssuer(), "audiences": []string{p.appID},
		}, p.tn.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		k8s := p.f.mint(t, mockidp.ProfileK8sServiceAccount, map[string]any{"aud": p.appID})
		resp := p.exchange(t, k8s, nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "issuer is not trusted for this grant", "one generic refusal")
	})
	t.Run("a disabled issuer, on every replica at the next request", func(t *testing.T) {
		_, replica := newDBFederationServer(t)
		status, _ := p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, map[string]any{"enabled": false}, p.tn.headers)
		require.Equal(t, http.StatusOK, status)
		requireRefused(t, p.exchange(t, good(), nil), "invalid_grant")
		requireRefused(t, postFederation(t, replica.URL, merged(idTokenExchangeBody(good()), clientCreds(t, p.appID, p.agent.key))), "invalid_grant")
		status, _ = p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, map[string]any{"enabled": true}, p.tn.headers)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, http.StatusOK, p.exchange(t, good(), nil).StatusCode, "re-enabled at the next request")
	})
	t.Run("another account registering the agent's app id as its own client cannot redeem", func(t *testing.T) {
		// A binds app Y but has not created its client yet; B registers a
		// private_key_jwt client named Y, unlinked or linked to B's agent,
		// and presents A's leaked ID token (aud = Y).
		appY := uid("app-y")
		status, body := p.f.bind(t, p.tn, p.rowID, appY, p.agent.id, false)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		b := newTITenant(t)
		leaked := p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"aud": appY})
		unlinked := keyClient(t, b, appY, "")
		resp := postFederation(t, p.f.http.URL, merged(idTokenExchangeBody(leaked), clientCreds(t, appY, unlinked)))
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "not registered to the agent")

		appZ := uid("app-z")
		status, body = p.f.bind(t, p.tn, p.rowID, appZ, p.agent.id, false)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		bAgent := b.agent(t)
		linkedToB := keyClient(t, b, appZ, bAgent.id)
		resp = postFederation(t, p.f.http.URL, merged(idTokenExchangeBody(p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"aud": appZ})),
			clientCreds(t, appZ, linkedToB)))
		requireRefused(t, resp, "invalid_grant")
	})
	t.Run("user_idp_sub cannot be supplied by the caller", func(t *testing.T) {
		resp := p.exchange(t, good(), map[string]any{"additional_claims": map[string]any{
			"user_idp_sub": "forged", "user_idp_iss": "forged", "user_id_iss": "forged"}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		claims := decodeIssuedTokenClaims(t, resp.AccessToken)
		assert.Equal(t, p.aliceOID, claims["user_idp_sub"])
		assert.Equal(t, p.f.idp.EntraIssuer(p.tid), claims["user_idp_iss"])
		assert.Equal(t, federationIssuer, claims["user_id_iss"])
	})
}

// TestTrustedIssuers_ResolverFailureFailsClosed: Admin unreachable means no
// token and nothing of the cause on the wire.
func TestTrustedIssuers_ResolverFailureFailsClosed(t *testing.T) {
	p := newP1C(t)
	p.f.srv.SetFederatedPersonResolver(func(context.Context, zeroid.FederatedPersonRequest) (string, error) {
		return "", errors.New("dial tcp admin:8040: connection refused")
	})
	resp := p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, nil), nil)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	requireRefused(t, resp, "server_error")
	assert.NotContains(t, resp.RawBody, "admin:8040")

	p.f.srv.SetFederatedPersonResolver(nil)
	resp = p.exchange(t, p.idToken(t, mockidp.ProfileEntraIDToken, nil), nil)
	requireRefused(t, resp, "server_error")
	assert.Contains(t, resp.RawBody, "not configured", "issuer rows require a person resolver")
}

// ── P1b: Okta-shaped ID-JAG ──────────────────────────────────────────────────

type p1bFixture struct {
	f        *dbFederation
	tn       tiTenant
	rowID    string
	clientID string
	agent    tiAgent
	aliceSub string
}

func newP1B(t *testing.T) *p1bFixture {
	t.Helper()
	p := &p1bFixture{f: newDBFederation(t), tn: newTITenant(t), clientID: uid("0oa"), aliceSub: uid("00u-alice")}
	p.rowID = p.f.oktaRow(t, p.tn)["id"].(string)
	p.agent = p.tn.agent(t)
	status, body := p.f.bind(t, p.tn, p.rowID, p.clientID, p.agent.id, true)
	require.Equal(t, http.StatusCreated, status, "%v", body)
	p.f.member(p.f.idp.OktaIssuer(), p.aliceSub, "user_hf_alice")
	return p
}

func (p *p1bFixture) idJAG(t *testing.T, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"aud": federationIssuer, "sub": p.aliceSub, "client_id": p.clientID,
		"act":      map[string]any{"sub": p.clientID, "sub_profile": "ai_agent"},
		"resource": "https://gateway.example/mcp/github", "scope": "tools:read", "jti": uid("jti"),
	}
	for k, v := range extra {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	return p.f.mint(t, mockidp.ProfileOktaIDJAG, claims)
}

func (p *p1bFixture) redeem(t *testing.T, assertion string, extra map[string]any) tokenResponse {
	t.Helper()
	return postFederation(t, p.f.http.URL, merged(map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":  assertion,
	}, clientCreds(t, p.clientID, p.agent.key), extra))
}

func TestTrustedIssuers_P1B_OktaIDJAGEndToEnd(t *testing.T) {
	p := newP1B(t)
	resp := p.redeem(t, p.idJAG(t, nil), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	claims := decodeIssuedTokenClaims(t, resp.AccessToken)
	assert.Equal(t, "user_hf_alice", claims["sub"])
	assert.Equal(t, federationIssuer, claims["user_id_iss"])
	assert.Equal(t, p.aliceSub, claims["user_idp_sub"])
	assert.Equal(t, p.f.idp.OktaIssuer(), claims["user_idp_iss"])
	assert.Equal(t, "user", claims["principal_type"])
	assert.Equal(t, p.tn.account, claims["account_id"])
	assert.Equal(t, p.tn.project, claims["project_id"])
	assert.Equal(t, []string{p.agent.wimse}, actChain(t, claims), "act.sub's bound agent is the current actor (zeroid#416)")
	assert.Equal(t, p.agent.extID, claims["act"].(map[string]any)["external_id"])
	assert.ElementsMatch(t, []any{"https://gateway.example/mcp/github"}, claims["aud"])
}

func TestTrustedIssuers_P1B_Refusals(t *testing.T) {
	p := newP1B(t)

	t.Run("a mismatched account_id is refused and does not burn the ID-JAG", func(t *testing.T) {
		jag := p.idJAG(t, nil)
		requireRefused(t, p.redeem(t, jag, map[string]any{"account_id": "acct-evil"}), "invalid_grant")
		assert.Equal(t, http.StatusOK, p.redeem(t, jag, nil).StatusCode, "the jti survived the refusal")
	})
	t.Run("an act.sub with no binding", func(t *testing.T) {
		resp := p.redeem(t, p.idJAG(t, map[string]any{"act": map[string]any{"sub": "0oaUNBOUND"}}), nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "no enabled binding")
	})
	t.Run("no act at all", func(t *testing.T) {
		requireRefused(t, p.redeem(t, p.idJAG(t, map[string]any{"act": nil}), nil), "invalid_grant")
	})
	t.Run("a discovered, unadopted agent", func(t *testing.T) {
		// Its own client, linked to no identity, so the binding alone decides.
		discovered := p.tn.discoveredAgent(t)
		key := uid("0oa-disc")
		status, body := p.f.bind(t, p.tn, p.rowID, key, discovered, false)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		require.Equal(t, false, body["enabled"], "created disabled; the mint still names the state (D7)")
		clientKey := keyClient(t, p.tn, key, discovered)
		resp := postFederation(t, p.f.http.URL, merged(map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":  p.idJAG(t, map[string]any{"client_id": key, "act": map[string]any{"sub": key}}),
		}, clientCreds(t, key, clientKey)))
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "discovered", "the refusal names the state")
	})
	t.Run("act.sub bound to an agent other than the client's", func(t *testing.T) {
		other := p.tn.agent(t)
		key := uid("0oa-other")
		status, body := p.f.bind(t, p.tn, p.rowID, key, other.id, false)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		requireRefused(t, p.redeem(t, p.idJAG(t, map[string]any{"act": map[string]any{"sub": key}}), nil), "invalid_grant")
	})
	t.Run("an application_id other than the bound agent", func(t *testing.T) {
		other := p.tn.agent(t)
		requireRefused(t, p.redeem(t, p.idJAG(t, nil), map[string]any{"application_id": other.id}), "invalid_grant")
	})
	t.Run("a workload subject (zeroid#415 on ID-JAG)", func(t *testing.T) {
		requireRefused(t, p.redeem(t, p.idJAG(t, map[string]any{"sub": "system:serviceaccount:ns:sa"}), nil), "invalid_grant")
		requireRefused(t, p.redeem(t, p.idJAG(t, map[string]any{"idtyp": "app"}), nil), "invalid_grant")
	})
	t.Run("a non-member", func(t *testing.T) {
		requireRefused(t, p.redeem(t, p.idJAG(t, map[string]any{"sub": uid("00u-stranger")}), nil), "invalid_grant")
	})
	t.Run("a workload-kind issuer", func(t *testing.T) {
		status, body := p.f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "workload", "issuer": p.f.idp.K8sIssuer(), "audiences": []string{federationIssuer},
		}, p.tn.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		typ := "oauth-id-jag+jwt"
		tok, _, err := p.f.idp.Mint(mockidp.MintRequest{Profile: mockidp.ProfileK8sServiceAccount, HeaderTyp: &typ, Claims: map[string]any{
			"aud": federationIssuer, "client_id": p.clientID, "act": map[string]any{"sub": p.clientID},
			"resource": "https://gateway.example/mcp/github", "jti": uid("jti"),
		}})
		require.NoError(t, err)
		requireRefused(t, p.redeem(t, tok, nil), "invalid_grant")
	})
	t.Run("a disabled issuer", func(t *testing.T) {
		status, _ := p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, map[string]any{"enabled": false}, p.tn.headers)
		require.Equal(t, http.StatusOK, status)
		defer p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, map[string]any{"enabled": true}, p.tn.headers)
		requireRefused(t, p.redeem(t, p.idJAG(t, nil), nil), "invalid_grant")
	})
	t.Run("an ID-JAG not addressed to an audience of the row", func(t *testing.T) {
		requireRefused(t, p.redeem(t, p.idJAG(t, map[string]any{"aud": "https://someone-else.example"}), nil), "invalid_grant")
	})
	t.Run("an ID-JAG addressed to an agent's app id, not to ZeroID", func(t *testing.T) {
		status, _ := p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID,
			map[string]any{"audiences": []string{federationIssuer, "app-for-p1c"}}, p.tn.headers)
		require.Equal(t, http.StatusOK, status)
		resp := p.redeem(t, p.idJAG(t, map[string]any{"aud": "app-for-p1c"}), nil)
		requireRefused(t, resp, "invalid_grant")
		assert.Contains(t, resp.RawBody, "not addressed to this authorization server")
	})
}

// TestTrustedIssuers_NonMemberDoesNotBurnIDJAG pins the pre-burn position of
// person resolution: a refused person leaves the ID-JAG redeemable once they
// become a member.
func TestTrustedIssuers_NonMemberDoesNotBurnIDJAG(t *testing.T) {
	p := newP1B(t)
	bob := uid("00u-bob")
	jag := p.idJAG(t, map[string]any{"sub": bob})
	requireRefused(t, p.redeem(t, jag, nil), "invalid_grant")
	p.f.member(p.f.idp.OktaIssuer(), bob, "user_hf_bob")
	resp := p.redeem(t, jag, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	assert.Equal(t, "user_hf_bob", decodeIssuedTokenClaims(t, resp.AccessToken)["sub"])
	requireRefused(t, p.redeem(t, jag, nil), "invalid_grant")
	assert.True(t, strings.Contains(p.redeem(t, jag, nil).RawBody, "already been redeemed"))
}

// TestTrustedIssuers_BindingsByIdentity: one query answers "which bindings
// does this agent have" across every issuer of the account.
func TestTrustedIssuers_BindingsByIdentity(t *testing.T) {
	f := newDBFederation(t)
	a, b := newTITenant(t), newTITenant(t)
	entra := f.entraRow(t, a, uid("bbi-tid"), nil)["id"].(string)
	okta := f.oktaRow(t, a)["id"].(string)
	agent, other := a.agent(t), a.agent(t)
	for _, bind := range []struct{ row, key, id string }{
		{entra, uid("app"), agent.id}, {okta, uid("0oa"), agent.id}, {entra, uid("app"), other.id},
	} {
		status, body := f.bind(t, a, bind.row, bind.key, bind.id, false)
		require.Equal(t, http.StatusCreated, status, "%v", body)
	}
	identities := func(list map[string]any) []string {
		var out []string
		for _, it := range list["items"].([]any) {
			out = append(out, it.(map[string]any)["identity_id"].(string))
		}
		return out
	}

	status, list := f.call(t, http.MethodGet, "/external-issuers/bindings?identity_id="+agent.id, nil, a.headers)
	require.Equal(t, http.StatusOK, status, "%v", list)
	assert.Equal(t, []string{agent.id, agent.id}, identities(list), "both issuers' bindings for the agent")

	status, list = f.call(t, http.MethodGet, "/external-issuers/bindings", nil, a.headers)
	require.Equal(t, http.StatusOK, status)
	assert.Len(t, list["items"], 3, "no filter: every binding of the account")

	status, list = f.call(t, http.MethodGet, "/external-issuers/"+entra+"/bindings?identity_id="+other.id, nil, a.headers)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, []string{other.id}, identities(list), "per-issuer list takes the same filter")

	status, list = f.call(t, http.MethodGet, "/external-issuers/bindings?identity_id="+agent.id, nil, b.headers)
	require.Equal(t, http.StatusOK, status)
	assert.Empty(t, list["items"], "another account sees none")

	status, body := f.call(t, http.MethodGet, "/external-issuers/bindings?identity_id=not-a-uuid", nil, a.headers)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_identity_id", body["code"])
}

// sharedTenant is the mock Entra tenant configured as a shared issuer.
const sharedTenant = "99999999-0000-0000-0000-000000000000"

// TestTrustedIssuers_SharedIssuerOverlap: on a shared issuer, a second
// account cannot add constraints that a token matching the first account's
// row could also satisfy, which would make every such grant ambiguous.
func TestTrustedIssuers_SharedIssuerOverlap(t *testing.T) {
	f := newDBFederation(t)
	a, b := newTITenant(t), newTITenant(t)
	create := func(tn tiTenant, c map[string][]string) (int, map[string]any) {
		return f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": f.idp.EntraIssuer(sharedTenant),
			"claim_mapping": map[string]string{"user_id": "oid"}, "claim_constraints": c,
		}, tn.headers)
	}
	status, body := create(a, map[string][]string{"hd": {"acme.com"}})
	require.Equal(t, http.StatusCreated, status, "%v", body)
	for name, c := range map[string]map[string][]string{
		"the same set":                    {"hd": {"acme.com"}},
		"a superset shadowing A's tokens": {"hd": {"acme.com"}, "email_verified": {"true"}},
		"a constraint on another claim":   {"tid": {"t1"}},
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			status, body := create(b, c)
			assert.Equal(t, http.StatusConflict, status, "%v", body)
			assert.Equal(t, "issuer_already_trusted", body["code"])
		})
	}
	t.Run("a pin on a claim every token carries is refused", func(t *testing.T) {
		status, body := create(b, map[string][]string{"hd": {"beta.com"}, "aud": {federationIssuer}})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_claim_constraints", body["code"])
	})
	t.Run("a disjoint pin is allowed", func(t *testing.T) {
		status, body := create(b, map[string][]string{"hd": {"beta.com"}})
		assert.Equal(t, http.StatusCreated, status, "%v", body)
	})
}

// TestTrustedIssuers_TrailingSlashIsOneIssuer: "https://x/" and "https://x"
// are one issuer for ownership.
func TestTrustedIssuers_TrailingSlashIsOneIssuer(t *testing.T) {
	f := newDBFederation(t)
	a, b := newTITenant(t), newTITenant(t)
	tid := uid("slash-tid")
	f.entraRow(t, a, tid, nil)
	status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
		"kind": "person", "issuer": f.idp.EntraIssuer(tid) + "/",
		"claim_mapping": map[string]string{"user_id": "oid"},
	}, b.headers)
	assert.Equal(t, http.StatusConflict, status, "%v", body)
	assert.Equal(t, "issuer_already_trusted", body["code"])
}

// TestTrustedIssuers_AccountCapUnderConcurrency: concurrent creates of
// different issuers in one account never exceed the cap.
func TestTrustedIssuers_AccountCapUnderConcurrency(t *testing.T) {
	f := newDBFederation(t)
	tn := newTITenant(t)
	for i := 0; i < 18; i++ {
		f.entraRow(t, tn, uid("cap-tid"), nil)
	}
	var wg sync.WaitGroup
	statuses := make([]int, 6)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tid := uid("cap-race")
			statuses[i], _ = f.call(t, http.MethodPost, "/external-issuers", map[string]any{
				"kind": "person", "issuer": f.idp.EntraIssuer(tid),
				"claim_mapping": map[string]string{"user_id": "oid"},
			}, tn.headers)
		}(i)
	}
	wg.Wait()
	created := 0
	for _, st := range statuses {
		if st == http.StatusCreated {
			created++
		}
	}
	assert.Equal(t, 2, created, "statuses %v", statuses)
	n, err := testDB.NewSelect().Table("external_issuers").Where("account_id = ?", tn.account).Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 20, n)
}

// TestTrustedIssuers_KeysComeFromDiscovery is the forge attack: an admin
// cannot point a trusted issuer at a key set of their own, at create or
// later, so they cannot sign tokens their IdP's issuer would name.
func TestTrustedIssuers_KeysComeFromDiscovery(t *testing.T) {
	f := newDBFederation(t)
	tn := newTITenant(t)

	t.Run("jwks_uri is not accepted at create", func(t *testing.T) {
		status, _ := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": f.idp.OktaIssuer(), "jwks_uri": "https://attacker.example/keys",
			"claim_mapping": map[string]string{"user_id": "sub"},
		}, tn.headers)
		assert.Equal(t, http.StatusUnprocessableEntity, status, "an unknown field")
	})
	row := f.oktaRow(t, tn)
	id := row["id"].(string)
	assert.Equal(t, f.idp.OktaJWKSURI(), row["jwks_uri"], "the key set the issuer's discovery names")

	t.Run("jwks_uri is not patchable", func(t *testing.T) {
		status, _ := f.call(t, http.MethodPatch, "/external-issuers/"+id, map[string]any{"jwks_uri": "https://attacker.example/keys"}, tn.headers)
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		_, got := f.call(t, http.MethodGet, "/external-issuers/"+id, nil, tn.headers)
		assert.Equal(t, f.idp.OktaJWKSURI(), got["jwks_uri"])
	})
	t.Run("refresh re-reads discovery", func(t *testing.T) {
		status, got := f.call(t, http.MethodPost, "/external-issuers/"+id+"/refresh", nil, tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", got)
		assert.Equal(t, f.idp.OktaJWKSURI(), got["jwks_uri"])
		assert.Equal(t, true, got["jwks_check"].(map[string]any)["reachable"])
	})
	t.Run("a discovery document naming another issuer is refused", func(t *testing.T) {
		liar := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.idp.OktaIssuer(), "jwks_uri": f.idp.OktaJWKSURI()})
		}))
		defer liar.Close()
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": liar.URL, "claim_mapping": map[string]string{"user_id": "sub"},
		}, newTITenant(t).headers)
		assert.Equal(t, http.StatusUnprocessableEntity, status, "%v", body)
		assert.Equal(t, "discovery_issuer_mismatch", body["code"])
	})
}
