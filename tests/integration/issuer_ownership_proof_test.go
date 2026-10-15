package integration_test

// Issuer ownership proof (ADR 0042 open question 8, person issuers): the two
// routes a deployer builds the owner's test sign-in on. GET
// /external-issuers/{id}/discovery hands back the sign-in endpoints; POST
// /external-issuers/{id}/verify-id-token verifies the resulting ID token
// under the row the way the ID-token exchange (P1c) does, plus the nonce.
// Contract: docs/external-issuers.md.

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/internal/mockidp"
)

func TestTrustedIssuers_OwnershipProof_Discovery(t *testing.T) {
	f := newDBFederation(t)
	a, b := newTITenant(t), newTITenant(t)
	tid := uid("proof-tid")
	entraID := f.entraRow(t, a, tid, nil)["id"].(string)
	oktaID := f.oktaRow(t, a)["id"].(string)

	t.Run("an Entra row's sign-in endpoints", func(t *testing.T) {
		status, body := f.call(t, http.MethodGet, "/external-issuers/"+entraID+"/discovery", nil, a.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		delete(body, "$schema") // huma's link on every body
		assert.Equal(t, map[string]any{
			"issuer":                 f.idp.EntraIssuer(tid),
			"authorization_endpoint": f.idpSrv.URL + "/entra/" + tid + "/oauth2/v2.0/authorize",
			"token_endpoint":         f.idpSrv.URL + "/entra/" + tid + "/oauth2/v2.0/token",
		}, body)
	})
	t.Run("an Okta row's sign-in endpoints", func(t *testing.T) {
		status, body := f.call(t, http.MethodGet, "/external-issuers/"+oktaID+"/discovery", nil, a.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, f.idp.OktaIssuer()+"/oauth2/v1/authorize", body["authorization_endpoint"])
		assert.Equal(t, f.idp.OktaIssuer()+"/oauth2/v1/token", body["token_endpoint"])
	})
	t.Run("a workload row is wrong_kind", func(t *testing.T) {
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "workload", "issuer": f.idp.EntraIssuer(tid), "audiences": []string{federationIssuer},
		}, a.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		status, body = f.call(t, http.MethodGet, "/external-issuers/"+body["id"].(string)+"/discovery", nil, a.headers)
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		assert.Equal(t, "wrong_kind", body["code"])
	})
	t.Run("a Kubernetes issuer names no sign-in endpoints", func(t *testing.T) {
		status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "person", "issuer": f.idp.K8sIssuer(), "claim_mapping": map[string]string{"user_id": "sub"},
		}, a.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		status, body = f.call(t, http.MethodGet, "/external-issuers/"+body["id"].(string)+"/discovery", nil, a.headers)
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		assert.Equal(t, "discovery_invalid", body["code"])
	})
	t.Run("another account's row is not found", func(t *testing.T) {
		status, body := f.call(t, http.MethodGet, "/external-issuers/"+entraID+"/discovery", nil, b.headers)
		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "not_found", body["code"])
		status, _ = f.call(t, http.MethodGet, "/external-issuers/not-a-uuid/discovery", nil, a.headers)
		assert.Equal(t, http.StatusNotFound, status)
	})
}

// proofFixture is an Entra-shaped person row with no binding: the
// verification app is not an agent.
type proofFixture struct {
	f     *dbFederation
	tn    tiTenant
	tid   string
	rowID string
	app   string
	nonce string
}

func newProof(t *testing.T) *proofFixture {
	t.Helper()
	p := &proofFixture{f: newDBFederation(t), tn: newTITenant(t), tid: uid("proof-tid"), app: uid("verify-app"), nonce: uid("nonce")}
	p.rowID = p.f.entraRow(t, p.tn, p.tid, nil)["id"].(string)
	return p
}

func (p *proofFixture) idToken(t *testing.T, profile string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{"aud": p.app, "tid": p.tid, "nonce": p.nonce, "oid": "oid-owner", "email": "owner@contoso.example"}
	for k, v := range extra {
		claims[k] = v
	}
	tok, _, err := p.f.idp.Mint(mockidp.MintRequest{Profile: profile, Tenant: p.tid, Claims: claims})
	require.NoError(t, err)
	return tok
}

func (p *proofFixture) verify(t *testing.T, tn tiTenant, rowID string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return p.f.call(t, http.MethodPost, "/external-issuers/"+rowID+"/verify-id-token", body, tn.headers)
}

func (p *proofFixture) body(tok string) map[string]any {
	return map[string]any{"id_token": tok, "client_id": p.app, "nonce": p.nonce}
}

func TestTrustedIssuers_OwnershipProof_VerifyIDToken(t *testing.T) {
	p := newProof(t)

	t.Run("an owner's sign-in is verified, with no binding", func(t *testing.T) {
		tok := p.idToken(t, mockidp.ProfileEntraIDToken, nil)
		status, body := p.verify(t, p.tn, p.rowID, p.body(tok))
		require.Equal(t, http.StatusOK, status, "%v", body)
		delete(body, "$schema") // huma's link on every body
		assert.Equal(t, map[string]any{
			"issuer_id":      p.rowID,
			"issuer":         p.f.idp.EntraIssuer(p.tid),
			"subject":        "oid-owner",
			"email":          "owner@contoso.example",
			"email_verified": true,
		}, body, "subject is the mapped user key (oid), email_verified is xms_edov")

		status, _ = p.verify(t, p.tn, p.rowID, p.body(tok))
		assert.Equal(t, http.StatusOK, status, "verification only reads the token: no jti is recorded")
	})
	t.Run("email_verified follows xms_edov, not email_verified", func(t *testing.T) {
		tok := p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"xms_edov": false, "email_verified": true})
		status, body := p.verify(t, p.tn, p.rowID, p.body(tok))
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, false, body["email_verified"])
	})

	old := time.Now().Add(-2 * time.Hour).Unix()
	refusals := []struct {
		name string
		tok  func() string
		body func(string) map[string]any
		code string
	}{
		{name: "no nonce", tok: func() string { return p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"nonce": nil}) }, code: "nonce_mismatch"},
		{name: "another nonce", tok: func() string {
			return p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"nonce": "replayed-" + p.nonce})
		}, code: "nonce_mismatch"},
		{name: "another nonce asked for", tok: func() string { return p.idToken(t, mockidp.ProfileEntraIDToken, nil) },
			body: func(tok string) map[string]any {
				return map[string]any{"id_token": tok, "client_id": p.app, "nonce": "other"}
			}, code: "nonce_mismatch"},
		{name: "wrong aud", tok: func() string { return p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"aud": "another-app"}) }, code: "audience_mismatch"},
		{name: "another client_id asked for", tok: func() string { return p.idToken(t, mockidp.ProfileEntraIDToken, nil) },
			body: func(tok string) map[string]any {
				return map[string]any{"id_token": tok, "client_id": "another-app", "nonce": p.nonce}
			}, code: "audience_mismatch"},
		{name: "azp names another party", tok: func() string { return p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"azp": "another-app"}) }, code: "audience_mismatch"},
		{name: "expired", tok: func() string {
			return p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"iat": old, "nbf": old, "exp": old + 600})
		}, code: "token_invalid"},
		{name: "another tenant's token", tok: func() string { return p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"tid": "other-tenant"}) }, code: "constraint_mismatch"},
		{name: "an access token", tok: func() string { return p.idToken(t, mockidp.ProfileAccessTokenLookalike, nil) }, code: "token_invalid"},
		{name: "an app-only token", tok: func() string { return p.idToken(t, mockidp.ProfileEntraAppOnly, nil) }, code: "token_invalid"},
		{name: "another issuer's token (an unknown key)", tok: func() string {
			tok, _, err := p.f.idp.Mint(mockidp.MintRequest{Profile: mockidp.ProfileOktaIDJAG, Claims: map[string]any{"aud": p.app, "nonce": p.nonce},
				HeaderTyp: new(string)})
			require.NoError(t, err)
			return tok
		}, code: "token_invalid"},
		{name: "signed by a key the issuer never published (unknown kid)", tok: func() string {
			return signUnpublishedRS256(t, "never-published", p.f.idp.EntraIssuer(p.tid), p.tid, p.app, p.nonce)
		}, code: "token_invalid"},
		{name: "signed by a key the issuer never published (the published kid)", tok: func() string {
			return signUnpublishedRS256(t, "entra-mock-key", p.f.idp.EntraIssuer(p.tid), p.tid, p.app, p.nonce)
		}, code: "token_invalid"},
		{name: "malformed", tok: func() string { return "eyJhbGciOiJSUzI1NiJ9.e30.c2ln" }, code: "token_invalid"},
	}
	for _, tc := range refusals {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			tok := tc.tok()
			body := p.body(tok)
			if tc.body != nil {
				body = tc.body(tok)
			}
			status, out := p.verify(t, p.tn, p.rowID, body)
			assert.Equal(t, http.StatusUnprocessableEntity, status, "%v", out)
			assert.Equal(t, tc.code, out["code"])
			for _, v := range out {
				s, _ := v.(string)
				assert.False(t, s != "" && (strings.Contains(s, tok) || strings.Contains(s, "owner@contoso.example") || strings.Contains(s, "oid-owner")),
					"a refusal never echoes the token or its claims: %v", out)
			}
		})
	}

	t.Run("a disabled row", func(t *testing.T) {
		status, body := p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, map[string]any{"enabled": false}, p.tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		defer func() {
			status, body := p.f.call(t, http.MethodPatch, "/external-issuers/"+p.rowID, map[string]any{"enabled": true}, p.tn.headers)
			require.Equal(t, http.StatusOK, status, "%v", body)
		}()
		status, body = p.verify(t, p.tn, p.rowID, p.body(p.idToken(t, mockidp.ProfileEntraIDToken, nil)))
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		assert.Equal(t, "issuer_disabled", body["code"])
	})
	t.Run("a workload row", func(t *testing.T) {
		status, body := p.f.call(t, http.MethodPost, "/external-issuers", map[string]any{
			"kind": "workload", "issuer": p.f.idp.EntraIssuer(p.tid), "audiences": []string{p.app},
		}, p.tn.headers)
		require.Equal(t, http.StatusCreated, status, "%v", body)
		status, body = p.verify(t, p.tn, body["id"].(string), p.body(p.idToken(t, mockidp.ProfileEntraIDToken, nil)))
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		assert.Equal(t, "wrong_kind", body["code"])
	})
	t.Run("another account's row is not found", func(t *testing.T) {
		status, body := p.verify(t, newTITenant(t), p.rowID, p.body(p.idToken(t, mockidp.ProfileEntraIDToken, nil)))
		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "not_found", body["code"])
	})
	t.Run("every field is required and capped", func(t *testing.T) {
		tok := p.idToken(t, mockidp.ProfileEntraIDToken, nil)
		for name, body := range map[string]map[string]any{
			"empty id_token":      {"id_token": "", "client_id": p.app, "nonce": p.nonce},
			"empty client_id":     {"id_token": tok, "client_id": "", "nonce": p.nonce},
			"empty nonce":         {"id_token": tok, "client_id": p.app, "nonce": ""},
			"oversized id_token":  {"id_token": strings.Repeat("a", 16<<10+1), "client_id": p.app, "nonce": p.nonce},
			"oversized nonce":     {"id_token": tok, "client_id": p.app, "nonce": strings.Repeat("n", 513)},
			"oversized client_id": {"id_token": tok, "client_id": strings.Repeat("c", 513), "nonce": p.nonce},
		} {
			status, out := p.verify(t, p.tn, p.rowID, body)
			assert.Equal(t, http.StatusBadRequest, status, name)
			assert.Equal(t, "invalid_request", out["code"], name)
		}
		status, _ := p.verify(t, p.tn, p.rowID, map[string]any{"id_token": tok, "client_id": p.app})
		assert.Equal(t, http.StatusUnprocessableEntity, status, "a missing field is a schema refusal")
		status, _ = p.verify(t, p.tn, p.rowID, map[string]any{"id_token": tok, "client_id": p.app, "nonce": p.nonce, "binding": "x"})
		assert.Equal(t, http.StatusUnprocessableEntity, status, "an unknown field is a schema refusal")
	})
}

// TestTrustedIssuers_OwnershipProof_SameChecksAsP1C: a token the ID-token
// exchange accepts verifies under the row, and verifying it does not stop
// the exchange accepting it.
func TestTrustedIssuers_OwnershipProof_SameChecksAsP1C(t *testing.T) {
	p := newP1C(t)
	nonce := uid("nonce")
	tok := p.idToken(t, mockidp.ProfileEntraIDToken, map[string]any{"nonce": nonce})

	status, body := p.f.call(t, http.MethodPost, "/external-issuers/"+p.rowID+"/verify-id-token",
		map[string]any{"id_token": tok, "client_id": p.appID, "nonce": nonce}, p.tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, p.aliceOID, body["subject"], "the same user key the exchange hands the person resolver")

	resp := p.exchange(t, tok, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)

	// An access-token look-alike the exchange refuses is refused here too.
	at := p.idToken(t, mockidp.ProfileAccessTokenLookalike, map[string]any{"nonce": nonce})
	requireRefused(t, p.exchange(t, at, nil), "invalid_grant")
	status, body = p.f.call(t, http.MethodPost, "/external-issuers/"+p.rowID+"/verify-id-token",
		map[string]any{"id_token": at, "client_id": p.appID, "nonce": nonce}, p.tn.headers)
	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "token_invalid", body["code"])
}

// signUnpublishedRS256 signs an otherwise valid Entra-shaped ID token with a
// fresh RSA key no JWKS publishes, under kid.
func signUnpublishedRS256(t *testing.T, kid, iss, tid, aud, nonce string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	tok := jwt.New()
	for k, v := range map[string]any{
		"iss": iss, "sub": "pairwise", "oid": "oid-owner", "tid": tid, "aud": aud, "nonce": nonce,
		"email": "owner@contoso.example", "xms_edov": true, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	} {
		require.NoError(t, tok.Set(k, v))
	}
	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, kid))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)
	return string(signed)
}
