package authjwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/pkg/authjwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// testKeySet holds both key pairs and serves a JWKS endpoint for tests.
type testKeySet struct {
	ecPriv  *ecdsa.PrivateKey
	rsaPriv *rsa.PrivateKey
	set     jwk.Set
	server  *httptest.Server
}

func newTestKeySet(t *testing.T) *testKeySet {
	t.Helper()

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	set := jwk.NewSet()

	ecPub, err := jwk.FromRaw(ecPriv.Public())
	if err != nil {
		t.Fatalf("create EC JWK: %v", err)
	}
	_ = ecPub.Set(jwk.KeyIDKey, "ec-key-1")
	_ = ecPub.Set(jwk.AlgorithmKey, jwa.ES256)
	_ = ecPub.Set(jwk.KeyUsageKey, "sig")
	_ = set.AddKey(ecPub)

	rsaPub, err := jwk.FromRaw(rsaPriv.Public())
	if err != nil {
		t.Fatalf("create RSA JWK: %v", err)
	}
	_ = rsaPub.Set(jwk.KeyIDKey, "rsa-key-1")
	_ = rsaPub.Set(jwk.AlgorithmKey, jwa.RS256)
	_ = rsaPub.Set(jwk.KeyUsageKey, "sig")
	_ = set.AddKey(rsaPub)

	ts := &testKeySet{ecPriv: ecPriv, rsaPriv: rsaPriv, set: set}
	ts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ts.set)
	}))
	t.Cleanup(ts.server.Close)

	return ts
}

func makeHeaders(kid string) jws.Headers {
	h := jws.NewHeaders()
	_ = h.Set(jws.KeyIDKey, kid)
	return h
}

func (ks *testKeySet) signES256(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	token := jwt.New()
	for k, v := range claims {
		_ = token.Set(k, v)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, ks.ecPriv, jws.WithProtectedHeaders(makeHeaders("ec-key-1"))))
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}
	return string(signed)
}

func (ks *testKeySet) signRS256(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	token := jwt.New()
	for k, v := range claims {
		_ = token.Set(k, v)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, ks.rsaPriv, jws.WithProtectedHeaders(makeHeaders("rsa-key-1"))))
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	return string(signed)
}

func baseClaims(issuer string) map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"iss":        issuer,
		"sub":        "user-123",
		"aud":        []string{"https://shield.example.com"},
		"iat":        now.Unix(),
		"exp":        now.Add(1 * time.Hour).Unix(),
		"jti":        "jti-abc",
		"account_id": "acc-001",
		"project_id": "proj-001",
		"grant_type": "api_key",
	}
}

func agentClaims(issuer string) map[string]interface{} {
	c := baseClaims(issuer)
	c["external_id"] = "agent-smith"
	c["identity_type"] = "agent"
	c["sub_type"] = "orchestrator"
	c["trust_level"] = "verified_third_party"
	c["grant_type"] = "client_credentials"
	c["framework"] = "langchain"
	c["publisher"] = "acme-corp"
	c["capabilities"] = []string{"read_file", "call_tool"}
	c["delegation_depth"] = 1
	c["act"] = map[string]interface{}{
		"sub": "orchestrator-1",
		"iss": issuer,
	}
	return c
}

func newVerifier(t *testing.T, ks *testKeySet, issuer string) *authjwt.Verifier {
	t.Helper()
	v, err := authjwt.NewVerifier(authjwt.VerifierConfig{
		JWKSURL: ks.server.URL,
		Issuer:  issuer,
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	t.Cleanup(v.Close)
	return v
}

func TestVerifyRS256Token(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	token := ks.signRS256(t, baseClaims(issuer))
	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify RS256: %v", err)
	}

	assertEqual(t, "AccountID", claims.AccountID, "acc-001")
	assertEqual(t, "ProjectID", claims.ProjectID, "proj-001")
	assertEqual(t, "Subject", claims.Subject, "user-123")
	assertEqual(t, "GrantType", claims.GrantType, "api_key")
	assertEqual(t, "Issuer", claims.Issuer, issuer)
	assertEqual(t, "JWTID", claims.JWTID, "jti-abc")
}

func TestVerifyES256Token(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	token := ks.signES256(t, agentClaims(issuer))
	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify ES256: %v", err)
	}

	assertEqual(t, "ExternalID", claims.ExternalID, "agent-smith")
	assertEqual(t, "IdentityType", claims.IdentityType, "agent")
	assertEqual(t, "SubType", claims.SubType, "orchestrator")
	assertEqual(t, "TrustLevel", claims.TrustLevel, "verified_third_party")
	assertEqual(t, "Framework", claims.Framework, "langchain")
	assertEqual(t, "Publisher", claims.Publisher, "acme-corp")

	if claims.DelegationDepth != 1 {
		t.Errorf("DelegationDepth = %d, want %d", claims.DelegationDepth, 1)
	}
	if claims.ActorClaims == nil {
		t.Fatal("ActorClaims is nil")
	}
	assertEqual(t, "ActorClaims.Subject", claims.ActorClaims.Subject, "orchestrator-1")

	if len(claims.Capabilities) != 2 {
		t.Fatalf("Capabilities = %v, want 2 items", claims.Capabilities)
	}
	assertEqual(t, "Capabilities[0]", claims.Capabilities[0], "read_file")
	assertEqual(t, "Capabilities[1]", claims.Capabilities[1], "call_tool")
}

func TestCustomClaims(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	c := baseClaims(issuer)
	c["application_id"] = "app-xyz"
	c["gateway_id"] = "gw-123"
	c["product"] = "guardrails"
	c["user_email"] = "test@example.com"

	token := ks.signRS256(t, c)
	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	// These should be in Custom, not typed fields.
	assertEqual(t, "Custom application_id", claims.GetCustomString("application_id"), "app-xyz")
	assertEqual(t, "Custom gateway_id", claims.GetCustomString("gateway_id"), "gw-123")
	assertEqual(t, "Custom product", claims.GetCustomString("product"), "guardrails")
	assertEqual(t, "Custom user_email", claims.GetCustomString("user_email"), "test@example.com")

	// Typed fields should still work.
	assertEqual(t, "AccountID", claims.AccountID, "acc-001")
}

func TestVerifyExpiredToken(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	c := baseClaims(issuer)
	c["exp"] = time.Now().Add(-1 * time.Hour).Unix()

	token := ks.signRS256(t, c)
	_, err := v.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyWrongIssuer(t *testing.T) {
	ks := newTestKeySet(t)
	v := newVerifier(t, ks, "https://auth.legit.com")

	token := ks.signRS256(t, baseClaims("https://auth.evil.com"))
	_, err := v.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestVerifyEmptyToken(t *testing.T) {
	ks := newTestKeySet(t)
	v := newVerifier(t, ks, "")

	_, err := v.Verify(context.Background(), "")
	if err != authjwt.ErrNoToken {
		t.Errorf("expected ErrNoToken, got: %v", err)
	}
}

func TestVerifyGarbageToken(t *testing.T) {
	ks := newTestKeySet(t)
	v := newVerifier(t, ks, "")

	_, err := v.Verify(context.Background(), "not.a.jwt")
	if err == nil {
		t.Fatal("expected error for garbage token")
	}
}

func TestMiddleware(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	mw := authjwt.Middleware(authjwt.MiddlewareConfig{
		Verifier:    v,
		ExemptPaths: []string{"/health", "/.well-known/"},
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := authjwt.ClaimsFromContext(r.Context())
		if claims != nil {
			w.Write([]byte(claims.AccountID))
		} else {
			w.Write([]byte("no-claims"))
		}
	}))

	t.Run("valid token", func(t *testing.T) {
		token := ks.signRS256(t, baseClaims(issuer))
		req := httptest.NewRequest("GET", "/v1/guard", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assertStatus(t, rec, 200)
		assertEqual(t, "body", rec.Body.String(), "acc-001")
	})

	t.Run("missing token returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/guard", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assertStatus(t, rec, 401)
	})

	t.Run("exempt path /health bypasses auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assertStatus(t, rec, 200)
		assertEqual(t, "body", rec.Body.String(), "no-claims")
	})

	t.Run("exempt path /.well-known/ bypasses auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assertStatus(t, rec, 200)
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/guard", nil)
		req.Header.Set("Authorization", "Bearer garbage.token.here")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assertStatus(t, rec, 401)
	})

	t.Run("expired token returns 401", func(t *testing.T) {
		c := baseClaims(issuer)
		c["exp"] = time.Now().Add(-1 * time.Hour).Unix()
		token := ks.signRS256(t, c)
		req := httptest.NewRequest("GET", "/v1/guard", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assertStatus(t, rec, 401)
	})
}

func TestMiddlewareAllowUnauthenticated(t *testing.T) {
	ks := newTestKeySet(t)
	v := newVerifier(t, ks, "")

	mw := authjwt.Middleware(authjwt.MiddlewareConfig{
		Verifier:             v,
		AllowUnauthenticated: true,
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := authjwt.ClaimsFromContext(r.Context())
		if claims != nil {
			w.Write([]byte("authenticated"))
		} else {
			w.Write([]byte("anonymous"))
		}
	}))

	t.Run("no token passes through", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/detect", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assertStatus(t, rec, 200)
		assertEqual(t, "body", rec.Body.String(), "anonymous")
	})

	t.Run("invalid token still rejected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/detect", nil)
		req.Header.Set("Authorization", "Bearer bad-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assertStatus(t, rec, 401)
	})
}

func TestJWKSClientRefreshOnUnknownKID(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}

	// Start with an empty JWKS, then add the key on second fetch.
	callCount := 0
	set := jwk.NewSet()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount >= 2 {
			// Add the key on refresh.
			pub, _ := jwk.FromRaw(ecPriv.Public())
			_ = pub.Set(jwk.KeyIDKey, "rotated-key")
			_ = pub.Set(jwk.AlgorithmKey, jwa.ES256)
			_ = pub.Set(jwk.KeyUsageKey, "sig")
			freshSet := jwk.NewSet()
			_ = freshSet.AddKey(pub)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(freshSet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(set)
	}))
	defer server.Close()

	v, err := authjwt.NewVerifier(authjwt.VerifierConfig{
		JWKSURL: server.URL,
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	defer v.Close()

	// Sign a token with the "rotated-key" kid.
	token := jwt.New()
	now := time.Now()
	_ = token.Set("iss", "https://auth.test.com")
	_ = token.Set("sub", "test")
	_ = token.Set("iat", now.Unix())
	_ = token.Set("exp", now.Add(1*time.Hour).Unix())
	_ = token.Set("account_id", "acc-rotated")

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, "rotated-key")

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, ecPriv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify — should fail on first JWKS (empty), trigger refresh, then succeed.
	claims, err := v.Verify(context.Background(), string(signed))
	if err != nil {
		t.Fatalf("verify after key rotation: %v", err)
	}
	assertEqual(t, "AccountID", claims.AccountID, "acc-rotated")
}

func TestVerifyAudience(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"

	v, err := authjwt.NewVerifier(authjwt.VerifierConfig{
		JWKSURL:  ks.server.URL,
		Issuer:   issuer,
		Audience: "my-mcp-server",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	defer v.Close()

	t.Run("matching audience passes", func(t *testing.T) {
		c := baseClaims(issuer)
		c["aud"] = []string{"my-mcp-server"}
		token := ks.signRS256(t, c)
		claims, err := v.Verify(context.Background(), token)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		assertEqual(t, "AccountID", claims.AccountID, "acc-001")
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		c := baseClaims(issuer)
		c["aud"] = []string{"other-service"}
		token := ks.signRS256(t, c)
		_, err := v.Verify(context.Background(), token)
		if err == nil {
			t.Fatal("expected error for wrong audience")
		}
	})
}

func TestScopeEnforcement(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	c := agentClaims(issuer)
	c["scopes"] = []string{"repo:read", "repo:write"}
	token := ks.signES256(t, c)

	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	t.Run("HasScope true", func(t *testing.T) {
		if !claims.HasScope("repo:read") {
			t.Error("expected HasScope(repo:read) = true")
		}
	})

	t.Run("HasScope false", func(t *testing.T) {
		if claims.HasScope("admin:delete") {
			t.Error("expected HasScope(admin:delete) = false")
		}
	})

	t.Run("RequireScope passes", func(t *testing.T) {
		if err := claims.RequireScope("repo:write"); err != nil {
			t.Errorf("RequireScope(repo:write) = %v, want nil", err)
		}
	})

	t.Run("RequireScope fails", func(t *testing.T) {
		err := claims.RequireScope("admin:delete")
		if err == nil {
			t.Fatal("expected error for missing scope")
		}
	})
}

func TestAgentIdentity(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	t.Run("agent token returns AgentIdentity", func(t *testing.T) {
		c := agentClaims(issuer)
		c["scopes"] = []string{"tool:call"}
		c["owner_user_id"] = "user-admin"
		token := ks.signES256(t, c)

		claims, err := v.Verify(context.Background(), token)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}

		agent := claims.Agent()
		if agent == nil {
			t.Fatal("Agent() returned nil for agent token")
		}

		assertEqual(t, "ExternalID", agent.ExternalID, "agent-smith")
		assertEqual(t, "IdentityType", agent.IdentityType, "agent")
		assertEqual(t, "SubType", agent.SubType, "orchestrator")
		assertEqual(t, "TrustLevel", agent.TrustLevel, "verified_third_party")
		assertEqual(t, "Framework", agent.Framework, "langchain")
		assertEqual(t, "Publisher", agent.Publisher, "acme-corp")
		assertEqual(t, "DelegatedBy", agent.DelegatedBy, "orchestrator-1")
		assertEqual(t, "Owner", agent.Owner, "user-admin")

		if agent.DelegationDepth != 1 {
			t.Errorf("DelegationDepth = %d, want 1", agent.DelegationDepth)
		}
		if len(agent.Scopes) != 1 || agent.Scopes[0] != "tool:call" {
			t.Errorf("Scopes = %v, want [tool:call]", agent.Scopes)
		}
	})

	t.Run("human token returns nil", func(t *testing.T) {
		token := ks.signRS256(t, baseClaims(issuer))
		claims, err := v.Verify(context.Background(), token)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if claims.Agent() != nil {
			t.Error("Agent() should return nil for human token")
		}
	})
}

func TestVerifyRealTime(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"

	t.Run("active token passes", func(t *testing.T) {
		introspectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"active":true}`))
		}))
		defer introspectServer.Close()

		v, err := authjwt.NewVerifier(authjwt.VerifierConfig{
			JWKSURL:       ks.server.URL,
			Issuer:        issuer,
			IntrospectURL: introspectServer.URL,
		})
		if err != nil {
			t.Fatalf("create verifier: %v", err)
		}
		defer v.Close()

		token := ks.signRS256(t, baseClaims(issuer))
		claims, err := v.VerifyRealTime(context.Background(), token)
		if err != nil {
			t.Fatalf("VerifyRealTime: %v", err)
		}
		assertEqual(t, "AccountID", claims.AccountID, "acc-001")
	})

	t.Run("revoked token rejected", func(t *testing.T) {
		introspectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"active":false}`))
		}))
		defer introspectServer.Close()

		v, err := authjwt.NewVerifier(authjwt.VerifierConfig{
			JWKSURL:       ks.server.URL,
			Issuer:        issuer,
			IntrospectURL: introspectServer.URL,
		})
		if err != nil {
			t.Fatalf("create verifier: %v", err)
		}
		defer v.Close()

		token := ks.signRS256(t, baseClaims(issuer))
		_, err = v.VerifyRealTime(context.Background(), token)
		if err == nil {
			t.Fatal("expected error for revoked token")
		}
	})

	t.Run("no introspect URL falls back to local", func(t *testing.T) {
		v := newVerifier(t, ks, issuer) // no IntrospectURL
		token := ks.signRS256(t, baseClaims(issuer))
		claims, err := v.VerifyRealTime(context.Background(), token)
		if err != nil {
			t.Fatalf("VerifyRealTime fallback: %v", err)
		}
		assertEqual(t, "AccountID", claims.AccountID, "acc-001")
	})
}

// Helpers

func assertEqual(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", field, got, want)
	}
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, want, rec.Body.String())
	}
}
