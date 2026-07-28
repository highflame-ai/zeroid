package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// This file hardens the direct-OIDC-federation e2e coverage beyond the single
// ES256 happy path in external_idp_test.go. Every case drives the REAL
// /oauth2/token HTTP endpoint of a real zeroid.NewServer (backed by the shared
// testcontainers Postgres) against a fake upstream IdP served over TLS — i.e.
// the full request path, not a unit shim.
//
// The headline case (TestExternalIDTokenFederation_NoAlgKeyAndAlgVariants) uses
// an Entra-shaped JWKS key that OMITS the `alg` member. jwx selects the verify
// algorithm from the key's `alg`; with no `alg` and without
// WithInferAlgorithmFromKey, it supplies no key and verification fails. This
// test therefore fails outright without the inference fix in
// externalIDTokenExchange — it is the regression guard for the "works in tests,
// silently broken against Entra/real IdPs" trap.

// fakeRSAIdP is a fake upstream OIDC IdP that signs RS256/PS256 tokens and
// publishes an RSA JWKS over TLS. includeAlg controls whether the published JWK
// carries an `alg` member (real IdPs vary: Okta/Auth0/Google include it,
// Microsoft Entra ID does not). It supports key rotation for the refresh test.
type fakeRSAIdP struct {
	srv    *httptest.Server
	mu     sync.Mutex
	priv   *rsa.PrivateKey
	kid    string
	keySet jwk.Set
}

func newFakeRSAIdP(t *testing.T, kid string, includeAlg bool) *fakeRSAIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idp := &fakeRSAIdP{
		priv:   priv,
		kid:    kid,
		keySet: buildRSAJWKS(t, &priv.PublicKey, kid, includeAlg),
	}
	idp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idp.mu.Lock()
		ks := idp.keySet
		idp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	return idp
}

func (i *fakeRSAIdP) JWKSURL() string { return i.srv.URL }
func (i *fakeRSAIdP) Close()          { i.srv.Close() }

// signKey/signKID return the current signing material under lock.
func (i *fakeRSAIdP) signKey() (*rsa.PrivateKey, string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.priv, i.kid
}

// sign mints an RS256 token with the current key/kid.
func (i *fakeRSAIdP) sign(t *testing.T, claims map[string]any) string {
	key, kid := i.signKey()
	return signRSAToken(t, jwa.RS256(), key, kid, claims)
}

// rotate swaps in a fresh key under a new kid and serves only the new JWKS,
// mimicking an upstream key rotation. The registry's cached JWKS (holding the
// old kid) must refetch on demand to verify a token signed with the new key.
func (i *fakeRSAIdP) rotate(t *testing.T, newKid string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	i.mu.Lock()
	i.priv = priv
	i.kid = newKid
	i.keySet = buildRSAJWKS(t, &priv.PublicKey, newKid, true)
	i.mu.Unlock()
}

func buildRSAJWKS(t *testing.T, pub *rsa.PublicKey, kid string, includeAlg bool) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	k, err := jwk.Import[jwk.Key](pub)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwk.KeyIDKey, kid))
	require.NoError(t, k.Set(jwk.KeyUsageKey, jwk.ForSignature))
	if includeAlg {
		require.NoError(t, k.Set(jwk.AlgorithmKey, jwa.RS256()))
	}
	require.NoError(t, set.AddKey(k))
	return set
}

// signRSAToken hand-signs a token with an explicit alg/key/kid so tests can
// forge mismatches (e.g. sign with an attacker key while advertising the real
// kid, or sign PS256 against an RSA key).
func signRSAToken(t *testing.T, alg jwa.SignatureAlgorithm, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, kid))
	require.NoError(t, hdr.Set(jws.TypeKey, "JWT"))
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)
	return string(signed)
}

func federationExchangeBody(idToken, accountID, projectID string) map[string]any {
	return map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      idToken,
		"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
		"account_id":         accountID,
		"project_id":         projectID,
	}
}

// TestExternalIDTokenFederation_NoAlgKeyAndAlgVariants is the P1-A regression
// guard: it federates against an IdP whose JWKS key omits `alg` (Entra-shaped),
// across RS256 and PS256 tokens. Without WithInferAlgorithmFromKey these all
// fail with "no key in the key set was usable".
func TestExternalIDTokenFederation_NoAlgKeyAndAlgVariants(t *testing.T) {
	iss := "https://noalg.idp.test"
	aud := "https://zeroid.federation.test"

	idp := newFakeRSAIdP(t, "noalg-kid-1", false /* includeAlg — Entra omits it */)
	defer idp.Close()

	fedSrv, fedHTTPSrv, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          iss,
		JWKSURI:         idp.JWKSURL(),
		Audience:        aud,
		ClaimMapping:    map[string]string{"user_id": "sub", "email": "email"},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTPSrv.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	validClaims := func() map[string]any {
		now := time.Now()
		return map[string]any{
			"iss":   iss,
			"aud":   aud,
			"sub":   "entra-user-oid-1",
			"email": "carol@example.com",
			"iat":   now.Unix(),
			"exp":   now.Add(5 * time.Minute).Unix(),
		}
	}

	t.Run("RS256 token with no-alg JWKS key verifies and emits user_id_iss", func(t *testing.T) {
		idToken := idp.sign(t, validClaims())
		resp := postFederation(t, fedHTTPSrv.URL, federationExchangeBody(idToken, fedCfg.AccountID, fedCfg.ProjectID))
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"no-alg JWKS key must verify (requires WithInferAlgorithmFromKey); body=%s", resp.RawBody)
		claims := decodeIssuedTokenClaims(t, resp.AccessToken)
		require.Equal(t, iss, claims["user_id_iss"])
		require.Equal(t, "external_id_token", claims["token_exchange"])
		require.Equal(t, "entra-user-oid-1", claims["sub"])
	})

	t.Run("PS256 token with no-alg JWKS key verifies", func(t *testing.T) {
		key, kid := idp.signKey()
		idToken := signRSAToken(t, jwa.PS256(), key, kid, validClaims())
		resp := postFederation(t, fedHTTPSrv.URL, federationExchangeBody(idToken, fedCfg.AccountID, fedCfg.ProjectID))
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"PS256 over a no-alg RSA key must verify via inference; body=%s", resp.RawBody)
	})
}

// TestExternalIDTokenFederation_CrossTenantRejected is the P1-B regression
// guard: an upstream token is bound to ZeroID-the-RP via aud, but NOT to a
// ZeroID tenant. Only allowed_accounts binds it. A request that presents a
// valid token under a tenant not in allowed_accounts must be rejected before
// any token is minted.
func TestExternalIDTokenFederation_CrossTenantRejected(t *testing.T) {
	iss := "https://tenant.idp.test"
	aud := "https://zeroid.federation.test"

	idp := newFakeRSAIdP(t, "tenant-kid-1", true)
	defer idp.Close()

	fedSrv, fedHTTPSrv, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          iss,
		JWKSURI:         idp.JWKSURL(),
		Audience:        aud,
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{"acct-fed-001"}, // matches fedCfg.AccountID; "acct-evil" is not listed
	})
	defer fedHTTPSrv.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	now := time.Now()
	idToken := idp.sign(t, map[string]any{
		"iss": iss, "aud": aud, "sub": "user-x",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})

	t.Run("allowed tenant succeeds", func(t *testing.T) {
		resp := postFederation(t, fedHTTPSrv.URL, federationExchangeBody(idToken, fedCfg.AccountID, fedCfg.ProjectID))
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	})

	t.Run("disallowed tenant is rejected (no cross-tenant minting)", func(t *testing.T) {
		resp := postFederation(t, fedHTTPSrv.URL, federationExchangeBody(idToken, "acct-evil", "proj-evil"))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"a token must not be exchangeable under a tenant not in allowed_accounts; body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken, "no token may be minted for a disallowed tenant")
	})
}

// TestExternalIDTokenFederation_VerificationNegatives drives the core
// verification rules: aud binding, exp/iat freshness, signature integrity,
// required-claim presence, and the unknown-issuer guard. All must fail closed
// with a 400 and no minted token. The baseline confirms the same server mints
// on a clean token, so each rejection is attributable to the single mutation.
func TestExternalIDTokenFederation_VerificationNegatives(t *testing.T) {
	iss := "https://neg.idp.test"
	aud := "https://zeroid.federation.test"

	idp := newFakeRSAIdP(t, "neg-kid-1", true)
	defer idp.Close()

	fedSrv, fedHTTPSrv, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          iss,
		JWKSURI:         idp.JWKSURL(),
		Audience:        aud,
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{"acct-fed-001"},
		// MaxTokenAge left at the 10m default; the stale-iat case exceeds it.
	})
	defer fedHTTPSrv.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	base := func() map[string]any {
		now := time.Now()
		return map[string]any{
			"iss": iss, "aud": aud, "sub": "user-neg",
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		}
	}

	// Baseline: a clean token mints, so every failure below is the mutation's
	// doing and not a misconfigured server.
	t.Run("baseline clean token mints", func(t *testing.T) {
		resp := postFederation(t, fedHTTPSrv.URL, federationExchangeBody(idp.sign(t, base()), fedCfg.AccountID, fedCfg.ProjectID))
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	})

	cases := []struct {
		name  string
		token func(t *testing.T) string
	}{
		{"wrong audience", func(t *testing.T) string {
			c := base()
			c["aud"] = "https://some.other.rp"
			return idp.sign(t, c)
		}},
		{"expired exp", func(t *testing.T) string {
			c := base()
			c["exp"] = time.Now().Add(-2 * time.Minute).Unix() // beyond the 60s skew
			return idp.sign(t, c)
		}},
		{"stale iat beyond max_token_age", func(t *testing.T) string {
			now := time.Now()
			c := base()
			c["iat"] = now.Add(-20 * time.Minute).Unix() // > 10m default cap
			c["exp"] = now.Add(5 * time.Minute).Unix()   // still unexpired
			return idp.sign(t, c)
		}},
		{"missing iat", func(t *testing.T) string {
			c := base()
			delete(c, "iat")
			return idp.sign(t, c)
		}},
		{"missing exp", func(t *testing.T) string {
			c := base()
			delete(c, "exp")
			return idp.sign(t, c)
		}},
		{"missing sub", func(t *testing.T) string {
			c := base()
			delete(c, "sub")
			return idp.sign(t, c)
		}},
		{"bad signature (attacker key, real kid)", func(t *testing.T) string {
			attacker, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			_, kid := idp.signKey()
			return signRSAToken(t, jwa.RS256(), attacker, kid, base())
		}},
		{"unknown issuer", func(t *testing.T) string {
			c := base()
			c["iss"] = "https://stranger.idp.test" // not configured → invalid_request
			return idp.sign(t, c)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name+" rejected", func(t *testing.T) {
			resp := postFederation(t, fedHTTPSrv.URL, federationExchangeBody(tc.token(t), fedCfg.AccountID, fedCfg.ProjectID))
			require.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"%s must be rejected with 400; body=%s", tc.name, resp.RawBody)
			require.Empty(t, resp.AccessToken, "%s must not mint a token", tc.name)
		})
	}
}

// TestExternalIDTokenFederation_KeyRotation proves the on-demand JWKS refresh:
// the registry warms up with kid-1, the upstream rotates to kid-2, and a token
// signed with kid-2 must still verify (the verifier refetches the JWKS once on
// an unknown kid and retries) — no ZeroID restart required.
func TestExternalIDTokenFederation_KeyRotation(t *testing.T) {
	iss := "https://rotate.idp.test"
	aud := "https://zeroid.federation.test"

	idp := newFakeRSAIdP(t, "rot-kid-1", true)
	defer idp.Close()

	fedSrv, fedHTTPSrv, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          iss,
		JWKSURI:         idp.JWKSURL(),
		Audience:        aud,
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTPSrv.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	mk := func() map[string]any {
		now := time.Now()
		return map[string]any{
			"iss": iss, "aud": aud, "sub": "user-rot",
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		}
	}

	// Sanity: kid-1 (already warm in the cache) verifies.
	resp := postFederation(t, fedHTTPSrv.URL, federationExchangeBody(idp.sign(t, mk()), fedCfg.AccountID, fedCfg.ProjectID))
	require.Equal(t, http.StatusOK, resp.StatusCode, "pre-rotation token must verify; body=%s", resp.RawBody)

	// Upstream rotates to a brand-new key+kid the cache has never seen.
	idp.rotate(t, "rot-kid-2")

	resp = postFederation(t, fedHTTPSrv.URL, federationExchangeBody(idp.sign(t, mk()), fedCfg.AccountID, fedCfg.ProjectID))
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"post-rotation token must verify after on-demand JWKS refresh; body=%s", resp.RawBody)
	claims := decodeIssuedTokenClaims(t, resp.AccessToken)
	require.Equal(t, iss, claims["user_id_iss"])
}
