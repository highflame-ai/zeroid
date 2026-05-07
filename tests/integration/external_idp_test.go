package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// TestExternalIDTokenFederation_EndToEnd covers the two manual smoke items
// in PR #124's test plan:
//
//   - Item 2: configure one external issuer, post an Okta-shaped ID token,
//     observe `user_id_iss` on the issued token.
//   - Item 3: with the same server, omit subject_token_type and confirm
//     dispatch still routes to the broker path (proven by the broker's
//     distinctive "external principal exchange is not configured" error,
//     which only that path emits).
//
// The federation server is a SECOND zeroid.NewServer instance pointed at
// the same Postgres as the shared TestMain server — adding external_issuers
// to the shared cfg would touch every other test, so we keep this one
// isolated. The fake upstream IdP runs as an httptest.NewTLSServer and the
// registry's HTTP client is overridden via the new
// zeroid.WithExternalIssuerJWKSOption hook so it can talk to the test cert.
func TestExternalIDTokenFederation_EndToEnd(t *testing.T) {
	upstreamIss := "https://upstream.idp.test"
	federationAud := "https://zeroid.federation.test"

	// Stand up a fake upstream IdP with one ES256 key.
	upstream := newFakeUpstreamIdP(t)
	defer upstream.Close()

	// Build a federation-configured server alongside the shared one.
	fedSrv, fedHTTPSrv, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:   upstreamIss,
		JWKSURI:  upstream.JWKSURL(),
		Audience: federationAud,
		ClaimMapping: map[string]string{
			"user_id": "sub",
			"email":   "email",
		},
		PropagateClaims: []string{"auth_time", "acr", "amr"},
	})
	defer fedHTTPSrv.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	t.Run("federation happy path emits user_id_iss", func(t *testing.T) {
		// Mint an Okta-shaped ID token. Okta uses `sub` as a stable string
		// identifier and emits `auth_time`/`amr` from the authentication event.
		now := time.Now()
		idToken := upstream.SignToken(t, map[string]any{
			"iss":        upstreamIss,
			"aud":        federationAud,
			"sub":        "00uABCDE12345",
			"email":      "alice@example.com",
			"iat":        now.Unix(),
			"exp":        now.Add(5 * time.Minute).Unix(),
			"auth_time":  now.Add(-30 * time.Second).Unix(),
			"amr":        []string{"pwd", "mfa"},
			"acr":        "urn:okta:app:mfa:factor:push",
		})

		resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      idToken,
			"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
			"account_id":         fedCfg.AccountID,
			"project_id":         fedCfg.ProjectID,
		})
		require.Equal(t, http.StatusOK, resp.StatusCode, "federation /oauth2/token must return 200; body=%s", resp.RawBody)

		issuedClaims := decodeIssuedTokenClaims(t, resp.AccessToken)

		// The headline assertion: user_id_iss is the upstream IdP's iss,
		// giving downstream consumers IdP-granular provenance.
		require.Equal(t, upstreamIss, issuedClaims["user_id_iss"],
			"issued token must carry user_id_iss = upstream iss")

		// The federation path emits token_exchange=external_id_token, which
		// distinguishes it from the broker's external_principal value.
		require.Equal(t, "external_id_token", issuedClaims["token_exchange"])

		// Honest claim propagation: auth_time/amr/acr were on the upstream,
		// so they should be on the issued token. The federation path never
		// default-fills these — we already verified absence in earlier unit
		// tests; this test verifies presence-when-upstream-set.
		require.Contains(t, issuedClaims, "auth_time")
		require.Contains(t, issuedClaims, "amr")
		require.Equal(t, "urn:okta:app:mfa:factor:push", issuedClaims["acr"])

		// Subject identifier flows through claim_mapping: user_id is mapped
		// to "sub", so the issued JWT's `sub` claim is the upstream `sub`.
		// (`user_id` itself isn't emitted as a JWT claim — it's on the API
		// response struct only, mirroring the broker path's behavior.)
		require.Equal(t, "00uABCDE12345", issuedClaims["sub"])
		require.Equal(t, "alice@example.com", issuedClaims["user_email"])
	})

	t.Run("broker dispatch unchanged when subject_token_type is omitted", func(t *testing.T) {
		// Same federation-configured server, but this request leaves
		// subject_token_type empty. Dispatch must NOT reach the federation
		// path; it must reach ExternalPrincipalExchange. The federation
		// server has no TrustedServiceValidator wired, so the broker path
		// fails with its distinctive "external principal exchange is not
		// configured" error — a fingerprint that only the broker path
		// produces. Different errors prove different dispatch arms.
		resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": "anything-the-broker-would-not-validate",
			"account_id":    fedCfg.AccountID,
			"project_id":    fedCfg.ProjectID,
			"user_id":       "alice",
		})
		require.NotEqual(t, http.StatusOK, resp.StatusCode,
			"broker path without TrustedServiceValidator must reject; body=%s", resp.RawBody)

		require.Contains(t, resp.RawBody, "external principal exchange is not configured",
			"broker fingerprint missing — dispatch may have leaked into the federation path. body=%s", resp.RawBody)

		// Sanity: the federation-only error string must NOT appear, since
		// dispatch should not have entered that arm at all.
		require.NotContains(t, resp.RawBody, "no external issuers are configured",
			"federation-path error string leaked — dispatch routed wrong")
	})
}

// ── Helpers ──────────────────────────────────────────────────────────────────

type fakeUpstreamIdP struct {
	srv     *httptest.Server
	priv    *ecdsa.PrivateKey
	keyID   string
	keySet  jwk.Set
	hits    atomic.Int64
}

func newFakeUpstreamIdP(t *testing.T) *fakeUpstreamIdP {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyID := "upstream-key-1"
	keySet := jwk.NewSet()
	pub, err := jwk.Import[jwk.Key](&priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, keyID))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.ES256()))
	require.NoError(t, pub.Set(jwk.KeyUsageKey, jwk.ForSignature))
	require.NoError(t, keySet.AddKey(pub))

	idp := &fakeUpstreamIdP{priv: priv, keyID: keyID, keySet: keySet}
	idp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(idp.keySet)
	}))
	return idp
}

func (i *fakeUpstreamIdP) JWKSURL() string { return i.srv.URL }
func (i *fakeUpstreamIdP) Close()          { i.srv.Close() }

// SignToken serialises the given claim map as an ES256 JWT. We use a hand
// rolled token rather than jwt.NewBuilder because we want full control over
// claim shape (e.g. amr as a string slice, auth_time as a unix int) to mimic
// real-world IdP outputs.
func (i *fakeUpstreamIdP) SignToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	hdr, err := jwsHeadersForKID(i.keyID)
	require.NoError(t, err)
	signed, err := jwt.Sign(tok,
		jwt.WithKey(jwa.ES256(), i.priv, jws.WithProtectedHeaders(hdr)),
	)
	require.NoError(t, err)
	return string(signed)
}

// federationServerCfg captures the bits the test needs to drive the server.
type federationServerCfg struct {
	AccountID string
	ProjectID string
}

// newFederationServer spins up a second zeroid.NewServer wired to the same
// Postgres as the shared TestMain server but with the given external_issuer
// configured. The fake JWKS runs over TLS, so we use
// WithExternalIssuerJWKSOption + an insecure HTTP client to let the registry
// reach it without trusting the test cert chain.
func newFederationServer(t *testing.T, issuer domain.ExternalIssuerConfig) (*zeroid.Server, *httptest.Server, federationServerCfg) {
	t.Helper()
	require.NoError(t, initFederationKeyMaterial(), "init federation key material")

	cfg := zeroid.Config{
		Server: zeroid.ServerConfig{
			Port:                   "0",
			Env:                    "test",
			ShutdownTimeoutSeconds: 5,
		},
		Database: zeroid.DatabaseConfig{
			URL:          sharedDBURL,
			MaxOpenConns: 5,
			MaxIdleConns: 2,
		},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath:    fedKeyPaths.privPath,
			PublicKeyPath:     fedKeyPaths.pubPath,
			KeyID:             "fed-test-key-1",
			RSAPrivateKeyPath: fedKeyPaths.rsaPriv,
			RSAPublicKeyPath:  fedKeyPaths.rsaPub,
			RSAKeyID:          "fed-test-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer:         "https://federation.zeroid.test",
			BaseURL:        "https://federation.zeroid.test",
			DefaultTTL:     3600,
			MaxTTL:         90 * 24 * 3600,
			HMACSecret:     testHMACSecret,
			AuthCodeIssuer: "https://federation.zeroid.test",
		},
		Telemetry:       zeroid.TelemetryConfig{Enabled: false},
		Logging:         zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain:     testWIMSE,
		ExternalIssuers: []domain.ExternalIssuerConfig{issuer},
	}

	insecure := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	srv, err := zeroid.NewServer(cfg, zeroid.WithExternalIssuerJWKSOption(authjwt.WithHTTPClient(insecure)))
	require.NoError(t, err, "build federation server")

	httpSrv := httptest.NewServer(srv.Router())

	return srv, httpSrv, federationServerCfg{
		AccountID: "acct-fed-001",
		ProjectID: "proj-fed-001",
	}
}

// tokenResponse decodes the relevant fields off /oauth2/token responses.
type tokenResponse struct {
	StatusCode  int
	AccessToken string
	RawBody     string
}

func postFederation(t *testing.T, baseURL string, body map[string]any) tokenResponse {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/oauth2/token", strings.NewReader(string(b)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var raw map[string]any
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&raw); err != nil {
		// Best-effort: the body might not be JSON on certain server errors.
		return tokenResponse{StatusCode: resp.StatusCode, RawBody: fmt.Sprintf("%v", err)}
	}
	at, _ := raw["access_token"].(string)
	rawBytes, _ := json.Marshal(raw)
	return tokenResponse{
		StatusCode:  resp.StatusCode,
		AccessToken: at,
		RawBody:     string(rawBytes),
	}
}

// decodeIssuedTokenClaims base64url-decodes the JWT payload section without
// verifying — we only need the claim map for assertions, and the issuer
// (the federation server we just built) is trusted by the test scope.
func decodeIssuedTokenClaims(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	require.NotEmpty(t, tokenStr, "access_token must be non-empty")
	parts := strings.Split(tokenStr, ".")
	require.Len(t, parts, 3, "JWT must have 3 parts")
	payload, err := jwtDecodeSegment(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(payload, &m))
	return m
}
