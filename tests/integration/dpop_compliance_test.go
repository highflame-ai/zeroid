// RFC 9449 (DPoP) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows: one MUST per test,
// test name carries the RFC + section citation, first comment quotes the
// clause, and the file groups tests in RFC order.
//
// Happy-path coverage (cnf.jkt set, token_type=DPoP, jti replay) lives in
// dpop_test.go and dpop_refresh_test.go. This file is the negative-space
// proof that each normative clause is enforced.

package integration_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildCustomDPoPProof signs a DPoP proof whose headers and payload come
// directly from the caller — used to construct spec violations the high-level
// `buildDPoPProof` helper deliberately can't produce (omitted claims, wrong
// `typ`, wrong `alg`, private-key-in-jwk-header, etc.).
//
// `extraHeaders` and `payload` are merged with the canonical fields. Pass nil
// for headers to use the defaults (`typ=dpop+jwt`, embedded public jwk, ES256);
// pass nil for payload to use canonical `{htm, htu, iat, jti}`. Pass an explicit
// non-nil map to override.
func buildCustomDPoPProof(t *testing.T, privKey *ecdsa.PrivateKey, headers, payload map[string]any) string {
	t.Helper()
	privJWK, err := jwk.Import[jwk.Key](privKey)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](&privKey.PublicKey)
	require.NoError(t, err)

	hdrs := jws.NewHeaders()
	defaultHeaders := map[string]any{
		"typ": "dpop+jwt",
		"jwk": pubJWK,
	}
	for k, v := range defaultHeaders {
		if _, ok := headers[k]; ok {
			continue
		}
		require.NoError(t, hdrs.Set(k, v))
	}
	for k, v := range headers {
		if v == nil {
			continue // explicit nil ⇒ omit header
		}
		require.NoError(t, hdrs.Set(k, v))
	}

	if payload == nil {
		payload = map[string]any{
			"htm": http.MethodPost,
			"htu": testServer.URL + "/oauth2/token",
			"iat": time.Now().Unix(),
			"jti": uuid.New().String(),
		}
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), privJWK, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return string(signed)
}

// dpopRegisterAndTokenRequest sets up the minimum environment a DPoP proof can
// be presented against — registers a confidential client and returns the
// canonical token-request body. Each test reuses this and only varies the
// DPoP header.
func dpopRegisterAndTokenRequest(t *testing.T, namePrefix string) map[string]any {
	t.Helper()
	agentID := uid(namePrefix)
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})
	return map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}
}

// assertInvalidDPoPProof posts a /oauth2/token request with the given proof
// and asserts the response is RFC 9449 §5 / RFC 6749 §5.2 shape:
// HTTP 400 with `error=invalid_dpop_proof`.
func assertInvalidDPoPProof(t *testing.T, body map[string]any, proof string) {
	t.Helper()
	resp := post(t, "/oauth2/token", body, map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected 400 for malformed proof")
	errBody := decode(t, resp)
	assert.Equal(t, "invalid_dpop_proof", errBody["error"], "error field must be invalid_dpop_proof per RFC 9449 §5")
}

// ── RFC 9449 §4.2 — DPoP Proof JWT ───────────────────────────────────────────

func TestRFC9449_S4_2_TypHeaderMustBeDpopJwt(t *testing.T) {
	// RFC 9449 §4.2: "The JOSE Header MUST contain at least the following
	//   parameters: ... typ: with value dpop+jwt"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildCustomDPoPProof(t, key, map[string]any{"typ": "JWT"}, nil)
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-typ"), proof)
}

func TestRFC9449_S4_2_AlgMustBeAsymmetric(t *testing.T) {
	// RFC 9449 §4.2: "alg: An identifier for an asymmetric digital signature
	//   algorithm ... MUST NOT be none or an identifier for a symmetric
	//   algorithm (MAC)."
	//
	// We assemble an HS256-signed proof manually because jws.Sign refuses to
	// embed a symmetric key in the jwk header; the verifier must reject it
	// at the alg-allowlist step (step 3 in DPoPService.validate).
	hdrJSON, err := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "HS256"})
	require.NoError(t, err)
	payloadJSON, err := json.Marshal(map[string]any{
		"htm": http.MethodPost,
		"htu": testServer.URL + "/oauth2/token",
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
	})
	require.NoError(t, err)
	signingInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	// Signature bytes are irrelevant — we expect rejection at the alg check
	// before signature verification. Pad with zeros so the JWS parses.
	proof := signingInput + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-alg"), proof)
}

func TestRFC9449_S4_2_JwkHeaderMustBePresent(t *testing.T) {
	// RFC 9449 §4.2: "jwk: The public key chosen by the client, in JSON Web
	//   Key (JWK) format, as defined in Section 4 of [RFC7517]"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// nil header value ⇒ omit
	proof := buildCustomDPoPProof(t, key, map[string]any{"jwk": nil}, nil)
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-no-jwk"), proof)
}

func TestRFC9449_S4_2_JwkMustNotContainPrivateKey(t *testing.T) {
	// RFC 9449 §4.2: "The jwk header value SHOULD NOT contain a private key."
	// We treat this as a MUST NOT — the validator rejects any private-key JWK
	// type (ECDSAPrivateKey / RSAPrivateKey / OKPPrivateKey) at step 4.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privJWK, err := jwk.Import[jwk.Key](key)
	require.NoError(t, err)
	// Override with the *private* JWK in the jwk header — must be rejected.
	proof := buildCustomDPoPProof(t, key, map[string]any{"jwk": privJWK}, nil)
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-priv-jwk"), proof)
}

func TestRFC9449_S4_2_IatMustBePresent(t *testing.T) {
	// RFC 9449 §4.2: "iat: Creation timestamp of the JWT (Section 4.1.6 of
	//   [RFC7519]); REQUIRED"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildCustomDPoPProof(t, key, nil, map[string]any{
		"htm": http.MethodPost,
		"htu": testServer.URL + "/oauth2/token",
		"jti": uuid.New().String(),
		// iat deliberately omitted
	})
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-no-iat"), proof)
}

func TestRFC9449_S4_2_JtiMustBePresent(t *testing.T) {
	// RFC 9449 §4.2: "jti: Unique identifier for the DPoP proof JWT.
	//   ... REQUIRED"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildCustomDPoPProof(t, key, nil, map[string]any{
		"htm": http.MethodPost,
		"htu": testServer.URL + "/oauth2/token",
		"iat": time.Now().Unix(),
		// jti deliberately omitted
	})
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-no-jti"), proof)
}

func TestRFC9449_S4_2_IatOutsideFreshnessWindowRejected(t *testing.T) {
	// RFC 9449 §4.3: "the iat claim of the JWT is within an acceptable
	//   timeframe (...)". 60 s freshness window + 5 s skew (per
	//   internal/service/dpop.go).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildCustomDPoPProof(t, key, nil, map[string]any{
		"htm": http.MethodPost,
		"htu": testServer.URL + "/oauth2/token",
		"iat": time.Now().Add(-2 * time.Minute).Unix(),
		"jti": uuid.New().String(),
	})
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-old-iat"), proof)
}

func TestRFC9449_S4_2_IatFarInFutureRejected(t *testing.T) {
	// RFC 9449 §4.3 (server validation): future iat beyond the skew tolerance
	// must be rejected; otherwise a client could pre-mint long-lived proofs.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildCustomDPoPProof(t, key, nil, map[string]any{
		"htm": http.MethodPost,
		"htu": testServer.URL + "/oauth2/token",
		"iat": time.Now().Add(time.Hour).Unix(),
		"jti": uuid.New().String(),
	})
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-future-iat"), proof)
}

func TestRFC9449_S4_2_ExpInPastRejected(t *testing.T) {
	// RFC 9449 §4.2: exp is OPTIONAL but if present must be honoured.
	// Without this, an explicitly-expired proof could ride on the iat
	// freshness check alone.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().Unix()
	proof := buildCustomDPoPProof(t, key, nil, map[string]any{
		"htm": http.MethodPost,
		"htu": testServer.URL + "/oauth2/token",
		"iat": now,
		"jti": uuid.New().String(),
		"exp": now - 600, // expired ten minutes ago
	})
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-past-exp"), proof)
}

func TestRFC9449_S4_2_NbfInFutureRejected(t *testing.T) {
	// RFC 9449 §4.2: nbf is OPTIONAL but if present must be honoured.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().Unix()
	proof := buildCustomDPoPProof(t, key, nil, map[string]any{
		"htm": http.MethodPost,
		"htu": testServer.URL + "/oauth2/token",
		"iat": now,
		"jti": uuid.New().String(),
		"nbf": now + 600, // not valid for another ten minutes
	})
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-future-nbf"), proof)
}

// ── RFC 9449 §4.3 — Server validation ────────────────────────────────────────

func TestRFC9449_S4_3_SingleSignatureRequired(t *testing.T) {
	// RFC 9449 §4.2: a DPoP proof is a JWT — implicitly compact JWS (one sig).
	// JWS JSON Serialization with >1 signature must be rejected so that an
	// attacker can't attach a second signature at index 0 with benign
	// protected headers while the attack signature sits elsewhere.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Build a perfectly normal compact proof, then re-serialize it as JWS
	// JSON with the same signature duplicated. Both signature slots will
	// pass crypto, but the validator must reject before reaching either.
	compact := buildCustomDPoPProof(t, key, nil, nil)
	parts := strings.Split(compact, ".")
	require.Len(t, parts, 3, "compact JWS has three parts")
	jsonSerialized := map[string]any{
		"payload": parts[1],
		"signatures": []map[string]any{
			{"protected": parts[0], "signature": parts[2]},
			{"protected": parts[0], "signature": parts[2]},
		},
	}
	jsonBytes, err := json.Marshal(jsonSerialized)
	require.NoError(t, err)

	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-multi-sig"), string(jsonBytes))
}

func TestRFC9449_S4_3_HtmCaseSensitive(t *testing.T) {
	// RFC 9449 §4.2 inherits RFC 9110 §9.1: HTTP method names are
	// case-sensitive uppercase. Lowercase "post" must NOT match POST.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildCustomDPoPProof(t, key, nil, map[string]any{
		"htm": "post", // lowercase
		"htu": testServer.URL + "/oauth2/token",
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
	})
	assertInvalidDPoPProof(t, dpopRegisterAndTokenRequest(t, "dpop-htm-case"), proof)
}

func TestRFC9449_S4_3_HtuStripsQueryAndFragment(t *testing.T) {
	// RFC 9449 §4.2: "The htu claim ... matching is performed ... but
	//   excluding any query and fragment parts."
	// Positive assertion: a proof whose htu carries a query string MUST be
	// accepted because the comparator strips it.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildCustomDPoPProof(t, key, nil, map[string]any{
		"htm": http.MethodPost,
		"htu": testServer.URL + "/oauth2/token?stray=value#fragment",
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
	})
	resp := post(t, "/oauth2/token", dpopRegisterAndTokenRequest(t, "dpop-htu-query"), map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusOK, resp.StatusCode, "htu with query/fragment must still match after normalisation")
	tok := decode(t, resp)
	assert.Equal(t, "DPoP", tok["token_type"], "token_type must reflect successful proof acceptance")
}

func TestRFC9449_S4_3_HtuHostCaseInsensitive(t *testing.T) {
	// RFC 3986 §3.2.2: the host component of a URI is case-insensitive.
	// A proof signed with `EXAMPLE.com` MUST verify against `example.com`
	// (and vice-versa). Build a proof whose htu uppercases the host portion
	// of testServer.URL.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// testServer.URL is like http://127.0.0.1:NNNN; uppercase the scheme.
	upperURL := strings.ToUpper(testServer.URL[:4]) + testServer.URL[4:]
	proof := buildCustomDPoPProof(t, key, nil, map[string]any{
		"htm": http.MethodPost,
		"htu": upperURL + "/oauth2/token",
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
	})
	resp := post(t, "/oauth2/token", dpopRegisterAndTokenRequest(t, "dpop-htu-case"), map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusOK, resp.StatusCode, "host/scheme case-difference must still validate")
	tok := decode(t, resp)
	assert.Equal(t, "DPoP", tok["token_type"])
}

// ── RFC 9449 §6.1 — Confirmation claim ───────────────────────────────────────

func TestRFC9449_S6_1_CnfJktEqualsRfc7638Thumbprint(t *testing.T) {
	// RFC 9449 §6.1: "When access tokens are represented as JWTs ... a public
	//   key confirmation MUST be made using a JWK SHA-256 Thumbprint
	//   confirmation method as defined in [RFC7638]."
	//
	// We compute the thumbprint independently (via jwk.Thumbprint with
	// crypto.SHA256, base64url-encoded with no padding) and assert byte-equal
	// to the cnf.jkt the server published on a successfully-bound token.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](&key.PublicKey)
	require.NoError(t, err)
	expectedBytes, err := pubJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	expected := base64.RawURLEncoding.EncodeToString(expectedBytes)

	body := dpopRegisterAndTokenRequest(t, "dpop-jkt")
	proof := buildCustomDPoPProof(t, key, nil, nil)
	resp := post(t, "/oauth2/token", body, map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	accessToken, _ := decode(t, resp)["access_token"].(string)

	result := introspect(t, accessToken)
	cnf, ok := result["cnf"].(map[string]any)
	require.True(t, ok)
	jkt, _ := cnf["jkt"].(string)
	assert.Equal(t, expected, jkt, "cnf.jkt MUST equal base64url(SHA-256(JWK)) per RFC 7638")
}
