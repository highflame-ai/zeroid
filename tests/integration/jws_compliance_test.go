// RFC 7515 §4.1.4 (kid) + RFC 8725 / BCP 225 (JWT Best Current Practices)
// compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows: one MUST per test,
// test name carries the RFC + section citation, first comment quotes the
// clause, and the file groups tests in RFC order.
//
// Scope: how a ZeroID-issued token is RESOLVED TO A KEY and how the signing
// algorithm is constrained once it is. RFC 7519 claim semantics live in
// jwt_compliance_test.go; this file is about the JOSE header and the key.
//
// These run against the agent-auth middleware path specifically. jwt_alg_test.go
// already covers alg=none and HS* at /oauth2/token/introspect and
// /oauth2/token/verify, but those are different code paths with their own
// verifiers — and this one had no coverage at all, which is how #357 survived:
// the middleware pinned a single algorithm and a single key, so every RS256
// token the grants issue was refused, and no test noticed.

package integration_test

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postToAgentAuth probes the agent-auth-protected endpoint with a bearer
// credential and returns the status. agentAuthProtectedPath is defined in
// www_authenticate_compliance_test.go.
func postToAgentAuth(t *testing.T, token string) int {
	t.Helper()
	resp := post(t, agentAuthProtectedPath(), map[string]any{
		"identity_id": "00000000-0000-0000-0000-000000000000",
		"audience":    "https://target.example.com",
		"nonce":       uid("jws-nonce"),
	}, map[string]string{"Authorization": "Bearer " + token})
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// issueJWTBearerToken mints a token through the jwt-bearer grant, which signs
// ES256 — the counterpart to issueAPIKeyToken, which signs RS256.
func issueJWTBearerToken(t *testing.T, externalID string) string {
	t.Helper()
	key := generateKey(t)
	identity := registerIdentity(t, externalID, []string{"data:read"}, ecPublicKeyPEM(t, key))

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":  buildAssertion(t, key, identity.WIMSEURI),
		"scope":      "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decode(t, resp)["access_token"].(string)
}

// headerAlgOf decodes the JOSE header and returns its alg, so a test can pin
// which signing path it actually exercised rather than assuming.
func headerAlgOf(t *testing.T, token string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	require.NoError(t, err)
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	require.NoError(t, json.Unmarshal(raw, &hdr))
	require.NotEmpty(t, hdr.Kid, "every ZeroID-issued token must carry kid (RFC 7515 §4.1.4)")
	return hdr.Alg
}

// ── RFC 7515 §4.1.4 — the "kid" (Key ID) Header Parameter ───────────────────

func TestRFC7515_S4_1_4_KidSelectsTheVerificationKey(t *testing.T) {
	// RFC 7515 §4.1.4: "The 'kid' (key ID) Header Parameter is a hint
	// indicating which key was used to secure the JWS. This parameter allows
	// originators to explicitly signal a change of key to recipients."
	//
	// A recipient MUST therefore resolve the key from kid, not assume one key.
	// ZeroID publishes an EC key and an RSA key and signs with both, so a
	// verifier that honours kid accepts either, and one that does not accepts
	// only whichever it happened to pin (#357).
	rs256 := issueAPIKeyToken(t, uid("rfc7515-kid-rs256"))
	es256 := issueJWTBearerToken(t, uid("rfc7515-kid-es256"))

	require.Equal(t, "RS256", headerAlgOf(t, rs256), "api_key grant is the RS256 path")
	require.Equal(t, "ES256", headerAlgOf(t, es256), "jwt-bearer grant is the ES256 path")

	for name, token := range map[string]string{
		"RS256 — apiKeyGrant, authorizationCode, refreshToken, CIBA, ID-JAG": rs256,
		"ES256 — clientCredentials, jwtBearer, tokenExchange":                es256,
	} {
		t.Run(name, func(t *testing.T) {
			assert.NotEqual(t, http.StatusUnauthorized, postToAgentAuth(t, token),
				"a token whose kid names a published key must resolve to that key")
		})
	}
}

func TestRFC7515_S4_1_4_UnknownKidIsRejected(t *testing.T) {
	// RFC 7515 §4.1.4: kid identifies the key "used to secure the JWS". A kid
	// naming no published key resolves to nothing, so the JWS cannot be
	// verified and MUST be refused. Honouring kid must not become trusting it.
	token := signWithServerECKey(t, "no-such-kid", testIssuer)

	assert.Equal(t, http.StatusUnauthorized, postToAgentAuth(t, token),
		"a kid outside the published JWKS must not verify")
}

// ── RFC 8725 §3.1 — Perform Algorithm Verification ──────────────────────────

func TestRFC8725_S3_1_SignatureIsVerifiedAgainstTheResolvedKey(t *testing.T) {
	// RFC 8725 §3.1: "the algorithm ... used ... must be verified" against the
	// key the recipient resolved — the header is an untrusted hint, not the
	// decision. A token naming a real kid but signed by a different key MUST
	// fail, or kid alone would be a credential.
	foreign := generateKey(t)
	token := signWithKey(t, foreign, testKeyID, jwa.ES256(), testIssuer)

	assert.Equal(t, http.StatusUnauthorized, postToAgentAuth(t, token),
		"a real kid signed by a foreign key must fail signature verification")
}

func TestRFC8725_S3_1_SymmetricAlgorithmIsRejected(t *testing.T) {
	// RFC 8725 §3.1 / §2.1: the algorithm-confusion attack — an attacker takes
	// a published ASYMMETRIC public key and presents an HMAC-signed token, so a
	// verifier that trusts the header's alg uses those public bytes as the
	// shared secret.
	//
	// This clause matters more since #357 widened the accepted algorithm set to
	// include RS256, because the RSA public key is the classic material for it.
	token := signHS256WithPublicKeyBytes(t)

	assert.Equal(t, http.StatusUnauthorized, postToAgentAuth(t, token),
		"an HMAC-signed token must never verify against an asymmetric key")
}

func TestRFC8725_S3_1_AlgNoneIsRejected(t *testing.T) {
	// RFC 8725 §3.1: "'none' ... MUST NOT be used" for a token that carries
	// authorization. jwt_alg_test.go pins this at introspect and verify; this
	// pins the agent-auth middleware, whose verifier is separate.
	for _, alg := range []string{"none", "None", "NONE"} {
		t.Run(alg, func(t *testing.T) {
			token := craftUnsignedJWT(alg, `{"sub":"attacker","iss":"`+testIssuer+`","account_id":"a","project_id":"p"}`)

			assert.Equal(t, http.StatusUnauthorized, postToAgentAuth(t, token),
				"alg=%s must be refused before any key lookup", alg)
		})
	}
}

// ── signing helpers ─────────────────────────────────────────────────────────

// signWithKey mints a structurally valid agent token signed by the given key
// and stamped with the given kid. Claims are correct throughout, so each test
// isolates exactly one JOSE-header variable.
func signWithKey(t *testing.T, key *ecdsa.PrivateKey, kid string, alg jwa.SignatureAlgorithm, issuer string) string {
	t.Helper()
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, issuer))
	require.NoError(t, tok.Set(jwt.SubjectKey, "spiffe://zeroid.dev/compliance"))
	require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	require.NoError(t, tok.Set("account_id", testAccountID))
	require.NoError(t, tok.Set("project_id", testProjectID))

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.KeyIDKey, kid))
	require.NoError(t, hdrs.Set(jws.TypeKey, "JWT"))

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return string(signed)
}

// signWithServerECKey signs with the server's own EC key, so only the kid is
// wrong.
func signWithServerECKey(t *testing.T, kid, issuer string) string {
	t.Helper()
	return signWithKey(t, testServerPrivKey, kid, jwa.ES256(), issuer)
}

// signHS256WithPublicKeyBytes builds the RFC 8725 §2.1 algorithm-confusion
// token: an HS256 JWS whose MAC key is the server's own PUBLIC key material.
// A verifier that reads alg from the header and reaches for "the key" would
// compute the same MAC and accept it.
func signHS256WithPublicKeyBytes(t *testing.T) string {
	t.Helper()
	// Bytes() is the uncompressed SEC 1 encoding — the same material a
	// verifier would hand to an HMAC if it trusted the header's alg, and the
	// same bytes the deprecated elliptic.Marshal used to produce.
	pub, err := testServerPrivKey.PublicKey.Bytes()
	require.NoError(t, err)

	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"HS256","kid":"` + testKeyID + `","typ":"JWT"}`))
	payload := enc([]byte(`{"sub":"attacker","iss":"` + testIssuer + `","account_id":"` + testAccountID +
		`","project_id":"` + testProjectID + `","exp":` + itoa(time.Now().Add(time.Hour).Unix()) + `}`))

	mac := hmac.New(sha256.New, pub)
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + enc(mac.Sum(nil))
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
