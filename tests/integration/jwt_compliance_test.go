// RFC 7519 (JSON Web Token) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// Most of RFC 7519 is structural — `xxx.yyy.zzz` shape, base64url-encoded
// JSON header + payload + signature — and is enforced by the jwx library
// at sign time. This file asserts the §4.1 standard claims set the issuer
// embeds in every token and the NumericDate encoding of the time claims.

package integration_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issueAccessToken mints a baseline client_credentials token whose claims
// the test inspects directly.
func issueAccessToken(t *testing.T) string {
	t.Helper()
	agentID := uid("compliance-jwt")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token, _ := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, token)
	return token
}

// ── RFC 7519 §4.1 — Registered Claim Names ──────────────────────────────────

func TestRFC7519_S4_1_IssClaimPresent(t *testing.T) {
	// RFC 7519 §4.1.1: "The 'iss' (issuer) claim identifies the principal
	//   that issued the JWT."
	parsed, err := jwt.ParseInsecure([]byte(issueAccessToken(t)))
	require.NoError(t, err)
	iss, ok := parsed.Issuer()
	assert.True(t, ok, "iss claim REQUIRED for tokens that name an issuer authority")
	assert.NotEmpty(t, iss, "iss MUST NOT be empty")
}

func TestRFC7519_S4_1_SubClaimPresent(t *testing.T) {
	// RFC 7519 §4.1.2: "The 'sub' (subject) claim identifies the principal
	//   that is the subject of the JWT."
	parsed, err := jwt.ParseInsecure([]byte(issueAccessToken(t)))
	require.NoError(t, err)
	sub, ok := parsed.Subject()
	assert.True(t, ok, "sub claim is core JWT identity")
	assert.NotEmpty(t, sub, "sub MUST NOT be empty")
	assert.True(t, strings.HasPrefix(sub, "spiffe://"),
		"ZeroID-issued tokens carry a SPIFFE / WIMSE URI as sub")
}

func TestRFC7519_S4_1_AudClaimPresent(t *testing.T) {
	// RFC 7519 §4.1.3: "The 'aud' (audience) claim identifies the recipients
	//   that the JWT is intended for."
	parsed, err := jwt.ParseInsecure([]byte(issueAccessToken(t)))
	require.NoError(t, err)
	aud, ok := parsed.Audience()
	assert.True(t, ok, "aud claim REQUIRED per JWT-SVID §3 for verifier interop")
	assert.NotEmpty(t, aud, "aud MUST contain at least one value")
}

func TestRFC7519_S4_1_ExpClaimIsNumericDate(t *testing.T) {
	// RFC 7519 §4.1.4: "The 'exp' (expiration time) claim ... value MUST be
	//   a number containing a NumericDate value." (Seconds since epoch.)
	parsed, err := jwt.ParseInsecure([]byte(issueAccessToken(t)))
	require.NoError(t, err)
	exp, ok := parsed.Expiration()
	require.True(t, ok, "exp claim REQUIRED on every issued access token")
	assert.False(t, exp.IsZero(), "exp must decode to a non-zero time")
	// Sanity bounds: between 2020-01-01 and 2200-01-01.
	low := time.Unix(1577836800, 0)
	high := time.Unix(7258118400, 0)
	assert.True(t, exp.After(low) && exp.Before(high),
		"exp must decode as NumericDate-Unix seconds (got %v)", exp)
}

func TestRFC7519_S4_1_IatClaimPresent(t *testing.T) {
	// RFC 7519 §4.1.6: "The 'iat' (issued at) claim identifies the time at
	//   which the JWT was issued." Always present on ZeroID-issued tokens.
	parsed, err := jwt.ParseInsecure([]byte(issueAccessToken(t)))
	require.NoError(t, err)
	iat, ok := parsed.IssuedAt()
	assert.True(t, ok, "iat REQUIRED on every issued token")
	assert.False(t, iat.IsZero(), "iat MUST decode to a real timestamp")
}

func TestRFC7519_S4_1_JtiClaimUniquePerToken(t *testing.T) {
	// RFC 7519 §4.1.7: "The 'jti' (JWT ID) claim provides a unique identifier
	//   for the JWT." Two tokens issued by the same identity MUST get
	//   distinct JTIs.
	parsed1, err := jwt.ParseInsecure([]byte(issueAccessToken(t)))
	require.NoError(t, err)
	parsed2, err := jwt.ParseInsecure([]byte(issueAccessToken(t)))
	require.NoError(t, err)
	jti1, _ := parsed1.JwtID()
	jti2, _ := parsed2.JwtID()
	assert.NotEmpty(t, jti1, "jti REQUIRED")
	assert.NotEmpty(t, jti2, "jti REQUIRED")
	assert.NotEqual(t, jti1, jti2, "two issuances MUST produce distinct JTIs")
}

// ── RFC 7519 §5 — JOSE Header ───────────────────────────────────────────────

func TestRFC7519_S5_TokenHasThreeBase64UrlSegments(t *testing.T) {
	// RFC 7519 §3 / RFC 7515 §3.1: a JWT in compact serialization is
	// `BASE64URL(JOSE Header) || '.' || BASE64URL(Payload) || '.' || BASE64URL(Signature)`.
	tok := issueAccessToken(t)
	parts := strings.Split(tok, ".")
	assert.Len(t, parts, 3, "JWT compact serialization MUST have exactly three dot-separated parts")
	for i, p := range parts {
		assert.NotEmpty(t, p, "segment %d MUST be non-empty", i)
		// base64url chars only — no =, no +, no /
		assert.NotContains(t, p, "+", "segment %d uses base64url, NOT base64 (forbids '+')", i)
		assert.NotContains(t, p, "/", "segment %d uses base64url, NOT base64 (forbids '/')", i)
		assert.NotContains(t, p, "=", "segment %d MUST omit base64url padding ('=')", i)
	}
}
