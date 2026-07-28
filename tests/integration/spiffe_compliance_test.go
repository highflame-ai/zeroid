// SPIFFE ID & JWT-SVID compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows. SPIFFE is an
// IETF Draft / CNCF spec, not a finalized RFC, but the README's standards
// table advertises support so the COMPLIANCE.md pattern applies.
//
// Happy-path coverage of the SPIFFE-format WIMSE URI is implicit in every
// test that issues a token (sub is a SPIFFE ID). This file pins the §2
// SPIFFE ID-shape MUSTs and the JWT-SVID §3 token-claim MUSTs.

package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issueSpiffeTestToken mints a baseline client_credentials token whose sub
// claim is a SPIFFE ID — the compliance tests then inspect its shape.
func issueSpiffeTestToken(t *testing.T) string {
	t.Helper()
	agentID := uid("compliance-spiffe")
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

// parsedSubject returns the sub claim of a newly-minted token.
func parsedSubject(t *testing.T, accessToken string) string {
	t.Helper()
	parsed, err := jwt.ParseInsecure([]byte(accessToken))
	require.NoError(t, err)
	sub, ok := parsed.Subject()
	require.True(t, ok, "issued token MUST carry sub")
	return sub
}

// ── SPIFFE-ID §2 — URI form ────────────────────────────────────────────────

func TestSPIFFE_S2_IDUsesSpiffeScheme(t *testing.T) {
	// SPIFFE-ID §2: "A SPIFFE ID is a structured string that takes the form
	//   spiffe://trust-domain/path."
	sub := parsedSubject(t, issueSpiffeTestToken(t))
	assert.True(t, strings.HasPrefix(sub, "spiffe://"),
		"sub MUST be a SPIFFE ID starting with the spiffe:// scheme; got %q", sub)
}

func TestSPIFFE_S2_2_TrustDomainIsLowercase(t *testing.T) {
	// SPIFFE-ID §2.2: "A trust domain is a name [whose] segments ... use
	//   lowercase letters, digits, and hyphens (DNS-style hostname format)."
	sub := parsedSubject(t, issueSpiffeTestToken(t))
	require.True(t, strings.HasPrefix(sub, "spiffe://"), "precondition")
	rest := strings.TrimPrefix(sub, "spiffe://")
	domain, _, _ := strings.Cut(rest, "/")
	assert.Equal(t, strings.ToLower(domain), domain,
		"trust domain MUST be lowercase; got %q", domain)
	for _, c := range domain {
		valid := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
		assert.Truef(t, valid,
			"trust-domain character %q is not in the SPIFFE allow-list (a-z 0-9 - .)", c)
	}
}

func TestSPIFFE_S3_1_IDUnder2048Bytes(t *testing.T) {
	// SPIFFE-ID §3.1: "Maximum SPIFFE ID length is 2048 bytes."
	// Existing test TestRFC9449... covers DPoP keys; this is the SPIFFE-side
	// guarantee. Issued tokens MUST carry a SPIFFE ID that fits the bound.
	sub := parsedSubject(t, issueSpiffeTestToken(t))
	assert.LessOrEqual(t, len(sub), 2048,
		"SPIFFE ID MUST be ≤2048 bytes per §3.1; got %d bytes", len(sub))
}

// ── JWT-SVID §3 — JWT-SVID token claims ─────────────────────────────────────

func TestJWTSVID_S3_AudClaimRequired(t *testing.T) {
	// JWT-SVID §3: "A JWT-SVID MUST contain ... aud (audience): identifies
	//   the recipient that the JWT-SVID is intended for."
	parsed, err := jwt.ParseInsecure([]byte(issueSpiffeTestToken(t)))
	require.NoError(t, err)
	aud, ok := parsed.Audience()
	require.True(t, ok, "aud MUST be present per JWT-SVID §3")
	assert.NotEmpty(t, aud, "aud MUST contain at least one value")
}

func TestJWTSVID_S3_SubIsSpiffeID(t *testing.T) {
	// JWT-SVID §3: "sub (subject): MUST contain the SPIFFE ID of the
	//   workload the JWT-SVID represents."
	parsed, err := jwt.ParseInsecure([]byte(issueSpiffeTestToken(t)))
	require.NoError(t, err)
	sub, ok := parsed.Subject()
	require.True(t, ok)
	assert.True(t, strings.HasPrefix(sub, "spiffe://"),
		"JWT-SVID sub MUST be a SPIFFE ID; got %q", sub)
}

func TestJWTSVID_S4_TrustBundlePublishesUseJwtSvid(t *testing.T) {
	// JWT-SVID §4: trust-bundle keys MUST advertise use=JWT-SVID. The
	// standard /.well-known/jwks.json uses use=sig for stock-OIDC
	// compatibility; SPIFFE-strict consumers fetch the dedicated trust
	// bundle endpoint which rewrites use to JWT-SVID.
	resp := get(t, "/.well-known/spiffe-trust-bundle.json", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	keys, ok := body["keys"].([]any)
	require.True(t, ok, "trust bundle MUST contain a keys array")
	require.NotEmpty(t, keys)
	for _, k := range keys {
		km, ok := k.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "JWT-SVID", km["use"],
			"every trust-bundle key MUST advertise use=JWT-SVID per JWT-SVID §4")
	}
}
