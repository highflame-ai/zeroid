// RFC 9728 §5.1 (WWW-Authenticate Response) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// RFC 9728 §5.1 defines the `resource_metadata` parameter — carried in the
// WWW-Authenticate header that a Bearer-protected resource returns on 401 —
// as "The URL of the protected resource metadata." This is the breadcrumb
// that lets a cold-start client (one that didn't already know the well-known
// URL) chain resource → PRM → AS metadata per spec.
//
// PR-162's PRM endpoint shipped a negative-pin test asserting the breadcrumb
// was NOT yet emitted. This PR flips that path: every 401 from a Bearer-
// protected ZeroID endpoint MUST now include the parameter.

package integration_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prmURL returns the URL the breadcrumb should point at, derived from the
// test harness's testIssuer (which serves as both iss claim and endpoint
// URL prefix per RFC 8414 §3).
func prmURL() string {
	return testIssuer + "/.well-known/oauth-protected-resource"
}

// resourceMetadataParamRE extracts the `resource_metadata="<url>"` parameter
// from a WWW-Authenticate header value. Matches the RFC 7235 §2.1
// quoted-string shape: the parameter name, "=", and a double-quoted value.
var resourceMetadataParamRE = regexp.MustCompile(`resource_metadata="([^"]+)"`)

// extractResourceMetadata returns the URL inside the resource_metadata
// parameter, or empty string if the parameter is absent.
func extractResourceMetadata(wwwAuthenticate string) string {
	m := resourceMetadataParamRE.FindStringSubmatch(wwwAuthenticate)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// ── RFC 9728 §5.1 — bearer-auth middleware path ─────────────────────────────

// agentAuthProtectedPath is a POST endpoint mounted inside the agent-auth
// middleware sub-group — POSTing to it exercises the middleware's 401
// emission path. The agent-auth group lives under the admin path prefix
// (adminPath("...")) so the full URL is "/api/v1/proof/generate".
func agentAuthProtectedPath() string { return adminPath("/proof/generate") }

func TestRFC9728_S5_1_AgentAuthMiddleware_EmitsBreadcrumbOnMissingAuth(t *testing.T) {
	// Probe an agent-auth-protected endpoint with no Authorization header
	// — the AgentAuthMiddleware MUST return 401 with the RFC 9728 §5.1
	// resource_metadata parameter so a cold-start client can discover PRM.
	resp := post(t, agentAuthProtectedPath(), map[string]any{}, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"bearer-protected endpoint with no auth MUST 401")

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	require.NotEmpty(t, wwwAuth,
		"401 MUST include a WWW-Authenticate challenge (RFC 6750 §3 / RFC 9728 §5.1)")

	url := extractResourceMetadata(wwwAuth)
	require.NotEmpty(t, url,
		"WWW-Authenticate MUST include the resource_metadata parameter (RFC 9728 §5.1); got %q", wwwAuth)
	assert.Equal(t, prmURL(), url,
		"resource_metadata MUST point at {issuer}/.well-known/oauth-protected-resource")
}

func TestRFC9728_S5_1_AgentAuthMiddleware_EmitsBreadcrumbOnInvalidToken(t *testing.T) {
	// Same path but with a bogus Bearer token — must still get the
	// breadcrumb. The error code is "invalid_token" per RFC 6750 §3.1.
	resp := post(t, agentAuthProtectedPath(), map[string]any{}, map[string]string{
		"Authorization": "Bearer not-a-real-token",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	require.NotEmpty(t, wwwAuth)

	assert.Equal(t, prmURL(), extractResourceMetadata(wwwAuth),
		"resource_metadata MUST point at PRM URL on invalid-token 401 as well")

	// RFC 6750 §3.1: error parameter MUST be one of invalid_request,
	// invalid_token, insufficient_scope on a 401.
	assert.Contains(t, wwwAuth, `error="invalid_token"`,
		"WWW-Authenticate MUST advertise error=invalid_token for a bogus bearer (RFC 6750 §3.1)")
}

// ── RFC 9728 §5.1 — DCR auth path ───────────────────────────────────────────

func TestRFC9728_S5_1_DCR_EmitsBreadcrumbOnInvalidToken(t *testing.T) {
	// DCR with a bogus initial access token — handler reaches dcrErr and
	// emits the breadcrumb via DCROutput.WWWAuthenticate. (We don't probe
	// the "no Authorization header" path because huma rejects it with 422
	// at input validation time — required:"true" on the Authorization
	// field — before the handler runs, so the breadcrumb has no
	// emission site to inject from.)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "test-bogus-iat",
	}, map[string]string{
		"Authorization": "Bearer not-a-real-iat",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"DCR with bogus initial access token MUST 401")

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	require.NotEmpty(t, wwwAuth,
		"DCR 401 MUST include WWW-Authenticate with resource_metadata")
	assert.Equal(t, prmURL(), extractResourceMetadata(wwwAuth),
		"DCR resource_metadata MUST point at PRM URL")
}

// ── RFC 9728 §5.1 — forward-auth verify path ─────────────────────────────────

func TestRFC9728_S5_1_AuthVerify_EmitsBreadcrumbOnMissingAuth(t *testing.T) {
	// GET /oauth2/token/verify is the reverse-proxy forward-auth endpoint.
	// It emits its own WWW-Authenticate on 401; PR-E adds the
	// resource_metadata parameter to each of its 3 emission sites.
	resp := get(t, "/oauth2/token/verify", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	require.NotEmpty(t, wwwAuth)
	assert.Equal(t, prmURL(), extractResourceMetadata(wwwAuth),
		"forward-auth verify MUST include resource_metadata on 401")
}

// ── RFC 6750 §3 — challenge shape stays well-formed ──────────────────────────

func TestRFC6750_S3_ChallengeShape_BearerSchemeFirst(t *testing.T) {
	// RFC 6750 §3: "The WWW-Authenticate response header field uses the
	//   framework defined by HTTP/1.1, Section 4.1 [RFC7235] as follows:
	//   challenge = 'Bearer' [ 1*SP 1#auth-param ]"
	// Verify our breadcrumb-augmented challenge still starts with "Bearer"
	// followed by a space and parameters, i.e. it's parseable by stock
	// OAuth clients that key off the scheme.
	resp := post(t, agentAuthProtectedPath(), map[string]any{}, nil)
	defer resp.Body.Close()
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	require.NotEmpty(t, wwwAuth)
	assert.True(t, strings.HasPrefix(wwwAuth, "Bearer "),
		`challenge MUST start with "Bearer " (RFC 6750 §3); got %q`, wwwAuth)
}

// ── PRM endpoint reachability via the breadcrumb ────────────────────────────

func TestRFC9728_S5_1_BreadcrumbURLShapeIsWellFormed(t *testing.T) {
	// The breadcrumb URL must be parseable and follow RFC 9728 §3's
	// well-known anchoring. We assert URL shape here, not that it resolves
	// — PR-E is branched off PR-D, which is independent of PR-A's PRM
	// endpoint. When this branch rebases against a main that has PR-A
	// merged, a separate test can extend this to fetch the URL and
	// confirm 200.
	resp := post(t, agentAuthProtectedPath(), map[string]any{}, nil)
	defer resp.Body.Close()
	url := extractResourceMetadata(resp.Header.Get("WWW-Authenticate"))
	require.NotEmpty(t, url)
	assert.True(t, strings.HasPrefix(url, testIssuer),
		"resource_metadata MUST live under the issuer URL (RFC 9728 §3 well-known anchoring)")
	assert.True(t, strings.HasSuffix(url, "/.well-known/oauth-protected-resource"),
		"resource_metadata MUST end with /.well-known/oauth-protected-resource (RFC 9728 §3)")
}
