// RFC 9728 (OAuth 2.0 Protected Resource Metadata) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// Happy-path coverage of /.well-known/oauth-protected-resource is folded into
// the §2 required-fields tests below — the document is small enough that the
// compliance suite doubles as smoke coverage. RFC 9728 is the discovery
// substrate every standards-track agent-auth draft (ID-JAG, identity-chaining,
// WIMSE workload identity) assumes: a 401 from the resource server points
// clients here, this document points them at the authorization server.

package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fetchPRMetadata returns the parsed JSON body of /.well-known/oauth-protected-resource.
func fetchPRMetadata(t *testing.T) map[string]any {
	t.Helper()
	resp := get(t, "/.well-known/oauth-protected-resource", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decode(t, resp)
}

// ── RFC 9728 §2 — Protected Resource Metadata ────────────────────────────────

func TestRFC9728_S2_ResourceRequired(t *testing.T) {
	// RFC 9728 §2: "resource REQUIRED. The protected resource's resource
	//   identifier, which is a URL that uses the https scheme and has no
	//   fragment components." Query is permitted; fragment is not.
	body := fetchPRMetadata(t)
	res, ok := body["resource"].(string)
	require.True(t, ok, "resource REQUIRED")
	assert.NotEmpty(t, res)
	assert.True(t, strings.HasPrefix(res, "https://"),
		"resource URL MUST use the https scheme (RFC 9728 §2) — caught a mis-configured BaseURL")
	assert.NotContains(t, res, "#", "resource URL MUST NOT have a fragment component")
}

func TestRFC9728_S2_AuthorizationServersListed(t *testing.T) {
	// RFC 9728 §2: "authorization_servers OPTIONAL. JSON array containing a
	//   list of OAuth authorization server issuer identifiers." When present,
	//   each entry MUST be a URL that uses the https scheme — these are the
	//   issuers a client SHOULD use to obtain access tokens for this resource.
	body := fetchPRMetadata(t)
	raw, ok := body["authorization_servers"].([]any)
	require.True(t, ok, "ZeroID advertises authorization_servers so clients can chain to AS metadata")
	require.NotEmpty(t, raw)
	for _, s := range raw {
		issuer, ok := s.(string)
		require.True(t, ok, "every authorization_servers entry MUST be a string")
		assert.True(t, strings.HasPrefix(issuer, "https://"),
			"authorization_servers entry MUST use https (RFC 9728 §2)")
		assert.NotContains(t, issuer, "#",
			"authorization_servers entry MUST NOT have a fragment (RFC 9728 §2)")
	}
}

func TestRFC9728_S2_BearerMethodsSupportedAdvertised(t *testing.T) {
	// RFC 9728 §2: "bearer_methods_supported OPTIONAL. JSON array containing
	//   a list of the supported methods of sending an OAuth 2.0 Bearer Token
	//   [RFC6750] to the protected resource. Defined values are 'header',
	//   'body', and 'query'." ZeroID accepts only the Authorization header,
	//   per RFC 6750 §2.1 best practice.
	body := fetchPRMetadata(t)
	raw, _ := body["bearer_methods_supported"].([]any)
	methods := make(map[string]bool, len(raw))
	for _, m := range raw {
		s, ok := m.(string)
		require.True(t, ok, "every bearer_methods_supported entry MUST be a string")
		methods[s] = true
	}
	assert.True(t, methods["header"],
		"bearer_methods_supported MUST advertise 'header' (RFC 6750 §2.1)")
	// ZeroID policy: query-string and form-encoded bearer tokens are not
	// accepted because they end up in access logs. Assert we don't
	// accidentally advertise them.
	assert.False(t, methods["query"],
		"ZeroID policy: 'query' MUST NOT be advertised — bearer tokens in URLs leak via logs")
}

func TestRFC9728_S2_JwksUriPointsAtASKeyset(t *testing.T) {
	// RFC 9728 §2: "jwks_uri OPTIONAL. URL of the protected resource's JWK
	//   Set [JWK] document." ZeroID's resource and AS share a keyset — the
	//   resource verifies tokens minted by the AS using the same JWKS, so
	//   the PRM advertises the AS keyset directly.
	body := fetchPRMetadata(t)
	jwks, _ := body["jwks_uri"].(string)
	require.NotEmpty(t, jwks, "ZeroID policy: jwks_uri required (exceeds RFC OPTIONAL)")
	assert.Contains(t, jwks, "/.well-known/jwks.json")
}

func TestRFC9728_S2_ResourceSigningAlgValuesSupportedListed(t *testing.T) {
	// RFC 9728 §2: "resource_signing_alg_values_supported OPTIONAL. JSON
	//   array containing a list of the JWS [JWS] signing algorithms (alg
	//   values) [JWA] supported by the protected resource for signed
	//   responses." ZeroID signs introspection responses and signed
	//   resource responses with the AS keyset, so the advertised algs
	//   MUST match the AS's signing algs.
	body := fetchPRMetadata(t)
	raw, _ := body["resource_signing_alg_values_supported"].([]any)
	require.NotEmpty(t, raw, "resource_signing_alg_values_supported expected when the resource signs responses")
	algs := make(map[string]bool, len(raw))
	for _, a := range raw {
		s, ok := a.(string)
		require.True(t, ok, "every resource_signing_alg_values_supported entry MUST be a string")
		algs[s] = true
	}
	assert.True(t, algs["ES256"], "ES256 MUST be advertised — ZeroID's default signing alg")
}

// ── RFC 9449 §5.3 — DPoP fields in PRM ──────────────────────────────────────

func TestRFC9449_S5_3_DPoPBoundAccessTokensRequiredAdvertised(t *testing.T) {
	// RFC 9449 §5.3: "dpop_bound_access_tokens_required: OPTIONAL. Boolean
	//   value specifying whether the protected resource always requires the
	//   use of DPoP-bound access tokens."
	// ZeroID accepts both bearer and DPoP-bound tokens today, so we
	// advertise false. Assert the field is present and boolean — it is the
	// only DPoP field RFC 9449 defines for PRM.
	body := fetchPRMetadata(t)
	required, ok := body["dpop_bound_access_tokens_required"].(bool)
	require.True(t, ok, "dpop_bound_access_tokens_required MUST be a boolean (RFC 9449 §5.3)")
	assert.False(t, required, "ZeroID currently accepts non-DPoP bearer tokens; flip when per-resource enforcement lands")
}

func TestRFC9449_S5_1_DPoPSigningAlgsAreASMetadataNotPRM(t *testing.T) {
	// RFC 9449 §5.1 defines dpop_signing_alg_values_supported as
	// *authorization server* metadata (algs the token endpoint will accept
	// on a DPoP proof). §5.3 — the PRM section — does not include this
	// field. Assert we don't accidentally leak it into PRM; the
	// /.well-known/oauth-authorization-server document is the only place
	// it belongs.
	prm := fetchPRMetadata(t)
	_, leaked := prm["dpop_signing_alg_values_supported"]
	assert.False(t, leaked,
		"dpop_signing_alg_values_supported is AS metadata (RFC 9449 §5.1), not PRM — it MUST NOT appear here")

	asMeta := fetchASMetadata(t)
	_, present := asMeta["dpop_signing_alg_values_supported"]
	assert.True(t, present,
		"dpop_signing_alg_values_supported MUST appear in AS metadata (RFC 9449 §5.1)")
}

// ── RFC 9728 §3 — Obtaining Protected Resource Metadata ─────────────────────

func TestRFC9728_S3_WellKnownPathIsExact(t *testing.T) {
	// RFC 9728 §3: "The path component of the metadata URL is
	//   /.well-known/oauth-protected-resource." Served as application/json.
	resp := get(t, "/.well-known/oauth-protected-resource", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"GET /.well-known/oauth-protected-resource MUST return 200")
	contentType := resp.Header.Get("Content-Type")
	assert.True(t, strings.HasPrefix(contentType, "application/json"),
		"PRM document MUST be served as application/json; got %q", contentType)
}

// ── Cross-document consistency ──────────────────────────────────────────────

func TestRFC9728_AuthorizationServersPointsAtASMetadata(t *testing.T) {
	// The whole point of RFC 9728 is to let an agent that hit a 401 chain
	// from the resource → PRM → AS metadata. Verify the issuer this PRM
	// advertises matches the issuer the AS metadata claims, so the chain
	// closes.
	prm := fetchPRMetadata(t)
	asMeta := fetchASMetadata(t)

	asIssuer, _ := asMeta["issuer"].(string)
	require.NotEmpty(t, asIssuer)

	advertised, _ := prm["authorization_servers"].([]any)
	require.NotEmpty(t, advertised)

	found := false
	for _, s := range advertised {
		if s.(string) == asIssuer {
			found = true
			break
		}
	}
	assert.True(t, found,
		"PRM's authorization_servers MUST include the AS metadata's issuer (%q) so the discovery chain closes",
		asIssuer)
}
