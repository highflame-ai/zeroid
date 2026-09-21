package integration_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Zero-element claims are prohibited in every discovery document ZeroID
// publishes. RFC 8414 §2 and OpenID Connect Discovery 1.0 §3 use identical
// wording — "Claims with zero elements MUST be omitted from the response" — and
// RFC 9728 §2 inherits it for protected-resource metadata.
//
// These tests sweep the WHOLE document rather than naming the members that were
// wrong when zeroid#316 was filed. That is deliberate: the three offenders
// (response_types_supported,
// backchannel_authentication_request_signing_alg_values_supported,
// id_token_signing_alg_values_supported) were each written by someone who had
// read the RFC and still emitted []. A test that lists them proves those three
// are fixed; a test that walks every member proves the DOCUMENT is conformant,
// and catches member number four without anyone remembering this file exists.

// requireNoZeroElementClaims asserts no member of a discovery document is an
// empty JSON array.
//
// Only arrays are checked. `false` and 0 are meaningful values for boolean and
// numeric claims — backchannel_user_code_parameter_supported and
// dpop_bound_access_tokens_required are both legitimately false — and the spec
// clause is specifically about claims that "return multiple values", i.e. the
// ones represented as JSON arrays.
func requireNoZeroElementClaims(t *testing.T, doc map[string]any, what string) {
	t.Helper()

	require.NotEmpty(t, doc, "%s returned an empty document", what)

	for name, value := range doc {
		arr, isArray := value.([]any)
		if !isArray {
			continue
		}

		require.NotEmpty(t, arr,
			"%s: claim %q is a zero-element array; RFC 8414 §2 / OIDC Discovery "+
				"§3 require it to be omitted from the response entirely "+
				"(zeroid#316). Emit the member only when it has a value.",
			what, name)
	}
}

// TestDiscovery_NoZeroElementClaims_Servable covers the ordinary posture: this
// suite registers PrincipalResolvers, so the authorization_code flow is
// servable and response_types_supported carries a value.
func TestDiscovery_NoZeroElementClaims_Servable(t *testing.T) {
	requireNoZeroElementClaims(t, fetchASMetadata(t),
		"/.well-known/oauth-authorization-server")
	requireNoZeroElementClaims(t, fetchOpenIDConfiguration(t),
		"/.well-known/openid-configuration")
	requireNoZeroElementClaims(t, fetchPRMetadata(t),
		"/.well-known/oauth-protected-resource")
}

// TestDiscovery_NoZeroElementClaims_Unservable covers the posture that actually
// produced the bug. With no PrincipalResolver the authorization_code flow
// cannot be served, response_types_supported has nothing to list, and the old
// code published it as []. Without flipping the predicate this whole class of
// defect is unreachable from the integration suite, since every test here
// shares one server that has resolvers registered.
//
// Safe to mutate shared state: no integration test calls t.Parallel().
func TestDiscovery_NoZeroElementClaims_Unservable(t *testing.T) {
	testZeroIDServer.SetAuthorizationCodeAvailable(func() bool { return false })
	defer testZeroIDServer.SetAuthorizationCodeAvailable(nil)

	asMeta := fetchASMetadata(t)

	// Guard against the test passing for the wrong reason. If the predicate
	// stopped taking effect, this posture would silently become identical to
	// the servable one and the sweep below would prove nothing about the case
	// it exists to cover.
	require.NotContains(t, asMeta, "response_types_supported",
		"the flow is unservable here, so the member must have been omitted — "+
			"if it is present, the predicate did not take effect and this test "+
			"is no longer exercising the unservable posture")

	requireNoZeroElementClaims(t, asMeta,
		"/.well-known/oauth-authorization-server (authorization_code unservable)")
	requireNoZeroElementClaims(t, fetchOpenIDConfiguration(t),
		"/.well-known/openid-configuration (authorization_code unservable)")
	requireNoZeroElementClaims(t, fetchPRMetadata(t),
		"/.well-known/oauth-protected-resource (authorization_code unservable)")
}
