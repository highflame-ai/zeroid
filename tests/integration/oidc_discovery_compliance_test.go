// OpenID Connect Discovery 1.0 compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// ZeroID serves /.well-known/openid-configuration for FEDERATION TRUST
// ESTABLISHMENT, not for OIDC login — AWS IAM OIDC identity providers, Azure
// federated identity credentials and GCP workload identity pools all discover
// an external issuer's keyset through this path and not through RFC 8414's.
// See internal/handler/wellknown.go openidConfigurationOp.
//
// That purpose is why the ZeroID-policy tests at the bottom of this file matter
// as much as the spec clauses above them: a document that parses but names the
// wrong keys, or a document that quietly starts implying id_token issuance ZeroID
// does not do, both fail the reason the endpoint exists.

package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fetchOpenIDConfiguration returns the parsed JSON body of
// /.well-known/openid-configuration.
func fetchOpenIDConfiguration(t *testing.T) map[string]any {
	t.Helper()
	resp := get(t, "/.well-known/openid-configuration", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	return decode(t, resp)
}

// ── OIDC Discovery 1.0 §4 — Obtaining Provider Configuration Information ────

func TestOIDCDiscovery1_0_S4_WellKnownPathIsExact(t *testing.T) {
	// OIDC Discovery 1.0 §4: "openid-configuration MUST be the final path
	//   component" of the configuration information location, formed by
	//   concatenating /.well-known/openid-configuration to the Issuer.
	// The path is the whole contract here: every cloud federation consumer
	// hardcodes it, so serving the same document at any other path is
	// indistinguishable from not serving it at all.
	resp := get(t, "/.well-known/openid-configuration", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"GET /.well-known/openid-configuration MUST return 200")
}

func TestOIDCDiscovery1_0_S4_3_IssuerMatchesDiscoveryPrefix(t *testing.T) {
	// OIDC Discovery 1.0 §4.3: "The issuer value returned MUST be identical to
	//   the Issuer URL that was used as the prefix to /.well-known/
	//   openid-configuration to retrieve the configuration information."
	// AWS and Azure both re-derive the issuer from the URL they fetched and
	// refuse the provider when it disagrees, so a mismatch here is not a
	// pedantic failure — it is a federation that cannot be configured.
	body := fetchOpenIDConfiguration(t)
	assert.Equal(t, testIssuer, body["issuer"],
		"issuer MUST equal the prefix the document was fetched from")
}

// ── OIDC Discovery 1.0 §3 — OpenID Provider Metadata ───────────────────────

func TestOIDCDiscovery1_0_S3_SubjectTypesSupportedRequired(t *testing.T) {
	// OIDC Discovery 1.0 §3: "subject_types_supported REQUIRED. JSON array
	//   containing a list of the Subject Identifier types that this OP
	//   supports."
	body := fetchOpenIDConfiguration(t)
	subjectTypes, ok := body["subject_types_supported"].([]any)
	require.True(t, ok, "subject_types_supported REQUIRED")
	assert.Equal(t, []any{"public"}, subjectTypes,
		"ZeroID `sub` is the stable identity ID, identical for every verifier — "+
			"a pairwise subject would break the cloud role trust policies that "+
			"pin a literal `sub` value")
}

func TestOIDCDiscovery1_0_S3_IDTokenSigningAlgValuesSupportedRequired(t *testing.T) {
	// OIDC Discovery 1.0 §3: "id_token_signing_alg_values_supported REQUIRED.
	//   JSON array containing a list of the JWS signing algorithms (alg values)
	//   supported by the OP for the ID Token."
	body := fetchOpenIDConfiguration(t)
	algs, ok := body["id_token_signing_alg_values_supported"].([]any)
	require.True(t, ok, "id_token_signing_alg_values_supported REQUIRED")
	assert.NotEmpty(t, algs,
		"an issuer that signs nothing cannot be federated to — the member is "+
			"derived from the live keyset, so an empty list means the keyset is empty")
}

// ── ZeroID policy — why this endpoint exists ───────────────────────────────

func TestOIDCDiscovery_SigningAlgsMatchPublishedJWKS(t *testing.T) {
	// Not a spec clause. A federation verifier reads the alg list here and the
	// keys from jwks_uri, then rejects any token whose alg is not in the list.
	// If the two ever disagree the failure surfaces at token-verification time
	// in someone else's cloud, which is the most expensive place to debug it.
	// Deriving the list from the keyset is what prevents that; this test is what
	// keeps it derived.
	body := fetchOpenIDConfiguration(t)

	advertised := map[string]bool{}
	algs, _ := body["id_token_signing_alg_values_supported"].([]any)

	for _, a := range algs {
		alg, _ := a.(string)
		assert.NotEmpty(t, alg, "an empty alg name is not a JWA algorithm")
		advertised[alg] = true
	}

	published := map[string]bool{}

	for _, key := range fetchJWKSKeys(t) {
		if alg, ok := key["alg"].(string); ok && alg != "" {
			published[alg] = true
		}
	}

	require.NotEmpty(t, published, "the published keyset must name its algorithms")
	assert.Equal(t, published, advertised,
		"the advertised alg list MUST be exactly the algs in /.well-known/jwks.json")
}

func TestOIDCDiscovery_NeverAdvertisesIDToken(t *testing.T) {
	// Not a spec clause — the inverse. ZeroID issues no id_token, and this
	// document existing must not become evidence that it does. response_types_
	// supported is the structural guard: a relying party cannot request an
	// id_token without asking for one here, so as long as no id_token response
	// type is advertised, publishing OIDC metadata promises nothing ZeroID
	// cannot deliver.
	//
	// When id_token issuance lands, this test is the one that should fail — and
	// it should be deleted in the same PR that makes the claim true, not before.
	body := fetchOpenIDConfiguration(t)

	responseTypes, _ := body["response_types_supported"].([]any)
	for _, rt := range responseTypes {
		assert.NotContains(t, rt, "id_token",
			"ZeroID issues no id_token; advertising a response type that "+
				"requests one is a promise it cannot keep")
	}

	scopes, _ := body["scopes_supported"].([]any)
	assert.NotContains(t, scopes, "openid",
		"the openid scope is what requests an id_token (OIDC Core §3.1.2.1) — "+
			"advertising it would be the same broken promise")
}

func TestOIDCDiscovery_IsSupersetOfASMetadata(t *testing.T) {
	// Not a spec clause. ZeroID is one authorization server described by two
	// discovery documents, and RFC 8414 §5 permits exactly that. Two
	// hand-maintained documents is how they drift, so the OIDC document is
	// built from the RFC 8414 one plus the members OIDC additionally requires.
	// This pins that construction: every RFC 8414 member must appear here,
	// identically.
	asMeta := fetchASMetadata(t)
	oidcMeta := fetchOpenIDConfiguration(t)

	for member, want := range asMeta {
		got, present := oidcMeta[member]
		require.True(t, present,
			"%q is in the RFC 8414 document but missing from the OIDC document — "+
				"the two have drifted", member)
		assert.Equal(t, want, got,
			"%q disagrees between the two discovery documents for one AS", member)
	}
}

func TestOIDCDiscovery_OIDCOnlyMembersStayOutOfASMetadata(t *testing.T) {
	// Not a spec clause. The OIDC document is built by adding members to the
	// RFC 8414 document, so a shared or cached base map would let those
	// additions leak backwards into the RFC 8414 document — silently, and only
	// after the OIDC endpoint had been hit once. Fetch in that order, then
	// assert the leak did not happen.
	_ = fetchOpenIDConfiguration(t)

	asMeta := fetchASMetadata(t)
	assert.NotContains(t, asMeta, "subject_types_supported",
		"OIDC-only member leaked into the RFC 8414 document — the base map is shared")
	assert.NotContains(t, asMeta, "id_token_signing_alg_values_supported",
		"OIDC-only member leaked into the RFC 8414 document — the base map is shared")
}
