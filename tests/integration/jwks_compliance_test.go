// RFC 7517 (JSON Web Key Set) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// Happy-path coverage of /.well-known/jwks.json lives in wellknown_test.go.
// This file pins the §4 per-key MUST/REQUIRED fields and the §4.2 / §4.3
// constraints on `use` / `alg` for every key the server publishes.

package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fetchJWKSKeys returns every key in /.well-known/jwks.json as a slice of
// the JSON map shape the test can inspect field-by-field.
func fetchJWKSKeys(t *testing.T) []map[string]any {
	t.Helper()
	resp := get(t, "/.well-known/jwks.json", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	rawKeys, ok := body["keys"].([]any)
	require.True(t, ok, "/.well-known/jwks.json MUST contain a 'keys' array")
	keys := make([]map[string]any, 0, len(rawKeys))
	for _, k := range rawKeys {
		km, ok := k.(map[string]any)
		require.True(t, ok, "every entry in the keys array MUST be an object")
		keys = append(keys, km)
	}
	require.GreaterOrEqual(t, len(keys), 1, "JWKS MUST publish at least one key")
	return keys
}

// ── RFC 7517 §4 — JWK Parameters ────────────────────────────────────────────

func TestRFC7517_S4_1_KtyRequired(t *testing.T) {
	// RFC 7517 §4.1: "The 'kty' (key type) parameter ... MUST be present
	//   in a JWK."
	for _, k := range fetchJWKSKeys(t) {
		assert.NotEmpty(t, k["kty"], "every JWK MUST carry kty")
	}
}

func TestRFC7517_S4_1_KtyIsRegisteredValue(t *testing.T) {
	// RFC 7517 §4.1: kty values come from the IANA JSON Web Key Types
	//   registry. ZeroID issues either EC (ECDSA) or RSA keys.
	allowed := map[string]bool{"EC": true, "RSA": true, "OKP": true, "oct": true}
	for _, k := range fetchJWKSKeys(t) {
		kty, _ := k["kty"].(string)
		assert.True(t, allowed[kty], "kty=%q not in the IANA registry", kty)
	}
}

func TestRFC7517_S4_2_UseIsSigForSigningKeys(t *testing.T) {
	// RFC 7517 §4.2: "Values defined by this specification are: 'sig' (signature)
	//   [and] 'enc' (encryption)." Every key ZeroID publishes is for signature
	//   verification — `use=sig` lets stock OIDC validators (PyJWT, jose, every
	//   WIF client) accept the bundle without extra config.
	for _, k := range fetchJWKSKeys(t) {
		assert.Equal(t, "sig", k["use"],
			"every JWKS key MUST advertise use=sig — keys with anything else (or no use) get rejected by stock validators")
	}
}

func TestRFC7517_S4_4_AlgRecommended(t *testing.T) {
	// RFC 7517 §4.4: "The 'alg' (algorithm) parameter ... is RECOMMENDED."
	// ZeroID sets it on every key so verifiers can pick the right algorithm
	// without inspecting kty.
	for _, k := range fetchJWKSKeys(t) {
		alg, _ := k["alg"].(string)
		assert.NotEmpty(t, alg, "alg SHOULD be set on every JWKS key (ZeroID makes it required)")
		assert.Contains(t, []string{"ES256", "RS256"}, alg,
			"ZeroID publishes only ES256 and RS256 keys")
	}
}

func TestRFC7517_S4_5_KidPresentForRollover(t *testing.T) {
	// RFC 7517 §4.5: "The 'kid' (key ID) parameter ... When used with JWS or
	//   JWE, the 'kid' value is used to match a specific key." ZeroID emits
	//   `kid` on every key so token verifiers can pick the right one
	//   during rollover.
	for _, k := range fetchJWKSKeys(t) {
		kid, _ := k["kid"].(string)
		assert.NotEmpty(t, kid, "every JWKS key MUST carry a kid for rollover-safe verification")
	}
}

// ── Private-key non-disclosure ──────────────────────────────────────────────

func TestRFC7517_NoPrivateKeyMaterialExposed(t *testing.T) {
	// RFC 7517 §6 / §8.4 (security considerations): publishing private-key
	// parameters defeats the entire point of the JWKS. The asymmetric private
	// components for the algs ZeroID uses are: ECDSA `d`, RSA `d`/`p`/`q`/
	// `dp`/`dq`/`qi`, OKP `d`, oct `k`. None may appear in a /.well-known/jwks.json.
	privateParams := []string{"d", "p", "q", "dp", "dq", "qi", "k"}
	for _, k := range fetchJWKSKeys(t) {
		for _, p := range privateParams {
			_, present := k[p]
			assert.False(t, present, "private-key parameter %q MUST NOT appear in JWKS", p)
		}
	}
}
