package integration_test

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntrospectRejectsAlgNone is the alg-none / HS* defense-in-depth check.
// We hand the introspect endpoint a token whose header advertises alg=none
// and expect active:false. Without the JWT-SVID §3 allow-list this would
// fall through to the verifier's alg-handling defaults — safe today, but a
// future change to how keys are published could regress that.
func TestIntrospectRejectsAlgNone(t *testing.T) {
	cases := []struct {
		name string
		alg  string
	}{
		{"alg_none_lowercase", "none"},
		{"alg_none_capitalized", "None"},
		{"alg_hs256", "HS256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := craftUnsignedJWT(tc.alg, `{"sub":"attacker","iss":"https://attacker.example"}`)

			result := introspect(t, token)
			active, _ := result["active"].(bool)
			assert.False(t, active, "introspect must return active:false for %s; got %#v", tc.alg, result)
		})
	}
}

// TestVerifyEndpointRejectsAlgNone covers the same path through the
// reverse-proxy /oauth2/token/verify endpoint, which proxies tend to wire
// up before any application code runs. A mistake here would let an attacker
// bypass auth entirely.
func TestVerifyEndpointRejectsAlgNone(t *testing.T) {
	token := craftUnsignedJWT("none", `{"sub":"attacker"}`)

	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Bearer " + token,
	})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"alg=none token must be rejected with 401 at the verify endpoint")
}

// craftUnsignedJWT builds a compact JWS with the given alg header and an
// empty signature. The payload is the raw JSON literal supplied by the
// caller — we don't sign anything, the whole point is the alg field.
func craftUnsignedJWT(alg, payloadJSON string) string {
	header := `{"alg":"` + alg + `","typ":"JWT"}`
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(payloadJSON)) + "."
}
