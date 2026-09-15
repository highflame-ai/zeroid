package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The HTTP auth-scheme token is case-insensitive (RFC 9110 §11.1), and a
// DPoP-bound access token is presented under the DPoP scheme rather than
// Bearer (RFC 9449 §7.1). These tests cover both rules on the forward-auth
// endpoint, which is the resource server for every proxied upstream.
// See issue #256.

// TestAuthVerify_SchemeIsCaseInsensitive checks that every legal spelling of
// the Bearer scheme is accepted, not only the canonical capitalisation.
func TestAuthVerify_SchemeIsCaseInsensitive(t *testing.T) {
	token := issueAPIKeyToken(t, uid("verify-scheme-case-agent"))

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		t.Run(scheme, func(t *testing.T) {
			resp := get(t, "/oauth2/token/verify", map[string]string{
				"Authorization": scheme + " " + token,
			})
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.NotEmpty(t, resp.Header.Get("X-Forwarded-User"))
		})
	}
}

// TestAuthVerify_ExtraSpaceAfterScheme checks that more than one space
// between the scheme and the credentials is tolerated — RFC 9110 §11.1
// allows 1*SP there, so the token must not be read with the spaces attached.
func TestAuthVerify_ExtraSpaceAfterScheme(t *testing.T) {
	token := issueAPIKeyToken(t, uid("verify-scheme-space-agent"))

	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Bearer   " + token,
	})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestAuthVerify_DPoPSchemeAccepted checks that a token presented under the
// RFC 9449 §7.1 DPoP scheme reaches introspection instead of being refused at
// the header parse. The proof header must accompany the scheme.
func TestAuthVerify_DPoPSchemeAccepted(t *testing.T) {
	token := issueAPIKeyToken(t, uid("verify-dpop-scheme-agent"))

	for _, scheme := range []string{"DPoP", "dpop", "DPOP"} {
		t.Run(scheme, func(t *testing.T) {
			resp := get(t, "/oauth2/token/verify", map[string]string{
				"Authorization": scheme + " " + token,
				"DPoP":          "proof-placeholder",
			})
			defer func() { _ = resp.Body.Close() }()

			// The token here is unbound (no cnf.jkt), so the request passes.
			// A bound token additionally has its proof validated — see the
			// sender-constraint work in #269 / #272.
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

// TestAuthVerify_DPoPSchemeWithoutProofRejected checks that the DPoP scheme
// cannot be used to present a token on weaker terms than Bearer. RFC 9449
// §7.1 pairs the scheme with a proof header, so the scheme alone is refused.
func TestAuthVerify_DPoPSchemeWithoutProofRejected(t *testing.T) {
	token := issueAPIKeyToken(t, uid("verify-dpop-noproof-agent"))

	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "DPoP " + token,
	})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAuthVerify_SchemeIsNotAPrefixMatch checks that a scheme token which
// merely starts with "Bearer" is refused. A prefix comparison would accept
// it; a token comparison does not.
func TestAuthVerify_SchemeIsNotAPrefixMatch(t *testing.T) {
	token := issueAPIKeyToken(t, uid("verify-scheme-prefix-agent"))

	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "BearerToken " + token,
	})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, expectedWWWAuth("invalid_request"), resp.Header.Get("WWW-Authenticate"))
}
