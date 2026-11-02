// RFC 9110 §11 (HTTP Authentication) + RFC 6750 §2.1 (Bearer credentials)
// compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows: one MUST per test,
// test name carries the RFC + section citation, first comment quotes the
// clause, and the file groups tests in RFC order.
//
// RFC 9110 §11 governs how EVERY credential ZeroID accepts is framed on the
// Authorization header, so it sits underneath RFC 6750 (Bearer), RFC 9449
// §7.1 (DPoP) and RFC 7591/7592 (DCR) alike. The clauses here are about the
// shape of the header — the scheme token and its separator — not about the
// credential inside it, which each of those suites covers.
//
// Happy-path coverage of the forward-auth endpoint lives in
// auth_verify_test.go. This file is the negative-space proof, plus the
// case-variant matrix that no single happy-path test can express.
//
// Regression origin: issue #256. Four call sites compared the header against
// the literal "Bearer " with HasPrefix/TrimPrefix/CutPrefix, so three of the
// four legal spellings of the scheme were refused.

package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bearerProtectedPath is the forward-auth endpoint. It reads the credential
// straight off the Authorization header and introspects it, so it is the
// shortest path from a header spelling to an accept/reject decision.
func bearerProtectedPath() string { return "/oauth2/token/verify" }

// ── RFC 9110 §11.1 — Authentication Scheme ──────────────────────────────────

func TestRFC9110_S11_1_SchemeIsCaseInsensitive(t *testing.T) {
	// RFC 9110 §11.1: "The authentication scheme is a case-insensitive token."
	// Every spelling below denotes the same scheme and MUST be accepted
	// identically.
	token := issueAPIKeyToken(t, uid("rfc9110-case"))

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr", "bEaReR"} {
		t.Run(scheme, func(t *testing.T) {
			resp := get(t, bearerProtectedPath(), map[string]string{
				"Authorization": scheme + " " + token,
			})
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode,
				"scheme %q is the same scheme as %q and must be accepted", scheme, "Bearer")
		})
	}
}

func TestRFC9110_S11_1_SchemeIsATokenNotAPrefix(t *testing.T) {
	// RFC 9110 §11.1: "credentials = auth-scheme [ 1*SP ( token68 / ... ) ]"
	// — auth-scheme is a whole token delimited by SP, so "BearerToken" is a
	// DIFFERENT scheme, not the Bearer scheme with extra characters. A server
	// that matches by prefix would accept it.
	token := issueAPIKeyToken(t, uid("rfc9110-prefix"))

	resp := get(t, bearerProtectedPath(), map[string]string{
		"Authorization": "BearerToken " + token,
	})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"BearerToken is a distinct auth-scheme and must not be read as Bearer")
}

func TestRFC9110_S11_1_SchemeAndCredentialsSeparatedBy1SP(t *testing.T) {
	// RFC 9110 §11.1: "credentials = auth-scheme [ 1*SP ... ]" — one OR MORE
	// spaces. The extra spaces are the delimiter, so they MUST NOT become part
	// of the credential.
	token := issueAPIKeyToken(t, uid("rfc9110-sp"))

	for name, header := range map[string]string{
		"one space":    "Bearer " + token,
		"two spaces":   "Bearer  " + token,
		"three spaces": "Bearer   " + token,
	} {
		t.Run(name, func(t *testing.T) {
			resp := get(t, bearerProtectedPath(), map[string]string{
				"Authorization": header,
			})
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode,
				"1*SP is the delimiter and must not be read as part of the token")
		})
	}
}

func TestRFC9110_S11_1_UnknownSchemeIsRejected(t *testing.T) {
	// RFC 9110 §11.1: a server MUST ignore or reject credentials whose
	// auth-scheme it does not support. Case-insensitivity widens the spellings
	// of a KNOWN scheme; it must not admit an unknown one.
	token := issueAPIKeyToken(t, uid("rfc9110-unknown"))

	for _, scheme := range []string{"Basic", "Negotiate", "Token", "JWT"} {
		t.Run(scheme, func(t *testing.T) {
			resp := get(t, bearerProtectedPath(), map[string]string{
				"Authorization": scheme + " " + token,
			})
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
				"scheme %q is not supported on this endpoint", scheme)
		})
	}
}

// ── RFC 6750 §2.1 — Authorization Request Header Field ──────────────────────

func TestRFC6750_S2_1_EmptyCredentialIsRejected(t *testing.T) {
	// RFC 6750 §2.1: "credentials = "Bearer" 1*SP b64token" — b64token is
	// 1*(...), so it cannot be empty. A scheme with nothing after it is a
	// malformed request, not a token to validate.
	resp := get(t, bearerProtectedPath(), map[string]string{
		"Authorization": "Bearer ",
	})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRFC6750_S3_1_UnsupportedSchemeIsInvalidRequest(t *testing.T) {
	// RFC 6750 §3.1: invalid_request is "The request is missing a required
	// parameter, includes an unsupported parameter or parameter value,
	// [or] is otherwise malformed." A credential in an unsupported scheme is
	// malformed — it is NOT invalid_token, which is reserved for a
	// syntactically valid credential that fails validation.
	token := issueAPIKeyToken(t, uid("rfc6750-errcode"))

	resp := get(t, bearerProtectedPath(), map[string]string{
		"Authorization": "Basic " + token,
	})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, expectedWWWAuth("invalid_request"), resp.Header.Get("WWW-Authenticate"))
}
