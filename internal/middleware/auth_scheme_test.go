package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractAuthToken(t *testing.T) {
	cases := []struct {
		name       string
		header     string
		accept     []string
		wantToken  string
		wantScheme string
		wantOK     bool
	}{
		// RFC 9110 §11.1 — auth-scheme is a case-insensitive token.
		{"canonical Bearer", "Bearer abc", []string{SchemeBearer}, "abc", SchemeBearer, true},
		{"lowercase bearer", "bearer abc", []string{SchemeBearer}, "abc", SchemeBearer, true},
		{"uppercase BEARER", "BEARER abc", []string{SchemeBearer}, "abc", SchemeBearer, true},
		{"mixed case BeArEr", "BeArEr abc", []string{SchemeBearer}, "abc", SchemeBearer, true},

		// RFC 9449 §7.1 — DPoP-bound tokens ride under the DPoP scheme.
		{"canonical DPoP", "DPoP abc", []string{SchemeBearer, SchemeDPoP}, "abc", SchemeDPoP, true},
		{"lowercase dpop", "dpop abc", []string{SchemeBearer, SchemeDPoP}, "abc", SchemeDPoP, true},

		// The canonical spelling is returned, never the client's spelling,
		// so callers may compare the result with ==.
		{"canonicalises the scheme", "dPoP abc", []string{SchemeDPoP}, "abc", SchemeDPoP, true},

		// A scheme outside accept is refused even when spelled correctly.
		{"DPoP not accepted here", "DPoP abc", []string{SchemeBearer}, "", "", false},
		{"Basic is not a token scheme", "Basic dXNlcjpwdw==", []string{SchemeBearer, SchemeDPoP}, "", "", false},

		// RFC 9110 §11.1 permits more than one space before the credentials.
		{"extra spaces are trimmed", "Bearer   abc", []string{SchemeBearer}, "abc", SchemeBearer, true},

		// ok reports the scheme match only. An empty credential still
		// matches, so the caller can emit its own "empty token" error.
		{"scheme with trailing space only", "Bearer ", []string{SchemeBearer}, "", SchemeBearer, true},

		// No space at all is not a credential.
		{"scheme with no credential", "Bearer", []string{SchemeBearer}, "", "", false},
		{"empty header", "", []string{SchemeBearer}, "", "", false},

		// A token that merely starts with the scheme name must not match.
		{"scheme is not a prefix match", "BearerToken abc", []string{SchemeBearer}, "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, scheme, ok := ExtractAuthToken(tc.header, tc.accept...)
			assert.Equal(t, tc.wantOK, ok, "ok")
			assert.Equal(t, tc.wantToken, token, "token")
			assert.Equal(t, tc.wantScheme, scheme, "scheme")
		})
	}
}

func TestAgentAuthMiddleware_SchemeHandling(t *testing.T) {
	const issuer = "https://issuer.test"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// The middleware resolves the verification key by kid from the JWKS
	// (#357), so the scheme tests publish a key set rather than one key.
	set := jwk.NewSet()
	addTestKey(t, set, &key.PublicKey, "ec-scheme", jwa.ES256())

	handler := AgentAuthMiddleware(AgentAuthConfig{
		KeySet: set,
		Issuer: issuer,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := mintKeySetToken(t, jwa.ES256(), key, "ec-scheme", issuer)

	cases := []struct {
		name       string
		authHeader string
		dpopProof  string
		wantStatus int
	}{
		{"canonical Bearer", "Bearer " + token, "", http.StatusOK},
		{"lowercase bearer", "bearer " + token, "", http.StatusOK},
		{"uppercase BEARER", "BEARER " + token, "", http.StatusOK},
		{"mixed case BeArEr", "BeArEr " + token, "", http.StatusOK},
		{"extra space after scheme", "Bearer  " + token, "", http.StatusOK},

		// RFC 9449 §7.1 — the DPoP scheme is accepted, but only together
		// with a proof header.
		{"DPoP scheme with proof", "DPoP " + token, "proof-jwt", http.StatusOK},
		{"lowercase dpop with proof", "dpop " + token, "proof-jwt", http.StatusOK},
		{"DPoP scheme without proof", "DPoP " + token, "", http.StatusUnauthorized},

		{"unknown scheme", "Token " + token, "", http.StatusUnauthorized},
		{"no credential after scheme", "Bearer ", "", http.StatusUnauthorized},
		{"absent header", "", "", http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.dpopProof != "" {
				req.Header.Set("DPoP", tc.dpopProof)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, tc.wantStatus, rec.Code)
		})
	}
}
