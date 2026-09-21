package middleware

import "strings"

// Authorization schemes ZeroID accepts on the credentials header.
//
// RFC 9110 §11.1 defines auth-scheme as a case-insensitive token, so a client
// may legally send "bearer", "BEARER", or "Bearer" and mean the same thing.
// Compare with ExtractAuthToken rather than strings.HasPrefix against a
// literal — a prefix match rejects two thirds of the legal spellings.
const (
	SchemeBearer = "Bearer"
	// SchemeDPoP is the RFC 9449 §7.1 scheme for a DPoP-bound access token.
	// ZeroID mints cnf.jkt and returns token_type "DPoP" whenever a proof
	// accompanies the token request (internal/service/credential.go), and
	// docs/dpop-and-dcr.md tells the client to present that token under this
	// scheme. Accept it anywhere such a token is a valid credential.
	SchemeDPoP = "DPoP"
)

// ExtractAuthToken splits an Authorization header value into its scheme and
// its credentials, and reports whether the scheme is one of accept.
//
// ok reports only that the scheme matched. The returned token may still be
// empty ("Bearer " with nothing after it), which callers reject separately —
// a malformed credential and an unsupported scheme are different RFC 6750
// §3.1 conditions and carry different error descriptions.
//
// scheme is the canonical spelling taken from accept, not the spelling the
// client sent, so a caller may compare it with ==.
//
// RFC 9110 §11.1 allows more than one space between the scheme and the
// credentials, so the credentials are trimmed before return.
func ExtractAuthToken(header string, accept ...string) (token, scheme string, ok bool) {
	rawScheme, credentials, found := strings.Cut(header, " ")
	if !found {
		return "", "", false
	}
	for _, want := range accept {
		if strings.EqualFold(rawScheme, want) {
			return strings.TrimSpace(credentials), want, true
		}
	}
	return "", "", false
}
