package oautherror

import "testing"

// TestConstantsAreNonEmpty documents the package's purpose and guards against
// an accidental empty-string declaration silently shipping (e.g. `const Foo = ""`
// would compile but emit a meaningless OAuth error code on the wire).
//
// Per-constant value assertions are intentionally not included: they would
// duplicate the const declarations in codes.go and add maintenance cost
// without catching real bugs. The authoritative reference is the RFC URL
// commented above each group in codes.go.
func TestConstantsAreNonEmpty(t *testing.T) {
	cases := map[string]string{
		// RFC 6749 §5.2
		"InvalidClient":        InvalidClient,
		"InvalidGrant":         InvalidGrant,
		"UnauthorizedClient":   UnauthorizedClient,
		"UnsupportedGrantType": UnsupportedGrantType,
		"InvalidScope":         InvalidScope,
		"ServerError":          ServerError,
		// RFC 6750 §3.1
		"InvalidRequest":    InvalidRequest,
		"InvalidToken":      InvalidToken,
		"InsufficientScope": InsufficientScope,
		// RFC 7591 §3.2.2 / RFC 7592 §2.3
		"InvalidClientMetadata":    InvalidClientMetadata,
		"InvalidRedirectURI":       InvalidRedirectURI,
		"InvalidSoftwareStatement": InvalidSoftwareStatement,
		// RFC 9396 §5.4
		"InvalidAuthorizationDetails": InvalidAuthorizationDetails,
		// RFC 9449 §5
		"InvalidDPoPProof": InvalidDPoPProof,
	}
	for name, val := range cases {
		if val == "" {
			t.Errorf("%s constant is empty; OAuth error codes must be non-empty wire-format strings", name)
		}
	}
}
