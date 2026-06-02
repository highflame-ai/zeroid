package dpop

// allowedAlgs is the DPoP signing-algorithm allow-list. Asymmetric only —
// "none" and HMAC variants are deliberately absent.
//
// Excluding HMAC variants is non-negotiable defense against algorithm-
// confusion attacks: if HS256 were allowed, an attacker could craft a proof
// signed with the public key bytes used as the HMAC secret, and the verifier
// — naively trusting the alg header — would accept it.
//
// EdDSA (Ed25519) is included as the modern best-practice signing algorithm:
// small key + signature, constant-time, no parameter-choice footguns.
var allowedAlgs = map[string]struct{}{
	"ES256": {},
	"ES384": {},
	"ES512": {},
	"EdDSA": {},
	"RS256": {},
	"RS384": {},
	"RS512": {},
	"PS256": {},
	"PS384": {},
	"PS512": {},
}

// AllowedAlgorithms returns a sorted copy of the alg allow-list. Useful for
// surfacing the policy in error responses / WWW-Authenticate hints.
func AllowedAlgorithms() []string {
	out := make([]string, 0, len(allowedAlgs))
	for a := range allowedAlgs {
		out = append(out, a)
	}
	// Stable order for tests + WWW-Authenticate readability.
	sortStrings(out)
	return out
}

// isAllowedAlg returns true if alg is in the allow-list. Single source of
// truth for both proof parsing (early-reject) and signature verification
// (defense-in-depth).
func isAllowedAlg(alg string) bool {
	_, ok := allowedAlgs[alg]
	return ok
}

// sortStrings is a tiny in-place insertion sort. We avoid importing sort here
// to keep this package's import surface minimal — the only allowed sort sites
// are deterministic test output and AllowedAlgorithms.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
