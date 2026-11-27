package service

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// propS256Reference is RFC 7636 §4.2's S256 written from the RFC's own
// definition rather than with the encoder verifyCodeChallenge uses:
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), where §2 defines base64url
// as the standard alphabet with '+' and '/' replaced and the '=' padding
// removed.
func propS256Reference(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	std := base64.StdEncoding.EncodeToString(sum[:])
	return strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(std), "=")
}

// propCodeVerifier draws an RFC 7636 §4.1 verifier, 43 to 128 unreserved
// characters, and sometimes any string at all.
func propCodeVerifier() *rapid.Generator[string] {
	unreserved := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
	return rapid.OneOf(
		rapid.StringOfN(rapid.SampledFrom(unreserved), 43, 128, -1),
		rapid.String(),
	)
}

// propFlipCase changes the case of one letter of s, or returns s when it has
// none.
func propFlipCase(t *rapid.T, s, label string) string {
	var letters []int
	for i := 0; i < len(s); i++ {
		if c := s[i] | 0x20; 'a' <= c && c <= 'z' {
			letters = append(letters, i)
		}
	}
	if len(letters) == 0 {
		return s
	}
	i := rapid.SampledFrom(letters).Draw(t, label)
	return s[:i] + string(s[i]^0x20) + s[i+1:]
}

// TestProperty_VerifyCodeChallenge_AcceptsExactlyS256: verifyCodeChallenge accepts a challenge iff it equals the reference S256 of the verifier, so plain, padded, standard-alphabet, case-folded, truncated, extended and altered challenges are all refused.
func TestProperty_VerifyCodeChallenge_AcceptsExactlyS256(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		verifier := propCodeVerifier().Draw(t, "verifier")
		want := propS256Reference(verifier)
		sum := sha256.Sum256([]byte(verifier))

		var challenge string
		switch rapid.IntRange(0, 9).Draw(t, "form") {
		case 0:
			challenge = want
		case 1:
			challenge = verifier // plain, which OAuth 2.1 removes
		case 2:
			challenge = base64.URLEncoding.EncodeToString(sum[:]) // padded
		case 3:
			challenge = base64.StdEncoding.EncodeToString(sum[:])
		case 4:
			i := rapid.IntRange(0, len(want)-1).Draw(t, "flip")
			c := want[i] ^ byte(rapid.IntRange(1, 0x3f).Draw(t, "xor"))
			challenge = want[:i] + string(c) + want[i+1:]
		case 5:
			challenge = propS256Reference(propCodeVerifier().Draw(t, "otherVerifier"))
		case 6:
			challenge = rapid.String().Draw(t, "random")
		case 7:
			challenge = propFlipCase(t, want, "caseFlip")
		case 8:
			challenge = want[:rapid.IntRange(0, len(want)-1).Draw(t, "cut")]
		case 9:
			challenge = want + rapid.SampledFrom([]string{"A", "-", "_", "=", " "}).Draw(t, "suffix")
		}

		if got := verifyCodeChallenge(verifier, challenge); got != (challenge == want) {
			t.Fatalf("verifyCodeChallenge(%q, %q) = %v, want %v (S256 %q)", verifier, challenge, got, challenge == want, want)
		}
	})
}
