// Package jwtalg rejects JWTs whose alg isn't in the JWT-SVID §3 allow-list.
// Run Validate before jwx parses anything so alg=none / HS* dies up-front
// rather than depending on the verifier's defaults.
package jwtalg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupportedAlg covers both "alg outside the allow-list" and a malformed
// header. Maps to 400/401 — caller-fixable, not a server fault.
var ErrUnsupportedAlg = errors.New("unsupported JWT algorithm")

// allowed is the literal set from JWT-SVID §3. Note the absence of "none"
// and HS* — those are the things this whole file exists to reject.
var allowed = map[string]struct{}{
	"ES256": {}, "ES384": {}, "ES512": {},
	"RS256": {}, "RS384": {}, "RS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
}

// Validate decodes only the protected header (everything before the first
// ".") and checks alg against the allow-list. No signature work runs.
func Validate(tokenStr string) error {
	dot := strings.IndexByte(tokenStr, '.')
	if dot <= 0 {
		return fmt.Errorf("%w: token is not a compact JWS", ErrUnsupportedAlg)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tokenStr[:dot])
	if err != nil {
		return fmt.Errorf("%w: header is not valid base64url: %v", ErrUnsupportedAlg, err)
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return fmt.Errorf("%w: header is not valid JSON: %v", ErrUnsupportedAlg, err)
	}
	if hdr.Alg == "" {
		return fmt.Errorf("%w: alg header is missing", ErrUnsupportedAlg)
	}
	if _, ok := allowed[hdr.Alg]; !ok {
		return fmt.Errorf("%w: %q is not in the JWT-SVID allow-list", ErrUnsupportedAlg, hdr.Alg)
	}
	return nil
}
