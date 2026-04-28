package authjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// allowedAlgs is the JWT-SVID §3 allow-list. "none" and HMAC variants are
// deliberately absent — presenting either MUST be rejected.
var allowedAlgs = map[string]struct{}{
	"ES256": {}, "ES384": {}, "ES512": {},
	"RS256": {}, "RS384": {}, "RS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
}

// validateAlg gates incoming tokens to the JWT-SVID §3 allow-list before any
// signature work runs. Defense-in-depth — a bundle published without per-key
// alg shouldn't widen what the verifier will accept.
func validateAlg(tokenStr string) error {
	dot := strings.IndexByte(tokenStr, '.')
	if dot <= 0 {
		return fmt.Errorf("%w: token is not a compact JWS", ErrInvalidToken)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tokenStr[:dot])
	if err != nil {
		return fmt.Errorf("%w: header is not valid base64url: %v", ErrInvalidToken, err)
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return fmt.Errorf("%w: header is not valid JSON: %v", ErrInvalidToken, err)
	}
	if hdr.Alg == "" {
		return fmt.Errorf("%w: alg header is missing", ErrInvalidToken)
	}
	if _, ok := allowedAlgs[hdr.Alg]; !ok {
		return fmt.Errorf("%w: %q is not in the JWT-SVID allow-list", ErrInvalidToken, hdr.Alg)
	}
	return nil
}
