package dpop

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// proofTypeHeader is the required value of the JOSE typ header for DPoP
// proofs, per RFC 9449 §4.2.
const proofTypeHeader = "dpop+jwt"

// Proof is the parsed, signature-verified representation of a DPoP proof JWT.
// Construction goes through parseAndVerify — outside that function, every
// instance of Proof has had its signature checked against its embedded key
// and its algorithm validated against the allow-list. Validation of htm,
// htu, iat, jti, ath, bh, and cnf.jkt happens later, against a specific
// request, in the Verifier.
type Proof struct {
	// Alg is the signing algorithm (e.g. "ES256", "EdDSA"). Already
	// guaranteed to be in the allow-list.
	Alg string

	// JWK is the public key used to sign the proof, embedded in the JWS
	// header. Guaranteed to be a public key (validated during parse).
	JWK jwk.Key

	// Thumbprint is the RFC 7638 JWK thumbprint of JWK, encoded as
	// base64url-no-padding. This is the value bound to cnf.jkt in any
	// access token issued or accepted on the same request.
	Thumbprint string

	// JTI is the proof's unique identifier (RFC 9449 §4.2 jti claim).
	// Required; empty values are rejected during parse. Already gated to
	// the configured max length so the downstream replay store can store
	// it without truncation surprises.
	JTI string

	// HTM is the HTTP method the proof asserts coverage of.
	HTM string

	// HTU is the HTTP URL the proof asserts coverage of. Already normalized
	// by parseAndVerify (query, fragment, scheme+host case, default port).
	HTU string

	// IssuedAt is the iat claim parsed as time.Time.
	IssuedAt time.Time

	// ExpiresAt is the optional exp claim (RFC 7519). Zero when the proof
	// has no exp claim. RFC 9449 §4.2 permits but does not require exp;
	// when present the verifier enforces it so an explicitly-expired proof
	// cannot succeed on the iat freshness check alone.
	ExpiresAt time.Time

	// NotBefore is the optional nbf claim (RFC 7519). Zero when absent.
	NotBefore time.Time

	// ATH is the optional access-token-hash claim (base64url(sha256(token))).
	// Empty when not present on the proof.
	ATH string

	// BH is the optional body-hash claim from the bh extension
	// (base64url(sha256(body))). Empty when not present on the proof.
	BH string

	// Nonce is the optional server-supplied freshness nonce (RFC 9449 §9).
	// Empty when not present on the proof.
	Nonce string
}

// proofClaims is the JSON payload of a DPoP proof. Mirrors RFC 9449 §4.2
// plus the optional RFC 7519 exp/nbf claims (enforced when present) and
// the bh extension claim.
type proofClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Exp   int64  `json:"exp,omitempty"`
	Nbf   int64  `json:"nbf,omitempty"`
	ATH   string `json:"ath,omitempty"`
	BH    string `json:"bh,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// parseAndVerify parses a compact-JWS-encoded DPoP proof, validates its
// structural form (typ, alg allow-list, embedded jwk), and verifies the
// signature against the embedded key. All header-level rejection reasons
// surface here; per-request validation (htm/htu/iat/jti/ath/bh) lives in
// the Verifier.
//
// The function deliberately splits header parse → header validate →
// signature verify → payload parse so that algorithm-confusion attempts
// die before any cryptographic work is done.
//
// maxJTILen caps the jti claim — oversized values are rejected as malformed
// proofs (4xx) rather than allowed to surface from the downstream store as
// truncation errors (which a column-bound store would otherwise mis-map to
// 5xx). Zero disables the check.
func parseAndVerify(raw string, normalizeURL func(string) string, maxJTILen int) (*Proof, error) {
	if raw == "" {
		return nil, withCause(ErrInvalidProof, errors.New("proof is empty"))
	}

	// 1. Parse compact JWS structurally. Does not verify the signature.
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		return nil, wrap(CodeInvalidProof, "proof is not a valid compact JWS", err)
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		// RFC 9449 §4.2: proofs are single-signature.
		return nil, wrap(CodeInvalidProof, fmt.Sprintf("proof must have exactly one signature; got %d", len(sigs)), nil)
	}
	hdr := sigs[0].ProtectedHeaders()

	// 2. typ must be exactly "dpop+jwt".
	typ, ok := hdr.Type()
	if !ok {
		return nil, wrap(CodeInvalidProof, "proof header missing typ", nil)
	}
	if typ != proofTypeHeader {
		return nil, wrap(CodeInvalidProof, fmt.Sprintf("proof typ must be %q; got %q", proofTypeHeader, typ), nil)
	}

	// 3. alg must be present and in the allow-list. Reject alg=none and HS*
	//    before we touch the signature — defense against algorithm confusion.
	algObj, ok := hdr.Algorithm()
	if !ok {
		return nil, wrap(CodeInvalidProof, "proof header missing alg", nil)
	}
	alg := algObj.String()
	if !isAllowedAlg(alg) {
		return nil, wrap(CodeUnsupportedAlg, fmt.Sprintf("alg %q is not in the allow-list", alg), nil)
	}

	// 4. jwk must be present, public-only (no private material, no symmetric
	//    keys), and match the alg.
	embedded, ok := hdr.JWK()
	if !ok || embedded == nil {
		return nil, wrap(CodeInvalidProof, "proof header missing jwk", nil)
	}
	if isPrivateJWK(embedded) {
		// RFC 9449 §4.2: "the jwk header parameter must contain the public key"
		return nil, wrap(CodeInvalidProof, "proof jwk must be a public key; private material rejected", nil)
	}
	if _, sym := embedded.(jwk.SymmetricKey); sym {
		// Defense-in-depth: an oct JWK in the jwk header is shared-secret
		// material. The alg allow-list at step 3 already excludes HS*, but
		// the explicit symmetric-key check keeps the policy honest if a
		// future jwx version adds an asymmetric alg paired with a symmetric
		// key shape.
		return nil, wrap(CodeInvalidProof, "proof jwk must not be a symmetric key", nil)
	}
	if !algMatchesKey(alg, embedded) {
		return nil, wrap(CodeInvalidProof, fmt.Sprintf("alg %q does not match jwk key type %q", alg, embedded.KeyType()), nil)
	}

	// 5. Verify the signature against the embedded key. This is where the
	//    actual cryptographic work happens.
	payload, err := jws.Verify([]byte(raw), jws.WithKey(algObj, embedded))
	if err != nil {
		return nil, withCause(ErrInvalidSignature, err)
	}

	// 6. Parse claims. Strict — unknown fields are tolerated (forward-compat
	//    with future spec additions) but every required field must be present.
	var claims proofClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, wrap(CodeInvalidProof, "proof payload is not valid JSON", err)
	}
	if claims.JTI == "" {
		return nil, wrap(CodeInvalidProof, "proof missing jti", nil)
	}
	if maxJTILen > 0 && len(claims.JTI) > maxJTILen {
		// Bounded so an oversized JTI surfaces as 4xx (malformed proof), not as
		// a store-side truncation error that a column-bound ReplayStore would
		// otherwise mis-map to 5xx.
		return nil, wrap(CodeInvalidProof, fmt.Sprintf("proof jti exceeds %d bytes", maxJTILen), nil)
	}
	if claims.HTM == "" {
		return nil, wrap(CodeInvalidProof, "proof missing htm", nil)
	}
	if claims.HTU == "" {
		return nil, wrap(CodeInvalidProof, "proof missing htu", nil)
	}
	if claims.IAT == 0 {
		return nil, wrap(CodeInvalidProof, "proof missing iat", nil)
	}

	// 7. Compute the thumbprint once, here, while we hold a verified key.
	//    Done BEFORE the verifier's replay-store insert so a thumbprint
	//    computation failure (vanishingly unlikely past jws.Verify) does
	//    not leave the jti consumed.
	thumb, err := JKT(embedded)
	if err != nil {
		return nil, err
	}

	htu := claims.HTU
	if normalizeURL != nil {
		htu = normalizeURL(htu)
	}

	p := &Proof{
		Alg:        alg,
		JWK:        embedded,
		Thumbprint: thumb,
		JTI:        claims.JTI,
		HTM:        claims.HTM,
		HTU:        htu,
		IssuedAt:   time.Unix(claims.IAT, 0),
		ATH:        claims.ATH,
		BH:         claims.BH,
		Nonce:      claims.Nonce,
	}
	if claims.Exp != 0 {
		p.ExpiresAt = time.Unix(claims.Exp, 0)
	}
	if claims.Nbf != 0 {
		p.NotBefore = time.Unix(claims.Nbf, 0)
	}
	return p, nil
}

// isPrivateJWK reports whether the JWK carries private-key material. Used to
// reject proofs whose JOSE header leaks a private key — a buggy-client
// indicator, never a legitimate proof shape.
func isPrivateJWK(k jwk.Key) bool {
	switch k.(type) {
	case jwk.RSAPrivateKey,
		jwk.ECDSAPrivateKey,
		jwk.OKPPrivateKey:
		return true
	}
	return false
}

// algMatchesKey reports whether alg is a compatible signing algorithm for the
// given JWK key type. Defense-in-depth: jws.Verify will reject the signature
// either way, but rejecting here gives a more diagnostic error and skips the
// crypto work for an obviously-wrong combination.
func algMatchesKey(alg string, k jwk.Key) bool {
	switch k.KeyType() {
	case jwa.EC():
		// EC keys sign ES* only.
		return alg == "ES256" || alg == "ES384" || alg == "ES512"
	case jwa.RSA():
		// RSA keys sign RS* and PS*.
		switch alg {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			return true
		}
		return false
	case jwa.OKP():
		// OKP (Ed25519/Ed448) signs EdDSA.
		return alg == "EdDSA"
	}
	return false
}
