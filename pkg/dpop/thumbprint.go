package dpop

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// JKT computes the RFC 7638 JWK Thumbprint of a public key, encoded as
// base64url-without-padding. This is the value bound to cnf.jkt in DPoP-bound
// access tokens.
//
// The thumbprint is over the canonical JSON of the key's required public
// members only (kty + alg-specific fields) — additional fields like kid,
// use, alg are not included, so two JWK serializations of the same public key
// yield the same thumbprint regardless of how the key was packaged.
//
// SHA-256 is used as the hash; RFC 7638 permits other hashes, but DPoP §6
// specifies SHA-256 for the cnf.jkt value, so this package is opinionated.
func JKT(key jwk.Key) (string, error) {
	if key == nil {
		return "", wrap(CodeInvalidProof, "cannot compute thumbprint: jwk is nil", nil)
	}
	pub, err := publicKeyOf(key)
	if err != nil {
		return "", wrap(CodeInvalidProof, "cannot extract public half of jwk", err)
	}
	raw, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", wrap(CodeInvalidProof, "thumbprint computation failed", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// publicKeyOf returns the public half of a JWK. If the input is already a
// public key, it's returned as-is; if it's a private key, the public counter-
// part is extracted. This guarantees the thumbprint is computed over the
// canonical public form regardless of which half the caller supplied.
//
// Defense-in-depth: DPoP proofs MUST embed only the public key in the JWK
// header. If a buggy client embeds a private key, computing the thumbprint
// over the public half is the right behavior; we still reject the proof
// elsewhere via validateProofHeader.
func publicKeyOf(key jwk.Key) (jwk.Key, error) {
	pub, err := jwk.PublicKeyOf(key)
	if err != nil {
		return nil, fmt.Errorf("public-key extraction: %w", err)
	}
	return pub, nil
}
