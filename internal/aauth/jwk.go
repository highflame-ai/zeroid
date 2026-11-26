// Package aauth is ZeroID's AAuth Agent Provider: it turns a workload's
// platform identity token into an AAuth agent token (aa-agent+jwt) bound to
// the agent's own key, and lets that agent token be exchanged for a
// DPoP-bound OAuth access token at the token endpoint (bridge.go).
//
// Everything AAuth lives here. It reuses ZeroID rather than running beside
// it: the workload checks are the federated grant's (service.VerifyWorkload-
// Assertion), and agent tokens are issued through IssueCredential, so they
// are ordinary issued_credentials rows that policy, listing, revocation and
// audit already cover.
//
// Spec baseline: the AAuth protocol and bootstrap editor's drafts linked from
// aauth.dev, and draft-hardt-httpbis-signature-key-09.
package aauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Algorithm identifiers (fully specified, per the AAuth signature profile).
// Every party must support Ed25519; ES256 is a SHOULD. The polymorphic EdDSA
// identifier is refused.
const (
	AlgEd25519 = "Ed25519"
	AlgES256   = "ES256"
)

// SupportedAlgs is the exact set this server verifies, for
// Accept-Signature-Alg.
var SupportedAlgs = []string{AlgEd25519, AlgES256}

// JWK is a public key in the two shapes AAuth uses here: OKP Ed25519 and
// EC P-256. alg is required and fully specified.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// errUnsupportedAlg and errKeyMismatch distinguish the two key failures the
// signature profile names separately: unsupported_algorithm and invalid_key.
var (
	errUnsupportedAlg = fmt.Errorf("unsupported algorithm")
	errKeyMismatch    = fmt.Errorf("key does not match its alg")
)

// PublicKey returns the key, after checking that alg is supported and agrees
// with kty and crv.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Alg {
	case AlgEd25519:
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Y != "" {
			return nil, fmt.Errorf("%w: %s needs kty OKP, crv Ed25519", errKeyMismatch, k.Alg)
		}
		x, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: x is not a 32-byte Ed25519 key", errKeyMismatch)
		}
		return ed25519.PublicKey(x), nil
	case AlgES256:
		if k.Kty != "EC" || k.Crv != "P-256" {
			return nil, fmt.Errorf("%w: %s needs kty EC, crv P-256", errKeyMismatch, k.Alg)
		}
		x, errX := base64.RawURLEncoding.Strict().DecodeString(k.X)
		y, errY := base64.RawURLEncoding.Strict().DecodeString(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, fmt.Errorf("%w: x and y are not 32-byte P-256 coordinates", errKeyMismatch)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, fmt.Errorf("%w: the point is not on P-256", errKeyMismatch)
		}
		return pub, nil
	case "":
		return nil, fmt.Errorf("%w: alg is absent", errUnsupportedAlg)
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedAlg, k.Alg)
	}
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint, base64url without padding.
// Only the required members take part (kty, crv, x, and y for EC), so alg,
// kid and use never change it: the same key has the same thumbprint in
// cnf.jwk, in a DPoP proof and in an hwk header.
func (k JWK) Thumbprint() (string, error) {
	var members any
	switch k.Kty {
	case "OKP":
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{k.Crv, k.Kty, k.X}
	case "EC":
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{k.Crv, k.Kty, k.X, k.Y}
	default:
		return "", fmt.Errorf("%w: kty %q", errUnsupportedAlg, k.Kty)
	}
	b, err := json.Marshal(members)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// PublicJWK is k without the members that name or scope a key, as carried in
// cnf.jwk: kty, crv, x, y and alg.
func (k JWK) PublicJWK() JWK {
	return JWK{Kty: k.Kty, Crv: k.Crv, X: k.X, Y: k.Y, Alg: k.Alg}
}

// Ed25519JWK returns the JWK of an Ed25519 public key.
func Ed25519JWK(pub ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), Alg: AlgEd25519}
}
