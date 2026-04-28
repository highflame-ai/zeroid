package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog/log"
)

// JWKSService manages signing key pairs (ECDSA P-256 for NHI, optional RSA for SDK/human)
// and exposes a combined JWKS endpoint so verifiers can validate both token types.
type JWKSService struct {
	// ECDSA P-256 — always present, used for agent/NHI flows (ES256).
	ecPrivateKey *ecdsa.PrivateKey
	ecPublicKey  *ecdsa.PublicKey
	ecKeyID      string

	// RSA — optional, used for SDK/human flows (RS256).
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
	rsaKeyID      string

	keySet jwk.Set
}

// NewJWKSService loads the ECDSA P-256 key pair from disk and builds a JWKS.
// RSA keys are loaded separately via LoadRSAKeys (optional).
func NewJWKSService(privateKeyPath, publicKeyPath, keyID string) (*JWKSService, error) {
	privPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}

	pubPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}
	block, _ = pem.Decode(pubPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}

	keySet := jwk.NewSet()
	if err := addToKeySet(keySet, pubKey, keyID, jwa.ES256); err != nil {
		return nil, fmt.Errorf("failed to add EC key to JWKS: %w", err)
	}

	log.Info().Str("key_id", keyID).Msg("JWKS service initialized with ECDSA P-256 key pair")

	return &JWKSService{
		ecPrivateKey: privKey,
		ecPublicKey:  pubKey,
		ecKeyID:      keyID,
		keySet:       keySet,
	}, nil
}

// LoadRSAKeys loads an RSA key pair and adds the public key to the JWKS.
// This is optional — if not called, the service only supports ES256.
func (s *JWKSService) LoadRSAKeys(privateKeyPath, publicKeyPath, keyID string) error {
	privPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read RSA private key file: %w", err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from RSA private key")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback to PKCS1 format.
		privKeyPKCS1, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err2 != nil {
			return fmt.Errorf("failed to parse RSA private key (tried PKCS8 and PKCS1): %w", err)
		}
		privKey = privKeyPKCS1
	}
	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not RSA")
	}

	pubPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read RSA public key file: %w", err)
	}
	block, _ = pem.Decode(pubPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from RSA public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse RSA public key: %w", err)
	}
	rsaPubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	if err := addToKeySet(s.keySet, rsaPubKey, keyID, jwa.RS256); err != nil {
		return fmt.Errorf("failed to add RSA key to JWKS: %w", err)
	}

	s.rsaPrivateKey = rsaPrivKey
	s.rsaPublicKey = rsaPubKey
	s.rsaKeyID = keyID

	log.Info().Str("key_id", keyID).Msg("JWKS service loaded RSA key pair for RS256 signing")
	return nil
}

// HasRSAKeys returns true if RSA keys have been loaded.
func (s *JWKSService) HasRSAKeys() bool {
	return s.rsaPrivateKey != nil
}

// PrivateKey returns the ECDSA private key for ES256 JWT signing.
func (s *JWKSService) PrivateKey() *ecdsa.PrivateKey {
	return s.ecPrivateKey
}

// PublicKey returns the ECDSA public key.
func (s *JWKSService) PublicKey() *ecdsa.PublicKey {
	return s.ecPublicKey
}

// KeyID returns the ECDSA key ID (kid) used in JWT headers.
func (s *JWKSService) KeyID() string {
	return s.ecKeyID
}

// RSAPrivateKey returns the RSA private key for RS256 JWT signing.
func (s *JWKSService) RSAPrivateKey() *rsa.PrivateKey {
	return s.rsaPrivateKey
}

// RSAPublicKey returns the RSA public key.
func (s *JWKSService) RSAPublicKey() *rsa.PublicKey {
	return s.rsaPublicKey
}

// RSAKeyID returns the RSA key ID (kid) used in RS256 JWT headers.
func (s *JWKSService) RSAKeyID() string {
	return s.rsaKeyID
}

// KeySet returns the JWKS containing all public keys (EC + RSA if loaded).
func (s *JWKSService) KeySet() jwk.Set {
	return s.keySet
}

// addToKeySet creates a JWK from a public key and adds it to the set.
func addToKeySet(set jwk.Set, pubKey crypto.PublicKey, keyID string, alg jwa.SignatureAlgorithm) error {
	jwkKey, err := jwk.FromRaw(pubKey)
	if err != nil {
		return fmt.Errorf("failed to create JWK from public key: %w", err)
	}
	if err := jwkKey.Set(jwk.KeyIDKey, keyID); err != nil {
		return fmt.Errorf("failed to set key ID: %w", err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, alg); err != nil {
		return fmt.Errorf("failed to set algorithm: %w", err)
	}
	// In-memory keys keep use=sig because lestrrat-go/jwx's verifier skips
	// any key whose use is set to anything other than "sig". The published
	// /.well-known/jwks.json rewrites this to "jwt-svid" at the handler so
	// SPIFFE verifiers see the value JWT-SVID §4 requires.
	if err := jwkKey.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return fmt.Errorf("failed to set key usage: %w", err)
	}
	if err := set.AddKey(jwkKey); err != nil {
		return fmt.Errorf("failed to add key to set: %w", err)
	}
	return nil
}
