package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"

	"github.com/lestrrat-go/jwx/v4/jws"
)

// sharedDBURL is the DSN of the shared TestMain Postgres container. It is
// captured on first use by the federation test helpers — we copy it from
// the bun.DB handle's underlying connector. Set in TestMain before any
// per-test code runs.
var sharedDBURL string

// federationKeyPaths holds the temp PEM file paths for the federation
// server's signing keys. Generated once on first federation-test access so
// every federation-server instance reuses the same keys (which is fine —
// no other test reads from these key files).
var fedKeyPaths struct {
	privPath string
	pubPath  string
	rsaPriv  string
	rsaPub   string
}

// initFederationKeyMaterial generates and writes the temp PEM files used
// by every federation server constructed in these tests. Called lazily from
// the federation tests themselves (TestMain has no hook).
func initFederationKeyMaterial() error {
	if fedKeyPaths.privPath != "" {
		return nil
	}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	privPath, pubPath, _, err := writeKeyFiles(privKey)
	if err != nil {
		return err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rsaPriv, rsaPub, _, err := writeRSAKeyFiles(rsaKey)
	if err != nil {
		return err
	}
	fedKeyPaths.privPath = privPath
	fedKeyPaths.pubPath = pubPath
	fedKeyPaths.rsaPriv = rsaPriv
	fedKeyPaths.rsaPub = rsaPub
	return nil
}

// jwsHeadersForKID returns a jws header object carrying kid + typ — used by
// the fake upstream IdP to mint tokens whose protected header announces the
// signing key the registry must look up.
func jwsHeadersForKID(kid string) (jws.Headers, error) {
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := hdr.Set(jws.TypeKey, "JWT"); err != nil {
		return nil, err
	}
	return hdr, nil
}

// jwtDecodeSegment base64url-decodes a JWT payload segment. Mirrors what
// jwt.Parse would do internally without running any signature checks —
// callers in this package only need the claim map for assertions.
func jwtDecodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}
