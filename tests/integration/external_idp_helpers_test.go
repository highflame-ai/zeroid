package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
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
	return jwsHeadersForKIDTyp(kid, "JWT")
}

// jwsHeadersForKIDTyp is jwsHeadersForKID with an explicit typ — used to mint
// MCP ID-JAG assertions (typ: oauth-id-jag+jwt) whose protected header drives
// the ZeroID jwt-bearer typ-branch (ADR 0010 D2).
func jwsHeadersForKIDTyp(kid, typ string) (jws.Headers, error) {
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := hdr.Set(jws.TypeKey, typ); err != nil {
		return nil, err
	}
	return hdr, nil
}

// SignTokenWithTyp mints an ES256 JWT against the fake upstream IdP's published
// key with an explicit JWS typ header. Used to forge ID-JAG-shaped assertions
// (typ: oauth-id-jag+jwt) the federation server will validate against the IdP's
// JWKS.
func (i *fakeUpstreamIdP) SignTokenWithTyp(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	hdr, err := jwsHeadersForKIDTyp(i.keyID, typ)
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), i.priv, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)
	return string(signed)
}

// signForeignIDJAG mints an ID-JAG-shaped assertion signed by a fresh key that
// no configured upstream JWKS publishes — used to prove a bad signature fails
// closed at the MAS. It reuses the fake IdP's published kid in the header so
// the verifier picks that key from the JWKS and the signature check (not a
// missing-key error) is what rejects it.
func signForeignIDJAG(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	hdr, err := jwsHeadersForKIDTyp("upstream-key-1", typ)
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), foreign, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)
	return string(signed)
}

// jwtDecodeSegment base64url-decodes a JWT payload segment. Mirrors what
// jwt.Parse would do internally without running any signature checks —
// callers in this package only need the claim map for assertions.
func jwtDecodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}
