package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/highflame-ai/zeroid/domain"
)

// AWS STS signs web identity tokens with RS256 or ES384, as the caller asks.
// An ES384 token from a P-384 key verifies when the row allows ES384, which
// rows do by default, and is refused when the row leaves it out.
func TestVerifyIDToken_ES384(t *testing.T) {
	f := newVerifyFixture(t, nil)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.Import[jwk.Key](&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub.Set(jwk.KeyIDKey, "k384")
	_ = pub.Set(jwk.AlgorithmKey, jwa.ES384())
	_ = pub.Set(jwk.KeyUsageKey, jwk.ForSignature)
	set := jwk.NewSet()
	_ = set.AddKey(pub)
	f.jwks.keySet = set

	tok := jwt.New()
	for k, v := range f.claims(nil) {
		if err := tok.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.KeyIDKey, "k384")
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES384(), priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}

	row := *f.row
	row.Algorithms = nil
	row.Normalize()
	if _, err := f.svc.verifyIDTokenForRow(context.Background(), &row, VerifyIDTokenInput{
		IDToken: string(signed), ClientID: verifyClientID, Nonce: verifyNonce,
	}); err != nil {
		t.Fatalf("ES384 token on a default row: %v", err)
	}

	row.Algorithms = []string{"RS256", "ES256", "PS256"}
	if _, err := f.svc.verifyIDTokenForRow(context.Background(), &row, VerifyIDTokenInput{
		IDToken: string(signed), ClientID: verifyClientID, Nonce: verifyNonce,
	}); err == nil {
		t.Fatal("ES384 token accepted by a row that leaves ES384 out")
	}

	if !domain.ExternalIssuerAlgorithmAllowed("ES384") {
		t.Fatal("ES384 is not an allowed issuer algorithm")
	}
}
