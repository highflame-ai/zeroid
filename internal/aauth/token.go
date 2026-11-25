package aauth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// Agent token constants (protocol draft, "Agent Token").
const (
	AgentTokenType   = "aa-agent+jwt"
	AgentMetadataDWK = "aauth-agent.json"
)

// signingKey is the Agent Provider's Ed25519 key. It signs agent tokens and
// nothing else, and is published only at /ap/jwks.json.
type signingKey struct {
	priv ed25519.PrivateKey
	jwk  JWK // public, with kid, use and alg
}

// loadSigningKey reads a PKCS#8 PEM Ed25519 private key. kid defaults to the
// key's RFC 7638 thumbprint.
func loadSigningKey(path, kid string) (*signingKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the AAuth signing key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("the AAuth signing key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the AAuth signing key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the AAuth signing key is %T, not Ed25519", parsed)
	}
	jwk := Ed25519JWK(priv.Public().(ed25519.PublicKey))
	if kid == "" {
		if kid, err = jwk.Thumbprint(); err != nil {
			return nil, err
		}
	}
	jwk.Kid, jwk.Use = kid, "sig"
	return &signingKey{priv: priv, jwk: jwk}, nil
}

// jwks is the document served at /ap/jwks.json. Every key carries alg, as
// the profile requires of a JWKS AAuth reads.
func (k *signingKey) jwks() map[string]any {
	return map[string]any{"keys": []JWK{k.jwk}}
}

// agentClaims are the claims of an agent token ZeroID issues.
type agentClaims struct {
	Subject   string
	JTI       string
	ExpiresAt time.Time
	Cnf       JWK
}

// sign returns the signed agent token: typ aa-agent+jwt, alg Ed25519, the
// common claims (iss, dwk, jti, iat, exp, cnf) and sub, the agent identifier.
func (k *signingKey) sign(issuer, sub string, cnf JWK, jti string, iat, exp time.Time) (string, error) {
	tok := jwt.New()
	for name, v := range map[string]any{
		jwt.IssuerKey:     issuer,
		"dwk":             AgentMetadataDWK,
		jwt.SubjectKey:    sub,
		jwt.JwtIDKey:      jti,
		jwt.IssuedAtKey:   iat,
		jwt.ExpirationKey: exp,
		"cnf":             map[string]any{"jwk": cnf.PublicJWK()},
	} {
		if err := tok.Set(name, v); err != nil {
			return "", fmt.Errorf("agent token claim %s: %w", name, err)
		}
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, k.jwk.Kid)
	_ = hdrs.Set(jws.TypeKey, AgentTokenType)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSAEd25519(), k.priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("signing the agent token: %w", err)
	}
	return string(signed), nil
}

// verify parses an agent token this Agent Provider issued: its signature
// under this key, typ, iss, dwk, an unexpired exp (no skew allowance, per the
// common JWT verification), sub and cnf.jwk.
func (k *signingKey) verify(raw, issuer string, now time.Time) (*agentClaims, error) {
	msg, err := jws.Parse([]byte(raw))
	if err != nil || len(msg.Signatures()) != 1 {
		return nil, errors.New("not a single-signature JWS")
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()
	if typ, _ := hdr.Type(); typ != AgentTokenType {
		return nil, fmt.Errorf("typ is %q, not %s", typ, AgentTokenType)
	}
	if kid, _ := hdr.KeyID(); kid != k.jwk.Kid {
		return nil, errors.New("not signed by this Agent Provider's key")
	}
	tok, err := jwt.Parse([]byte(raw), jwt.WithKey(jwa.EdDSAEd25519(), k.priv.Public()), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if iss, _ := tok.Issuer(); iss != issuer {
		return nil, fmt.Errorf("iss is %q, not this Agent Provider", iss)
	}
	if dwk, _ := tok.Field("dwk"); dwk != AgentMetadataDWK {
		return nil, errors.New("dwk is not " + AgentMetadataDWK)
	}
	exp, ok := tok.Expiration()
	if !ok || !now.Before(exp) {
		return nil, errors.New("expired")
	}
	sub, _ := tok.Subject()
	jti, _ := tok.JwtID()
	if !strings.HasPrefix(sub, "aauth:") || jti == "" {
		return nil, errors.New("no agent identifier or jti")
	}
	cnf, ok := tok.Field("cnf")
	cnfMap, isMap := cnf.(map[string]any)
	if !ok || !isMap {
		return nil, errors.New("no cnf")
	}
	b, err := json.Marshal(cnfMap["jwk"])
	if err != nil {
		return nil, errors.New("cnf.jwk unreadable")
	}
	var key JWK
	if err := json.Unmarshal(b, &key); err != nil || key.Kty == "" {
		return nil, errors.New("no cnf.jwk")
	}
	return &agentClaims{Subject: sub, JTI: jti, ExpiresAt: exp, Cnf: key}, nil
}
