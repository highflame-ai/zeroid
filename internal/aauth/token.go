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
// the Agent Provider's own requests, and is published only at /ap/jwks.json.
// retired are earlier keys, published and accepted until the tokens they
// signed have expired, so a key can be replaced without invalidating every
// outstanding agent token at once.
type signingKey struct {
	priv    ed25519.PrivateKey
	jwk     JWK   // public, with kid, use and alg
	retired []JWK // public, with kid, use and alg
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
	jwk, err := publishedJWK(priv.Public().(ed25519.PublicKey), kid)
	if err != nil {
		return nil, err
	}
	return &signingKey{priv: priv, jwk: jwk}, nil
}

// addRetired publishes and accepts a retired signing key: a PEM file holding
// its PKCS#8 private key or its PKIX public key (only the public half is
// kept). kid defaults to its RFC 7638 thumbprint, and must be the kid the
// key signed with.
func (k *signingKey) addRetired(path, kid string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading the retired AAuth signing key %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return fmt.Errorf("the retired AAuth signing key %s is not PEM", path)
	}
	var pub ed25519.PublicKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("the retired AAuth signing key %s is %T, not Ed25519", path, parsed)
		}
		pub = priv.Public().(ed25519.PublicKey)
	} else if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		p, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("the retired AAuth signing key %s is %T, not Ed25519", path, parsed)
		}
		pub = p
	} else {
		return fmt.Errorf("the retired AAuth signing key %s is neither a PKCS#8 private nor a PKIX public key", path)
	}
	jwk, err := publishedJWK(pub, kid)
	if err != nil {
		return err
	}
	for _, have := range append([]JWK{k.jwk}, k.retired...) {
		if have.Kid == jwk.Kid || have.X == jwk.X {
			return fmt.Errorf("the retired AAuth signing key %s repeats a published key or kid %q", path, jwk.Kid)
		}
	}
	k.retired = append(k.retired, jwk)
	return nil
}

func publishedJWK(pub ed25519.PublicKey, kid string) (JWK, error) {
	jwk := Ed25519JWK(pub)
	if kid == "" {
		var err error
		if kid, err = jwk.Thumbprint(); err != nil {
			return JWK{}, err
		}
	}
	jwk.Kid, jwk.Use = kid, "sig"
	return jwk, nil
}

// jwks is the document served at /ap/jwks.json: the current key, then the
// retired ones. Every key carries alg, as the profile requires of a JWKS
// AAuth reads.
func (k *signingKey) jwks() map[string]any {
	return map[string]any{"keys": append([]JWK{k.jwk}, k.retired...)}
}

// publicKeyFor returns the published key a token's kid names.
func (k *signingKey) publicKeyFor(kid string) (ed25519.PublicKey, bool) {
	for _, j := range append([]JWK{k.jwk}, k.retired...) {
		if j.Kid == kid {
			pub, err := j.PublicKey()
			if err != nil {
				return nil, false
			}
			return pub.(ed25519.PublicKey), true
		}
	}
	return nil, false
}

// errAgentTokenExpired is verify's error for an agent token past its exp.
var errAgentTokenExpired = errors.New("expired")

// agentClaims are the claims of an agent token ZeroID issues.
type agentClaims struct {
	Subject   string
	JTI       string
	ExpiresAt time.Time
	Cnf       JWK
	// PS is the agent's person server (the ps claim), if it has one.
	PS string
	// ParentAgent, set only on a sub-agent token, is its parent's agent
	// identifier: the authoritative marker of a sub-agent.
	ParentAgent string
}

// tokenExtras are an agent token's optional claims.
type tokenExtras struct {
	PS          string // ps
	ParentAgent string // parent_agent
}

// sign returns the signed agent token: typ aa-agent+jwt, alg Ed25519, the
// common claims (iss, dwk, jti, iat, exp, cnf), sub, the agent identifier,
// and the optional ps and parent_agent.
func (k *signingKey) sign(issuer, sub string, cnf JWK, jti string, iat, exp time.Time, extra tokenExtras) (string, error) {
	tok := jwt.New()
	claims := map[string]any{
		jwt.IssuerKey:     issuer,
		"dwk":             AgentMetadataDWK,
		jwt.SubjectKey:    sub,
		jwt.JwtIDKey:      jti,
		jwt.IssuedAtKey:   iat,
		jwt.ExpirationKey: exp,
		"cnf":             map[string]any{"jwk": cnf.PublicJWK()},
	}
	if extra.PS != "" {
		claims["ps"] = extra.PS
	}
	if extra.ParentAgent != "" {
		claims["parent_agent"] = extra.ParentAgent
	}
	for name, v := range claims {
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
	kid, _ := hdr.KeyID()
	pub, ok := k.publicKeyFor(kid)
	if !ok {
		return nil, errors.New("not signed by a key this Agent Provider publishes")
	}
	tok, err := jwt.Parse([]byte(raw), jwt.WithKey(jwa.EdDSAEd25519(), pub), jwt.WithValidate(false))
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
	if !ok {
		return nil, errors.New("no exp")
	}
	if !now.Before(exp) {
		return nil, errAgentTokenExpired
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
	out := &agentClaims{Subject: sub, JTI: jti, ExpiresAt: exp, Cnf: key}
	if v, ok := tok.Field("ps"); ok {
		if out.PS, ok = v.(string); !ok {
			return nil, errors.New("ps is not a string")
		}
	}
	if v, ok := tok.Field("parent_agent"); ok {
		if out.ParentAgent, ok = v.(string); !ok || !strings.HasPrefix(out.ParentAgent, "aauth:") {
			return nil, errors.New("parent_agent is not an agent identifier")
		}
	}
	return out, nil
}
