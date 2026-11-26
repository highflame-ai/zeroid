package aauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

// signAsServer signs an outbound request the Agent Provider makes in its own
// right (a revocation at a person server, or a poll of one) under the
// jwks_uri Signature-Key scheme (protocol draft, "Keying Material"): id is
// the Agent Provider's issuer, dwk its metadata document, kid its signing
// key, which the recipient discovers at {id}/.well-known/{dwk} → jwks_uri.
// The signature covers @method, @authority, @path and signature-key, and,
// with a body, content-digest and content-type (which the caller sets).
func (k *signingKey) signAsServer(req *http.Request, body []byte, issuer string, now time.Time) error {
	sk := httpsfv.NewDictionary()
	params := httpsfv.NewParams()
	params.Add("id", issuer)
	params.Add("dwk", AgentMetadataDWK)
	params.Add("kid", k.jwk.Kid)
	sk.Add(signatureLabel, httpsfv.Item{Value: httpsfv.Token("jwks_uri"), Params: params})
	skv, err := httpsfv.Marshal(sk)
	if err != nil {
		return fmt.Errorf("serializing Signature-Key: %w", err)
	}
	req.Header.Set(HeaderSignatureKey, skv)

	covered := append([]string(nil), baseComponents...)
	if len(body) > 0 {
		if req.Header.Get("Content-Type") == "" {
			return fmt.Errorf("a signed request with a body needs a Content-Type")
		}
		sum := sha256.Sum256(body)
		req.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
		covered = append(covered, "content-digest", "content-type")
	}
	items := make([]httpsfv.Item, 0, len(covered))
	for _, c := range covered {
		items = append(items, httpsfv.NewItem(c))
	}
	sigParams := httpsfv.NewParams()
	sigParams.Add("created", now.Unix())
	inputs := httpsfv.NewDictionary()
	inputs.Add(signatureLabel, httpsfv.InnerList{Items: items, Params: sigParams})

	base, err := signatureBase(req, covered, signatureLabel, inputs, outboundAuthority(req))
	if err != nil {
		return err
	}
	iv, err := httpsfv.Marshal(inputs)
	if err != nil {
		return fmt.Errorf("serializing Signature-Input: %w", err)
	}
	sigs := httpsfv.NewDictionary()
	sigs.Add(signatureLabel, httpsfv.NewItem(ed25519.Sign(k.priv, base)))
	sv, err := httpsfv.Marshal(sigs)
	if err != nil {
		return fmt.Errorf("serializing Signature: %w", err)
	}
	req.Header.Set(HeaderSignatureInput, iv)
	req.Header.Set(HeaderSignature, sv)
	return nil
}

// outboundAuthority is @authority for a request this server sends: the
// target's host, lower case, without the https default port.
func outboundAuthority(req *http.Request) string {
	host := strings.ToLower(req.URL.Host)
	if h, port, ok := strings.Cut(host, ":"); ok && port == "443" {
		host = h
	}
	return host
}
