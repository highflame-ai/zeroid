package aauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

// This file verifies RFC 9421 HTTP Message Signatures under the AAuth profile
// (protocol draft, "HTTP Message Signatures Profile"): a signature covering at
// least @method, @authority, @path and signature-key, with a required
// created parameter, keyed by the Signature-Key header
// (draft-hardt-httpbis-signature-key). It implements exactly the profile, not
// RFC 9421 in general: derived components @method, @authority, @path and
// @query, and header fields without component parameters.

// Header names.
const (
	HeaderSignature             = "Signature"
	HeaderSignatureInput        = "Signature-Input"
	HeaderSignatureKey          = "Signature-Key"
	HeaderSignatureError        = "Signature-Error"
	HeaderAcceptSignatureScheme = "Accept-Signature-Scheme"
	HeaderAcceptSignatureAlg    = "Accept-Signature-Alg"
)

// signatureLabel is the label AAuth agents sign under.
const signatureLabel = "sig"

// DefaultSignatureWindow is the profile's default validity window for created.
const DefaultSignatureWindow = 60 * time.Second

// baseComponents are covered by every AAuth signature.
var baseComponents = []string{"@method", "@authority", "@path", "signature-key"}

// Signature-Error codes (draft-hardt-httpbis-signature-key §5.4).
const (
	ErrCodeInvalidSignature     = "invalid_signature"
	ErrCodeInvalidInput         = "invalid_input"
	ErrCodeUnsupportedScheme    = "unsupported_scheme"
	ErrCodeUnsupportedAlgorithm = "unsupported_algorithm"
	ErrCodeInvalidKey           = "invalid_key"
	ErrCodeClockSkew            = "clock_skew"
)

// SigError is a signature failure, answered 401 with a Signature-Error
// header (the AAuth profile answers every signature failure 401).
type SigError struct {
	Code   string
	Detail string
	// RequiredInput lists the covered components required, for invalid_input.
	RequiredInput []string
	// AcceptSchemes, for unsupported_scheme, are the schemes this endpoint takes.
	AcceptSchemes []string
}

func (e *SigError) Error() string { return e.Code + ": " + e.Detail }

func sigErr(code, format string, args ...any) *SigError {
	return &SigError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// VerifyOptions configure one verification.
type VerifyOptions struct {
	// Now is the verifier's clock.
	Now time.Time
	// Window bounds created in both directions; zero means
	// DefaultSignatureWindow.
	Window time.Duration
	// Authority is @authority as this server was reached: lower-case host,
	// with the port only when it is not the scheme's default. Empty means the
	// request's Host.
	Authority string
	// RequiredComponents must be covered beyond the base four.
	RequiredComponents []string
	// RequireBodyCoverage makes content-digest and content-type required on a
	// request with a body, as the profile requires of a body sent to a PS, an
	// AS or (bootstrap draft) an Agent Provider.
	RequireBodyCoverage bool
	// Schemes are the Signature-Key schemes accepted. Any other scheme is
	// unsupported_scheme.
	Schemes []string
	// ResolveKey returns the key a Signature-Key member names. A *SigError it
	// returns is passed through; any other error is invalid_key.
	ResolveKey func(scheme string, params map[string]any) (JWK, error)
}

// Verified is a request whose signature verified.
type Verified struct {
	// Key verified the signature.
	Key JWK
	// Scheme and Params are the Signature-Key member that named it.
	Scheme string
	Params map[string]any
	// Created is the signature's created parameter.
	Created time.Time
}

// VerifyRequest verifies r's signature over body (the request body as
// received, read once by the caller) in the order the profile's verification
// steps give.
func VerifyRequest(r *http.Request, body []byte, opt VerifyOptions) (*Verified, error) {
	// 1. All three headers.
	sigInput := r.Header.Values(HeaderSignatureInput)
	sigValues := r.Header.Values(HeaderSignature)
	sigKey := r.Header.Values(HeaderSignatureKey)
	if len(sigInput) == 0 || len(sigValues) == 0 || len(sigKey) == 0 {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature, Signature-Input and Signature-Key are all required")
	}
	inputs, err := httpsfv.UnmarshalDictionary(sigInput)
	if err != nil {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature-Input is not a structured dictionary")
	}
	label, ok := selectLabel(inputs)
	if !ok {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature-Input has no %q signature", signatureLabel)
	}
	member, _ := inputs.Get(label)
	il, ok := member.(httpsfv.InnerList)
	if !ok {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature-Input %q is not an inner list", label)
	}

	// 2. Covered components.
	covered := make([]string, 0, len(il.Items))
	for _, it := range il.Items {
		name, isString := it.Value.(string)
		if !isString || name == "" {
			return nil, sigErr(ErrCodeInvalidInput, "a covered component is not a string")
		}
		if it.Params != nil && len(it.Params.Names()) > 0 {
			return nil, sigErr(ErrCodeInvalidInput, "component parameters are not supported (%q)", name)
		}
		if name != strings.ToLower(name) {
			return nil, sigErr(ErrCodeInvalidInput, "component %q is not lower case", name)
		}
		if slices.Contains(covered, name) {
			return nil, sigErr(ErrCodeInvalidInput, "component %q is covered twice", name)
		}
		covered = append(covered, name)
	}
	required := slices.Clone(baseComponents)
	required = append(required, opt.RequiredComponents...)
	if opt.RequireBodyCoverage && len(body) > 0 {
		required = append(required, "content-digest", "content-type")
	}
	var missing []string
	for _, c := range required {
		if !slices.Contains(covered, c) && !slices.Contains(missing, c) {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		// required_input lists everything required, not only what is missing.
		return nil, &SigError{Code: ErrCodeInvalidInput, Detail: "required components are not covered: " + strings.Join(missing, " "), RequiredInput: required}
	}

	// 3. created, within the window; expires, if present, in the future.
	created, err := intParam(il.Params, "created")
	if err != nil {
		return nil, sigErr(ErrCodeInvalidSignature, "created: %v", err)
	}
	window := opt.Window
	if window <= 0 {
		window = DefaultSignatureWindow
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	createdAt := time.Unix(created, 0)
	if now.Sub(createdAt) > window {
		return nil, sigErr(ErrCodeInvalidSignature, "created is older than the %s window", window)
	}
	if createdAt.Sub(now) > window {
		return nil, sigErr(ErrCodeClockSkew, "created is ahead of the server clock by more than %s", window)
	}
	if _, present := paramValue(il.Params, "expires"); present {
		expires, err := intParam(il.Params, "expires")
		if err != nil {
			return nil, sigErr(ErrCodeInvalidSignature, "expires: %v", err)
		}
		if !now.Before(time.Unix(expires, 0)) {
			return nil, sigErr(ErrCodeInvalidSignature, "the signature has expired")
		}
	}

	// 4. The Signature-Key member for this label, and its scheme.
	keys, err := httpsfv.UnmarshalDictionary(sigKey)
	if err != nil {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature-Key is not a structured dictionary")
	}
	km, ok := keys.Get(label)
	if !ok {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature-Key has no member for %q", label)
	}
	kItem, ok := km.(httpsfv.Item)
	if !ok {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature-Key %q is not an item", label)
	}
	schemeTok, ok := kItem.Value.(httpsfv.Token)
	if !ok || !slices.Contains(opt.Schemes, string(schemeTok)) {
		return nil, &SigError{Code: ErrCodeUnsupportedScheme, Detail: "the Signature-Key scheme is not accepted here", AcceptSchemes: opt.Schemes}
	}
	params := map[string]any{}
	if kItem.Params != nil {
		for _, n := range kItem.Params.Names() {
			v, _ := kItem.Params.Get(n)
			params[n] = v
		}
	}

	// 5. The key.
	if opt.ResolveKey == nil {
		return nil, sigErr(ErrCodeInvalidKey, "no key resolver")
	}
	jwk, err := opt.ResolveKey(string(schemeTok), params)
	if err != nil {
		var se *SigError
		if errors.As(err, &se) {
			return nil, se
		}
		return nil, sigErr(ErrCodeInvalidKey, "%v", err)
	}

	// 6. The algorithm, from the key.
	pub, err := jwk.PublicKey()
	switch {
	case errors.Is(err, errUnsupportedAlg):
		return nil, sigErr(ErrCodeUnsupportedAlgorithm, "%v", err)
	case err != nil:
		return nil, sigErr(ErrCodeInvalidKey, "%v", err)
	}

	// Content-Digest, when covered, must match the body.
	if slices.Contains(covered, "content-digest") {
		if err := checkContentDigest(r.Header.Values("Content-Digest"), body); err != nil {
			return nil, sigErr(ErrCodeInvalidSignature, "%v", err)
		}
	}

	// 7. The signature over the signature base.
	base, err := signatureBase(r, covered, label, inputs, opt.Authority)
	if err != nil {
		return nil, sigErr(ErrCodeInvalidSignature, "%v", err)
	}
	sigs, err := httpsfv.UnmarshalDictionary(sigValues)
	if err != nil {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature is not a structured dictionary")
	}
	sm, ok := sigs.Get(label)
	if !ok {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature has no member for %q", label)
	}
	sItem, ok := sm.(httpsfv.Item)
	if !ok {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature %q is not an item", label)
	}
	sig, ok := sItem.Value.([]byte)
	if !ok {
		return nil, sigErr(ErrCodeInvalidSignature, "Signature %q is not a byte sequence", label)
	}
	if !verifySignature(jwk.Alg, pub, base, sig) {
		return nil, sigErr(ErrCodeInvalidSignature, "the signature does not verify")
	}
	return &Verified{Key: jwk, Scheme: string(schemeTok), Params: params, Created: createdAt}, nil
}

// selectLabel picks the signature to verify: the AAuth label "sig", or the
// only signature present.
func selectLabel(inputs *httpsfv.Dictionary) (string, bool) {
	names := inputs.Names()
	if slices.Contains(names, signatureLabel) {
		return signatureLabel, true
	}
	if len(names) == 1 {
		return names[0], true
	}
	return "", false
}

func paramValue(p *httpsfv.Params, name string) (any, bool) {
	if p == nil {
		return nil, false
	}
	return p.Get(name)
}

func intParam(p *httpsfv.Params, name string) (int64, error) {
	v, ok := paramValue(p, name)
	if !ok {
		return 0, fmt.Errorf("absent")
	}
	n, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("not an integer")
	}
	return n, nil
}

// signatureBase builds the RFC 9421 §2.5 signature base: one line per
// covered component, then @signature-params as the label's inner list
// serialized back from the parsed Signature-Input.
func signatureBase(r *http.Request, covered []string, label string, inputs *httpsfv.Dictionary, authority string) ([]byte, error) {
	var b strings.Builder
	for _, c := range covered {
		v, err := componentValue(r, c, authority)
		if err != nil {
			return nil, err
		}
		b.WriteString(`"` + c + `": ` + v + "\n")
	}
	member, _ := inputs.Get(label)
	only := httpsfv.NewDictionary()
	only.Add(label, member)
	serialized, err := httpsfv.Marshal(only)
	if err != nil {
		return nil, fmt.Errorf("serializing the signature parameters: %w", err)
	}
	b.WriteString(`"@signature-params": ` + strings.TrimPrefix(serialized, label+"="))
	return []byte(b.String()), nil
}

func componentValue(r *http.Request, c, authority string) (string, error) {
	switch c {
	case "@method":
		return r.Method, nil
	case "@authority":
		if authority == "" {
			authority = strings.ToLower(r.Host)
		}
		return authority, nil
	case "@path":
		p := r.URL.EscapedPath()
		if p == "" {
			p = "/"
		}
		return p, nil
	case "@query":
		return "?" + r.URL.RawQuery, nil
	}
	if strings.HasPrefix(c, "@") {
		return "", fmt.Errorf("derived component %q is not supported", c)
	}
	values := slices.Clone(r.Header.Values(c)) // never trim the request's own header slice
	if len(values) == 0 {
		return "", fmt.Errorf("covered header %q is absent", c)
	}
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
	}
	return strings.Join(values, ", "), nil
}

// checkContentDigest verifies an RFC 9530 Content-Digest against body. One
// matching sha-256 or sha-512 member is enough; any member it can check must
// match.
func checkContentDigest(values []string, body []byte) error {
	if len(values) == 0 {
		return fmt.Errorf("content-digest is covered but absent")
	}
	d, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return fmt.Errorf("Content-Digest is not a structured dictionary")
	}
	checked := false
	for _, alg := range d.Names() {
		m, _ := d.Get(alg)
		it, ok := m.(httpsfv.Item)
		if !ok {
			continue
		}
		want, ok := it.Value.([]byte)
		if !ok {
			continue
		}
		var got []byte
		switch alg {
		case "sha-256":
			s := sha256.Sum256(body)
			got = s[:]
		case "sha-512":
			s := sha512.Sum512(body)
			got = s[:]
		default:
			continue
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("Content-Digest %s does not match the body", alg)
		}
		checked = true
	}
	if !checked {
		return fmt.Errorf("Content-Digest has no sha-256 or sha-512 member")
	}
	return nil
}

func verifySignature(alg string, pub crypto.PublicKey, base, sig []byte) bool {
	switch alg {
	case AlgEd25519:
		k, ok := pub.(ed25519.PublicKey)
		return ok && ed25519.Verify(k, base, sig)
	case AlgES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return false
		}
		h := sha256.Sum256(base)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k, h[:], r, s)
	}
	return false
}

// ResolveHWK reads the key an hwk Signature-Key member carries inline
// (draft-hardt-httpbis-signature-key §3.4). kid must not be present.
func ResolveHWK(params map[string]any) (JWK, error) {
	if _, ok := params["kid"]; ok {
		return JWK{}, sigErr(ErrCodeInvalidKey, "hwk must not carry kid")
	}
	str := func(name string) string {
		v, _ := params[name].(string)
		return v
	}
	k := JWK{Kty: str("kty"), Crv: str("crv"), X: str("x"), Y: str("y"), Alg: str("alg")}
	if k.Kty == "" || k.X == "" {
		return JWK{}, sigErr(ErrCodeInvalidKey, "hwk needs kty and x")
	}
	return k, nil
}

// WriteSigError answers a signature failure: 401, the Signature-Error
// header, the Accept-Signature-* header the code calls for, and an RFC 9457
// problem body whose type is the error's URN.
func WriteSigError(w http.ResponseWriter, e *SigError) {
	errDict := httpsfv.NewDictionary()
	errDict.Add("error", httpsfv.NewItem(httpsfv.Token(e.Code)))
	if len(e.RequiredInput) > 0 {
		items := make([]httpsfv.Item, 0, len(e.RequiredInput))
		for _, c := range e.RequiredInput {
			items = append(items, httpsfv.NewItem(c))
		}
		errDict.Add("required_input", httpsfv.InnerList{Items: items, Params: httpsfv.NewParams()})
	}
	if v, err := httpsfv.Marshal(errDict); err == nil {
		w.Header().Set(HeaderSignatureError, v)
	}
	switch e.Code {
	case ErrCodeUnsupportedScheme:
		w.Header().Set(HeaderAcceptSignatureScheme, strings.Join(e.AcceptSchemes, ", "))
	case ErrCodeUnsupportedAlgorithm:
		w.Header().Set(HeaderAcceptSignatureAlg, strings.Join(SupportedAlgs, ", "))
	}
	writeProblem(w, http.StatusUnauthorized, "urn:ietf:params:sig-error:"+e.Code, "Signature verification failed", e.Detail)
}
