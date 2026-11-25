package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
)

// vectorCase is one case of aauth-go's http-signature.json.
type vectorCase struct {
	Name       string            `json:"name"`
	SigningKey JWK               `json:"signing_key"`
	Request    vectorRequest     `json:"request"`
	Signed     map[string]string `json:"signed"`
	Tamper     *vectorRequest    `json:"tamper"`
	Verify     struct {
		AtOffset            int64    `json:"at_offset"`
		WindowSeconds       int64    `json:"window_seconds"`
		RequireBodyCoverage bool     `json:"require_body_coverage"`
		RequiredComponents  []string `json:"required_components"`
	} `json:"verify"`
	Expect string `json:"expect"`
}

type vectorRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
}

// TestAAuthGoSignatureVectors runs the reference implementation's published
// signature vectors through ZeroID's verifier: the same signature base, the
// same window, the same error codes.
func TestAAuthGoSignatureVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/aauth-go/http-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []vectorCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 10 {
		t.Fatalf("only %d vector cases loaded", len(file.Cases))
	}
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v := c.Request
			if c.Tamper != nil {
				if c.Tamper.Method != "" {
					v.Method = c.Tamper.Method
				}
				if c.Tamper.URL != "" {
					v.URL = c.Tamper.URL
				}
				if c.Tamper.Body != nil {
					v.Body = c.Tamper.Body
				}
				merged := map[string]string{}
				for k, val := range v.Headers {
					merged[k] = val
				}
				for k, val := range c.Tamper.Headers {
					merged[k] = val
				}
				v.Headers = merged
			}
			var body []byte
			if v.Body != nil {
				body = []byte(*v.Body)
			}
			req := httptest.NewRequest(v.Method, v.URL, strings.NewReader(string(body)))
			for k, val := range v.Headers {
				req.Header.Set(k, val)
			}
			for k, val := range c.Signed {
				req.Header.Set(k, val)
			}

			created := createdOf(t, c.Signed["Signature-Input"])
			opt := VerifyOptions{
				Now:                 time.Unix(created+c.Verify.AtOffset, 0),
				Window:              time.Duration(c.Verify.WindowSeconds) * time.Second,
				RequireBodyCoverage: c.Verify.RequireBodyCoverage,
				RequiredComponents:  c.Verify.RequiredComponents,
				Schemes:             []string{"jwt"},
				ResolveKey: func(string, map[string]any) (JWK, error) {
					return c.SigningKey.PublicJWK(), nil
				},
			}
			_, err := VerifyRequest(req, body, opt)
			if c.Expect == "valid" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			se, ok := err.(*SigError)
			if !ok {
				t.Fatalf("expected %s, got %v", c.Expect, err)
			}
			if se.Code != c.Expect {
				t.Fatalf("expected %s, got %s (%s)", c.Expect, se.Code, se.Detail)
			}
		})
	}
}

func createdOf(t *testing.T, input string) int64 {
	t.Helper()
	d, err := httpsfv.UnmarshalDictionary([]string{input})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := d.Get("sig")
	n, err := intParam(m.(httpsfv.InnerList).Params, "created")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// signHWK signs req as an AAuth agent signs an enrollment: hwk scheme, the
// base components plus content-digest and content-type over body. It uses the
// verifier's own signature base, which the vectors above pin to aauth-go's.
func signHWK(t *testing.T, req *http.Request, body []byte, priv ed25519.PrivateKey, created time.Time, extra string) {
	t.Helper()
	jwk := Ed25519JWK(priv.Public().(ed25519.PublicKey))
	req.Header.Set(HeaderSignatureKey, fmt.Sprintf(`sig=hwk;kty="OKP";crv="Ed25519";x="%s";alg="Ed25519"%s`, jwk.X, extra))
	sum := sha256.Sum256(body)
	req.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
	req.Header.Set(HeaderSignatureInput, fmt.Sprintf(`sig=("@method" "@authority" "@path" "signature-key" "content-digest" "content-type");created=%d`, created.Unix()))
	inputs, err := httpsfv.UnmarshalDictionary([]string{req.Header.Get(HeaderSignatureInput)})
	if err != nil {
		t.Fatal(err)
	}
	base, err := signatureBase(req, []string{"@method", "@authority", "@path", "signature-key", "content-digest", "content-type"}, "sig", inputs, "")
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderSignature, "sig=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(priv, base))+":")
}

func enrollRequest(t *testing.T, priv ed25519.PrivateKey, created time.Time, body string, extraKeyParams string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://ap.example/ap/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	signHWK(t, req, []byte(body), priv, created, extraKeyParams)
	return req
}

func hwkOptions(now time.Time) VerifyOptions {
	return VerifyOptions{
		Now:                 now,
		RequireBodyCoverage: true,
		Schemes:             []string{"hwk"},
		ResolveKey: func(_ string, params map[string]any) (JWK, error) {
			return ResolveHWK(params)
		},
	}
}

func TestVerifyHWKEnrollment(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	body := `{"attestation":"x"}`

	t.Run("verifies and returns the hwk key", func(t *testing.T) {
		v, err := VerifyRequest(enrollRequest(t, priv, now, body, ""), []byte(body), hwkOptions(now))
		if err != nil {
			t.Fatal(err)
		}
		want := Ed25519JWK(priv.Public().(ed25519.PublicKey))
		if v.Key.X != want.X || v.Scheme != "hwk" {
			t.Fatalf("verified key %+v, scheme %s", v.Key, v.Scheme)
		}
	})

	cases := []struct {
		name   string
		mutate func(r *http.Request) (*http.Request, []byte, VerifyOptions)
		want   string
	}{
		{"a body that does not match Content-Digest", func(r *http.Request) (*http.Request, []byte, VerifyOptions) {
			return r, []byte(`{"attestation":"y"}`), hwkOptions(now)
		}, ErrCodeInvalidSignature},
		{"another authority than the one signed", func(r *http.Request) (*http.Request, []byte, VerifyOptions) {
			o := hwkOptions(now)
			o.Authority = "other.example"
			return r, []byte(body), o
		}, ErrCodeInvalidSignature},
		{"a scheme this endpoint does not take", func(r *http.Request) (*http.Request, []byte, VerifyOptions) {
			o := hwkOptions(now)
			o.Schemes = []string{"jwt"}
			return r, []byte(body), o
		}, ErrCodeUnsupportedScheme},
		{"no Signature header", func(r *http.Request) (*http.Request, []byte, VerifyOptions) {
			r.Header.Del(HeaderSignature)
			return r, []byte(body), hwkOptions(now)
		}, ErrCodeInvalidSignature},
		{"created a minute and more in the past", func(r *http.Request) (*http.Request, []byte, VerifyOptions) {
			return r, []byte(body), hwkOptions(now.Add(61 * time.Second))
		}, ErrCodeInvalidSignature},
		{"the polymorphic EdDSA alg", func(r *http.Request) (*http.Request, []byte, VerifyOptions) {
			r.Header.Set(HeaderSignatureKey, strings.Replace(r.Header.Get(HeaderSignatureKey), `alg="Ed25519"`, `alg="EdDSA"`, 1))
			return r, []byte(body), hwkOptions(now)
		}, ErrCodeUnsupportedAlgorithm},
		{"an alg that disagrees with the key type", func(r *http.Request) (*http.Request, []byte, VerifyOptions) {
			r.Header.Set(HeaderSignatureKey, strings.Replace(r.Header.Get(HeaderSignatureKey), `alg="Ed25519"`, `alg="ES256"`, 1))
			return r, []byte(body), hwkOptions(now)
		}, ErrCodeInvalidKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, b, o := tc.mutate(enrollRequest(t, priv, now, body, ""))
			_, err := VerifyRequest(r, b, o)
			se, ok := err.(*SigError)
			if !ok || se.Code != tc.want {
				t.Fatalf("expected %s, got %v", tc.want, err)
			}
		})
	}

	t.Run("hwk with a kid is refused", func(t *testing.T) {
		_, err := VerifyRequest(enrollRequest(t, priv, now, body, `;kid="k1"`), []byte(body), hwkOptions(now))
		se, ok := err.(*SigError)
		if !ok || se.Code != ErrCodeInvalidKey {
			t.Fatalf("expected invalid_key, got %v", err)
		}
	})

	t.Run("a body not covered is invalid_input naming every required component", func(t *testing.T) {
		r := enrollRequest(t, priv, now, body, "")
		r.Header.Set(HeaderSignatureInput, fmt.Sprintf(`sig=("@method" "@authority" "@path" "signature-key");created=%d`, now.Unix()))
		_, err := VerifyRequest(r, []byte(body), hwkOptions(now))
		se, ok := err.(*SigError)
		if !ok || se.Code != ErrCodeInvalidInput || len(se.RequiredInput) != 6 {
			t.Fatalf("expected invalid_input with 6 required components, got %v", err)
		}
	})
}

func TestWriteSigError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteSigError(rec, &SigError{Code: ErrCodeInvalidInput, RequiredInput: []string{"@method", "content-digest"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get(HeaderSignatureError); got != `error=invalid_input, required_input=("@method" "content-digest")` {
		t.Fatalf("Signature-Error %q", got)
	}
	rec = httptest.NewRecorder()
	WriteSigError(rec, &SigError{Code: ErrCodeUnsupportedScheme, AcceptSchemes: []string{"hwk"}})
	if rec.Header().Get(HeaderAcceptSignatureScheme) != "hwk" {
		t.Fatalf("Accept-Signature-Scheme %q", rec.Header().Get(HeaderAcceptSignatureScheme))
	}
}

func TestThumbprintIgnoresAlgAndKid(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	k := Ed25519JWK(priv.Public().(ed25519.PublicKey))
	a, _ := k.Thumbprint()
	k.Kid, k.Alg = "kid-1", ""
	b, _ := k.Thumbprint()
	if a != b || a == "" {
		t.Fatalf("thumbprints differ: %s vs %s", a, b)
	}
}
