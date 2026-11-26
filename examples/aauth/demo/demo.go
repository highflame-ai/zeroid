// Package demo is the agent and resource side of the ZeroID AAuth demo: where
// a workload gets its platform token, the agent key it keeps for the life of
// its pod, the bridge exchange, and a small MCP-style resource that accepts
// the bridged DPoP-bound token. The AAuth request signing and agent-token
// verification are aauth-go's, the reference implementation, so the demo
// also checks ZeroID against an independent implementation.
package demo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PlatformToken returns a workload's platform identity token for audience.
type PlatformToken func(ctx context.Context, audience string) (string, error)

// MockIdPToken mints a Kubernetes service account token from the mock IdP
// (cmd/zeroid-mockidp), standing in for the kubelet in local runs.
func MockIdPToken(hc *http.Client, mockIdPURL, subject string) PlatformToken {
	return func(ctx context.Context, audience string) (string, error) {
		body, _ := json.Marshal(map[string]any{
			"profile": "k8s_sa",
			"claims":  map[string]any{"sub": subject, "aud": audience, "jti": randomID()},
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(mockIdPURL, "/")+"/mint", bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		var out struct {
			Token string `json:"token"`
		}
		if err := doJSON(hc, req, &out); err != nil {
			return "", fmt.Errorf("mock IdP: %w", err)
		}
		return out.Token, nil
	}
}

// FileToken reads a projected service account token from path: what a pod
// on EKS, GKE or AKS mounts when its spec projects a token with audience set
// to ZeroID's issuer and expirationSeconds 600. The kubelet rotates the file;
// it is read fresh every time. Written for real clusters; not exercised by
// the local demo.
func FileToken(path string) PlatformToken {
	return func(context.Context, string) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
}

// AWSToken gets an STS web identity token for audience with the AWS CLI
// (aws sts get-web-identity-token), from the principal the workload runs as.
// The account needs outbound identity federation enabled
// (aws iam enable-outbound-web-identity-federation) and the principal
// sts:GetWebIdentityToken. The CLI requires a signing algorithm; ZeroID
// accepts RS256 (the default here) and ES384.
func AWSToken(signingAlgorithm string) PlatformToken {
	if signingAlgorithm == "" {
		signingAlgorithm = "RS256"
	}
	return func(ctx context.Context, audience string) (string, error) {
		args := []string{"sts", "get-web-identity-token", "--audience", audience,
			"--signing-algorithm", signingAlgorithm, "--output", "json"}
		out, err := exec.CommandContext(ctx, "aws", args...).Output()
		if err != nil {
			return "", fmt.Errorf("aws sts get-web-identity-token: %w", err)
		}
		var resp struct {
			WebIdentityToken string `json:"WebIdentityToken"`
		}
		if err := json.Unmarshal(out, &resp); err != nil || resp.WebIdentityToken == "" {
			return "", errors.New("aws sts get-web-identity-token: no WebIdentityToken in the response")
		}
		return resp.WebIdentityToken, nil
	}
}

// LoadOrCreateKey returns the agent's Ed25519 key from path, creating it the
// first time. Point every container of a pod at one path on a shared emptyDir:
// the pod keeps one agent key for its life, which is what lets a restarted
// container or a second worker redeem the pod's platform token again at
// ZeroID's /ap/token (ZeroID refuses any other key for that token).
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("%s is not PEM", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an Ed25519 key", path)
		}
		return priv, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// O_EXCL: two workers starting at once must not each write their own key.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateKey(path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return nil, err
	}
	return priv, nil
}

// DPoPProof is an RFC 9449 proof for method and htu, signed by key. With an
// access token, it carries ath. Ed25519 proofs use the JOSE name EdDSA,
// which ZeroID's pkg/dpop requires; AAuth names the same key Ed25519.
func DPoPProof(key ed25519.PrivateKey, method, htu, accessToken string) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	x := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	claims := map[string]any{"jti": randomID(), "htm": method, "htu": htu, "iat": time.Now().Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	signing := enc(map[string]any{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": x}}) +
		"." + enc(claims)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signing)))
}

// BridgeGrantType exchanges an AAuth agent token for an OAuth access token.
const BridgeGrantType = "urn:highflame:params:oauth:grant-type:aauth-agent-token"

// Bridge exchanges agentToken at ZeroID's token endpoint for a DPoP-bound
// OAuth access token for resource, proving possession of the agent key with
// a DPoP proof.
func Bridge(ctx context.Context, hc *http.Client, issuer, agentToken string, key ed25519.PrivateKey, resource, scope string) (string, error) {
	tokenEndpoint := strings.TrimRight(issuer, "/") + "/oauth2/token"
	body, _ := json.Marshal(map[string]any{
		"grant_type":    BridgeGrantType,
		"subject_token": agentToken,
		"resource":      resource,
		"scope":         scope,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", DPoPProof(key, http.MethodPost, tokenEndpoint, ""))
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := doJSON(hc, req, &out); err != nil {
		return "", fmt.Errorf("bridge: %w", err)
	}
	if out.TokenType != "DPoP" {
		return "", fmt.Errorf("bridge: token_type %q, want DPoP", out.TokenType)
	}
	return out.AccessToken, nil
}

// CallMCP calls a tool on the MCP-style resource with a DPoP-bound token.
func CallMCP(ctx context.Context, hc *http.Client, url, accessToken string, key ed25519.PrivateKey, tool string) (map[string]any, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", DPoPProof(key, http.MethodPost, url, accessToken))
	var out map[string]any
	if err := doJSON(hc, req, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// StatusError is a non-2xx answer.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string { return fmt.Sprintf("status %d: %s", e.Status, e.Body) }

func doJSON(hc *http.Client, req *http.Request, out any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return &StatusError{Status: resp.StatusCode, Body: string(raw)}
	}
	return json.Unmarshal(raw, out)
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
