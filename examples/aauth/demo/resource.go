package demo

import (
	"context"
	"crypto"
	"encoding/json"

	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	aauth "github.com/aauth-dev/aauth-go"

	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// ResourceConfig configures the demo resource.
type ResourceConfig struct {
	// Resource is the resource's identifier: https, host only. The bridged
	// tokens it accepts must name it as their resource.
	Resource string
	// AgentProviders are the Agent Provider issuers whose agent tokens
	// /whoami accepts (ZeroID's issuer).
	AgentProviders []string
	// ZeroIDIssuer is where /mcp introspects the bridged tokens it is shown,
	// so a revoked token stops working at once.
	ZeroIDIssuer string
	// HTTPClient makes discovery and introspection requests.
	HTTPClient *http.Client
}

// NewResource returns the demo resource:
//
//   - GET /whoami is an AAuth resource in agent-identity mode, guarded by
//     aauth-go's ResourceGuard: it verifies the request signature and the
//     agent token itself, discovering the Agent Provider's keys from its
//     metadata, and answers with the caller.
//   - POST /mcp stands in for an MCP server that only speaks OAuth: it takes
//     a DPoP-bound access token from ZeroID's bridge grant, checks the DPoP
//     proof against the token's cnf.jkt, and introspects the token.
func NewResource(cfg ResourceConfig) (http.Handler, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	resolver := trustedProviders{inner: aauth.NewJWKSResolver(cfg.HTTPClient), issuers: cfg.AgentProviders}
	guard, err := aauth.NewResourceGuard(aauth.ResourceGuardConfig{
		Resource: cfg.Resource,
		Verify:   aauth.TokenVerifyOptions{Resolver: resolver},
	})
	if err != nil {
		return nil, err
	}
	verifier, err := dpop.NewVerifier(dpop.Config{Store: dpop.NewMemoryStore()})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /whoami", guard.Require(aauth.Access{Level: aauth.AccessAgent}, http.HandlerFunc(whoami)))
	mux.Handle("POST /mcp", &mcpResource{cfg: cfg, dpop: verifier})
	mux.Handle("GET /.well-known/aauth-resource.json", guard.WellKnown())
	return mux, nil
}

func whoami(w http.ResponseWriter, r *http.Request) {
	caller, _ := aauth.CallerFromContext(r.Context())
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"agent":        caller.Agent,
		"agent_issuer": caller.AgentIssuer,
		"agent_jkt":    caller.AgentJKT,
		"token_type":   caller.TokenType,
	})
}

// trustedProviders resolves agent-token keys only for the configured Agent
// Providers. A valid signature proves only that some issuer signed a token.
type trustedProviders struct {
	inner   aauth.JWKSResolver
	issuers []string
}

func (t trustedProviders) ResolveKey(ctx context.Context, iss, dwk, kid string, jwk *aauth.JWK) (crypto.PublicKey, error) {
	if !slices.Contains(t.issuers, iss) {
		return nil, fmt.Errorf("agent provider %q is not trusted here", iss)
	}
	return t.inner.ResolveKey(ctx, iss, dwk, kid, jwk)
}

func (t trustedProviders) RefreshKey(ctx context.Context, iss, dwk, kid string, jwk *aauth.JWK) (crypto.PublicKey, error) {
	if !slices.Contains(t.issuers, iss) {
		return nil, fmt.Errorf("agent provider %q is not trusted here", iss)
	}
	return t.inner.RefreshKey(ctx, iss, dwk, kid, jwk)
}

type mcpResource struct {
	cfg  ResourceConfig
	dpop *dpop.Verifier
}

func (m *mcpResource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "DPoP") || token == "" {
		w.Header().Set("WWW-Authenticate", `DPoP algs="EdDSA ES256"`)
		writeJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "a DPoP-bound access token is required"})
		return
	}
	info, err := m.introspect(r.Context(), token)
	if err != nil {
		writeJSONResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	if active, _ := info["active"].(bool); !active {
		writeJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "the token is not active"})
		return
	}
	if !audienceIncludes(info["aud"], m.cfg.Resource) {
		writeJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "the token is not for this resource"})
		return
	}
	cnf, _ := info["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	if jkt == "" {
		writeJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "the token is not DPoP-bound"})
		return
	}
	if _, err := m.dpop.ValidateBoundToToken(r.Context(), dpop.ValidateRequest{
		ProofJWT:    r.Header.Get("DPoP"),
		Method:      r.Method,
		URL:         m.cfg.Resource + r.URL.Path,
		AccessToken: token,
	}, jkt); err != nil {
		writeJSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid_dpop_proof", "error_description": err.Error()})
		return
	}
	var call struct {
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&call)
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]any{"content": []map[string]string{{
			"type": "text",
			"text": fmt.Sprintf("ran %s for %v", call.Params.Name, info["sub"]),
		}}},
	})
}

func (m *mcpResource) introspect(ctx context.Context, token string) (map[string]any, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(m.cfg.ZeroIDIssuer, "/")+"/oauth2/token/introspect",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out map[string]any
	if err := doJSON(m.cfg.HTTPClient, req, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func audienceIncludes(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if a == want {
				return true
			}
		}
	}
	return false
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
