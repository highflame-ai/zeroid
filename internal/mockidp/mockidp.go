// Package mockidp is a fake upstream IdP for local end-to-end runs and
// integration tests of trusted issuers (ADR 0042): an Entra-shaped tenant,
// an Okta-shaped org and a Kubernetes-shaped cluster issuer, each with its
// own signing key, plus a mint endpoint for the token shapes ZeroID must
// accept or refuse. It is a test fixture: it signs whatever it is asked to.
package mockidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// Token profiles POST /mint accepts.
const (
	ProfileEntraIDToken         = "entra_id_token"
	ProfileEntraAppOnly         = "entra_app_only"
	ProfileOktaIDJAG            = "okta_id_jag"
	ProfileK8sServiceAccount    = "k8s_sa"
	ProfileAccessTokenLookalike = "access_token_lookalike"
)

// DefaultEntraTenant is the tenant id used when a request names none.
const DefaultEntraTenant = "11111111-2222-3333-4444-555555555555"

// IdP is the fake IdP. Safe for concurrent use.
type IdP struct {
	mu   sync.RWMutex
	base string

	entra *rsa.PrivateKey
	okta  *rsa.PrivateKey
	k8s   *rsa.PrivateKey
}

// New builds an IdP whose issuers live under base (e.g. http://mockidp:8080).
func New(base string) (*IdP, error) {
	i := &IdP{base: strings.TrimRight(base, "/")}
	for _, k := range []**rsa.PrivateKey{&i.entra, &i.okta, &i.k8s} {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		*k = key
	}
	return i, nil
}

// SetBaseURL changes the URL the issuers are published under, for a server
// whose address is known only after it starts.
func (i *IdP) SetBaseURL(base string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.base = strings.TrimRight(base, "/")
}

func (i *IdP) baseURL() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.base
}

// EntraIssuer is an Entra tenant's v2.0 issuer.
func (i *IdP) EntraIssuer(tenant string) string {
	return i.baseURL() + "/entra/" + tenant + "/v2.0"
}

// EntraJWKSURI is an Entra tenant's key set.
func (i *IdP) EntraJWKSURI(tenant string) string {
	return i.baseURL() + "/entra/" + tenant + "/discovery/v2.0/keys"
}

// OktaIssuer is the Okta org authorization server's issuer.
func (i *IdP) OktaIssuer() string { return i.baseURL() + "/okta" }

// OktaJWKSURI is the Okta org's key set.
func (i *IdP) OktaJWKSURI() string { return i.baseURL() + "/okta/oauth2/v1/keys" }

// K8sIssuer is the cluster's service-account issuer.
func (i *IdP) K8sIssuer() string { return i.baseURL() + "/k8s" }

// K8sJWKSURI is the cluster's key set.
func (i *IdP) K8sJWKSURI() string { return i.baseURL() + "/k8s/openid/v1/jwks" }

const (
	entraKID = "entra-mock-key"
	oktaKID  = "okta-mock-key"
	k8sKID   = "k8s-mock-key"
)

// Handler serves discovery, keys and POST /mint.
func (i *IdP) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /entra/{tid}/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		tid := r.PathValue("tid")
		base := i.baseURL() + "/entra/" + tid + "/oauth2/v2.0"
		writeJSON(w, http.StatusOK, discovery(i.EntraIssuer(tid), i.EntraJWKSURI(tid), base+"/authorize", base+"/token"))
	})
	// Entra publishes keys with no alg member.
	mux.HandleFunc("GET /entra/{tid}/discovery/v2.0/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, keySet(&i.entra.PublicKey, entraKID, false))
	})
	mux.HandleFunc("GET /okta/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, discovery(i.OktaIssuer(), i.OktaJWKSURI(), i.OktaIssuer()+"/oauth2/v1/authorize", i.OktaIssuer()+"/oauth2/v1/token"))
	})
	mux.HandleFunc("GET /okta/oauth2/v1/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, keySet(&i.okta.PublicKey, oktaKID, true))
	})
	mux.HandleFunc("GET /k8s/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, discovery(i.K8sIssuer(), i.K8sJWKSURI(), "", ""))
	})
	mux.HandleFunc("GET /k8s/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, keySet(&i.k8s.PublicKey, k8sKID, true))
	})
	mux.HandleFunc("POST /mint", func(w http.ResponseWriter, r *http.Request) {
		var req MintRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be a JSON MintRequest"})
			return
		}
		tok, claims, err := i.Mint(req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": tok, "claims": claims})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

// MintRequest is POST /mint. Claims override the profile's defaults; a JSON
// null removes a claim. HeaderTyp overrides the JWS typ header.
type MintRequest struct {
	Profile    string         `json:"profile"`
	Tenant     string         `json:"tenant,omitempty"`
	Claims     map[string]any `json:"claims,omitempty"`
	HeaderTyp  *string        `json:"header_typ,omitempty"`
	TTLSeconds int            `json:"ttl_seconds,omitempty"`
}

// Mint signs a token of the requested profile and returns it with its
// claims.
func (i *IdP) Mint(req MintRequest) (string, map[string]any, error) {
	now := time.Now()
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	tenant := req.Tenant
	if tenant == "" {
		tenant = DefaultEntraTenant
	}
	claims := map[string]any{"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(ttl).Unix()}
	var (
		key *rsa.PrivateKey
		kid string
		typ = "JWT"
	)
	switch req.Profile {
	case ProfileEntraIDToken:
		key, kid = i.entra, entraKID
		merge(claims, map[string]any{
			"ver": "2.0", "iss": i.EntraIssuer(tenant), "tid": tenant,
			"sub": "pairwise-" + randomID(), "oid": "00000000-0000-0000-0000-" + randomHex(12),
			"email": "alice@contoso.example", "xms_edov": true, "name": "Alice Example",
			"preferred_username": "alice@contoso.example",
		})
	case ProfileEntraAppOnly:
		key, kid = i.entra, entraKID
		oid := "00000000-0000-0000-0000-" + randomHex(12)
		merge(claims, map[string]any{
			"ver": "2.0", "iss": i.EntraIssuer(tenant), "tid": tenant,
			"sub": oid, "oid": oid, "idtyp": "app", "roles": []string{"Agent.Run"},
		})
	case ProfileAccessTokenLookalike:
		key, kid = i.entra, entraKID
		merge(claims, map[string]any{
			"ver": "2.0", "iss": i.EntraIssuer(tenant), "tid": tenant,
			"sub": "pairwise-" + randomID(), "oid": "00000000-0000-0000-0000-" + randomHex(12),
			"scp": "User.Read", "email": "alice@contoso.example", "xms_edov": true,
		})
	case ProfileOktaIDJAG:
		key, kid, typ = i.okta, oktaKID, "oauth-id-jag+jwt"
		merge(claims, map[string]any{
			"iss": i.OktaIssuer(), "sub": "00u" + randomID(), "jti": randomID(),
			"email": "alice@contoso.example", "email_verified": true, "client_id": "0oaAGENT",
			"act": map[string]any{"sub": "0oaAGENT", "sub_profile": "ai_agent"},
		})
	case ProfileK8sServiceAccount:
		key, kid = i.k8s, k8sKID
		merge(claims, map[string]any{
			"iss": i.K8sIssuer(), "sub": "system:serviceaccount:default:agent",
			"kubernetes.io": map[string]any{"namespace": "default", "serviceaccount": map[string]any{"name": "agent"}},
		})
	default:
		return "", nil, fmt.Errorf("unknown profile %q (want %s, %s, %s, %s or %s)", req.Profile,
			ProfileEntraIDToken, ProfileEntraAppOnly, ProfileOktaIDJAG, ProfileK8sServiceAccount, ProfileAccessTokenLookalike)
	}
	for k, v := range req.Claims {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	if _, ok := claims["aud"]; !ok {
		return "", nil, errors.New(`claims.aud is required: the agent's app id for an ID token, ZeroID's issuer for an ID-JAG`)
	}
	if req.HeaderTyp != nil {
		typ = *req.HeaderTyp
	}

	tok := jwt.New()
	for k, v := range claims {
		if err := tok.Set(k, v); err != nil {
			return "", nil, fmt.Errorf("claim %s: %w", k, err)
		}
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.KeyIDKey, kid)
	if typ != "" {
		_ = hdr.Set(jws.TypeKey, typ)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", nil, err
	}
	return string(signed), claims, nil
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

// discovery is an issuer's discovery document. The authorization and token
// endpoints are advertised (a Kubernetes issuer has none) but not served:
// tokens come from POST /mint, with any nonce in claims.
func discovery(iss, jwksURI, authorizationEndpoint, tokenEndpoint string) map[string]any {
	doc := map[string]any{
		"issuer":                                iss,
		"jwks_uri":                              jwksURI,
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code", "id_token"},
		"subject_types_supported":               []string{"pairwise"},
	}
	if authorizationEndpoint != "" {
		doc["authorization_endpoint"] = authorizationEndpoint
		doc["token_endpoint"] = tokenEndpoint
	}
	return doc
}

func keySet(pub *rsa.PublicKey, kid string, withAlg bool) jwk.Set {
	key, err := jwk.Import[jwk.Key](pub)
	if err != nil {
		panic(err)
	}
	_ = key.Set(jwk.KeyIDKey, kid)
	_ = key.Set(jwk.KeyUsageKey, jwk.ForSignature)
	if withAlg {
		_ = key.Set(jwk.AlgorithmKey, jwa.RS256())
	}
	set := jwk.NewSet()
	_ = set.AddKey(key)
	return set
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomID() string { return randomHex(16) }

func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)[:n]
}
