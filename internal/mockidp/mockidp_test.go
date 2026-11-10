package mockidp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func TestMockIdP(t *testing.T) {
	idp, err := New("http://placeholder")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(idp.Handler())
	defer srv.Close()
	idp.SetBaseURL(srv.URL)

	fetchKeys := func(url string) jwk.Set {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var raw json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		set, err := jwk.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	mint := func(req MintRequest) (string, int) {
		b, _ := json.Marshal(req)
		resp, err := http.Post(srv.URL+"/mint", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		tok, _ := out["token"].(string)
		return tok, resp.StatusCode
	}

	t.Run("entra keys carry no alg, like Entra", func(t *testing.T) {
		set := fetchKeys(idp.EntraJWKSURI(DefaultEntraTenant))
		key, _ := set.Key(0)
		if _, ok := key.Algorithm(); ok {
			t.Fatal("Entra-shaped keys must omit alg")
		}
	})
	t.Run("entra ID token verifies with inferred alg and has the Entra claims", func(t *testing.T) {
		tok, status := mint(MintRequest{Profile: ProfileEntraIDToken, Claims: map[string]any{"aud": "app-1"}})
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
		parsed, err := jwt.Parse([]byte(tok), jwt.WithKeySet(fetchKeys(idp.EntraJWKSURI(DefaultEntraTenant)), jws.WithInferAlgorithmFromKey(true)))
		if err != nil {
			t.Fatal(err)
		}
		iss, _ := parsed.Issuer()
		if iss != idp.EntraIssuer(DefaultEntraTenant) {
			t.Fatalf("iss %s", iss)
		}
		for _, c := range []string{"oid", "tid", "xms_edov", "email"} {
			if !parsed.Has(c) {
				t.Fatalf("missing %s", c)
			}
		}
	})
	t.Run("okta ID-JAG is typed and names the agent in act", func(t *testing.T) {
		tok, _ := mint(MintRequest{Profile: ProfileOktaIDJAG, Claims: map[string]any{"aud": "https://zeroid", "resource": "https://mcp"}})
		msg, err := jws.Parse([]byte(tok))
		if err != nil {
			t.Fatal(err)
		}
		if typ, _ := msg.Signatures()[0].ProtectedHeaders().Type(); typ != "oauth-id-jag+jwt" {
			t.Fatalf("typ %s", typ)
		}
		parsed, err := jwt.Parse([]byte(tok), jwt.WithKeySet(fetchKeys(idp.OktaJWKSURI())))
		if err != nil {
			t.Fatal(err)
		}
		act, err := jwt.Get[map[string]any](parsed, "act")
		if err != nil || act["sub"] != "0oaAGENT" {
			t.Fatalf("act %v %v", act, err)
		}
	})
	t.Run("claims override and null removes", func(t *testing.T) {
		tok, _ := mint(MintRequest{Profile: ProfileK8sServiceAccount, Claims: map[string]any{"aud": "z", "sub": "system:serviceaccount:x:y", "nbf": nil}})
		parsed, _ := jwt.ParseInsecure([]byte(tok))
		if sub, _ := parsed.Subject(); sub != "system:serviceaccount:x:y" || parsed.Has("nbf") {
			t.Fatalf("sub %s nbf %v", sub, parsed.Has("nbf"))
		}
	})
	t.Run("aud is required and profiles are checked", func(t *testing.T) {
		if _, status := mint(MintRequest{Profile: ProfileEntraIDToken}); status != http.StatusBadRequest {
			t.Fatal("no aud must be refused")
		}
		if _, status := mint(MintRequest{Profile: "saml"}); status != http.StatusBadRequest {
			t.Fatal("unknown profile must be refused")
		}
	})
}
