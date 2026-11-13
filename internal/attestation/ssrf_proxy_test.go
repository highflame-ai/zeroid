package attestation

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
)

// The guard checks the address it dials. Through a proxy it would dial, and
// check, only the proxy, so the guarded transport must ignore HTTPS_PROXY.
func TestSSRFGuardedTransport_NoProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.example:3128")
	for _, allow := range []bool{false, true} {
		client := NewSSRFGuardedHTTPClient(allow)
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport is %T", client.Transport)
		}
		if tr.Proxy != nil {
			t.Fatalf("allowPrivate=%v: the guarded transport must not use a proxy", allow)
		}
	}
}

func TestGuardedRedirect(t *testing.T) {
	req := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	strict, dev := guardedRedirect(false), guardedRedirect(true)
	if err := strict(req("https://keys.example/k"), make([]*http.Request, 1)); err != nil {
		t.Fatalf("an https redirect is followed: %v", err)
	}
	if err := strict(req("http://keys.example/k"), make([]*http.Request, 1)); !errors.Is(err, ErrInsecureRedirect) {
		t.Fatal("a downgrade to http is refused")
	}
	if err := strict(req("https://keys.example/k"), make([]*http.Request, 3)); !errors.Is(err, ErrInsecureRedirect) {
		t.Fatal("a fourth redirect is refused")
	}
	if err := dev(req("http://mockidp:8080/k"), make([]*http.Request, 1)); err != nil {
		t.Fatal("with private endpoints allowed, local http redirects are followed")
	}
	if NewSSRFGuardedHTTPClient(false).CheckRedirect == nil {
		t.Fatal("the guarded client must check redirects")
	}
}
