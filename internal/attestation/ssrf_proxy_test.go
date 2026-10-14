package attestation

import (
	"net/http"
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
