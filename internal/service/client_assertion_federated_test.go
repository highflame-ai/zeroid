package service

import "testing"

// Any account can add its own issuer and bind any subject string, so the
// client_id is always issuer-qualified: the same sub under two issuers (two
// clusters, or a lookalike issuer in another tenant) never shares one.
func TestFederatedClientID(t *testing.T) {
	for _, sub := range []string{"system:serviceaccount:agents:foo", "arn:aws:iam::111122223333:role/agent", "spiffe://example.org/agent"} {
		a, b := federatedClientID("https://issuer-a.example", sub), federatedClientID("https://issuer-b.example", sub)
		if a != "https://issuer-a.example#"+sub {
			t.Fatalf("got %q, want <iss>#<sub>", a)
		}
		if a == b {
			t.Fatalf("%q under two issuers shares a client_id", sub)
		}
	}
}
