package authjwt_test

import (
	"context"
	"testing"
)

// The service-token accessors read what Verify extracted from a signed token,
// end to end.
func TestServiceTokenAccessorsAfterVerify(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	c := baseClaims(issuer)
	c["client_id"] = "gw"
	c["resource"] = []string{"urn:example:svc:a"}
	c["act"] = map[string]any{"sub": "spiffe://zeroid.test/platform/p/service/gw", "client_id": "gw"}

	claims, err := v.Verify(context.Background(), ks.signES256(t, c))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := claims.ClientID(); got != "gw" {
		t.Errorf("ClientID() = %q, want gw", got)
	}
	if got := claims.ActorClientID(); got != "gw" {
		t.Errorf("ActorClientID() = %q, want gw", got)
	}
	if err := claims.RequireResource("urn:example:svc:a"); err != nil {
		t.Errorf("RequireResource: %v", err)
	}
	if err := claims.RequireResource("https://shield.example.com"); err == nil {
		t.Error("RequireResource accepted the audience, which is not a resource binding")
	}
}
