package authjwt_test

import (
	"context"
	"testing"
)

// TestResourceClaim verifies the RFC 8707 `resource` claim lands in the typed
// Resource field. A PEP gates resource enforcement on this field, so it must
// not require digging through Custom.
func TestResourceClaim(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	c := baseClaims(issuer)
	c["resource"] = []string{"https://gw.example.com/mcp/github"}

	claims, err := v.Verify(context.Background(), ks.signRS256(t, c))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if len(claims.Resource) != 1 || claims.Resource[0] != "https://gw.example.com/mcp/github" {
		t.Errorf("Resource = %#v, want [https://gw.example.com/mcp/github]", claims.Resource)
	}

	// Known claim → typed home only, never duplicated into Custom.
	if _, ok := claims.GetCustom("resource"); ok {
		t.Error("resource leaked into Custom (should be typed-only)")
	}
}

// TestResourceClaimSingleString covers RFC 8707's other legal shape: a single
// URI string rather than an array. ZeroID mints the array, but a bare string
// must not degrade to "unbound" — that direction fails open.
func TestResourceClaimSingleString(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	c := baseClaims(issuer)
	c["resource"] = "https://gw.example.com/mcp/github"

	claims, err := v.Verify(context.Background(), ks.signRS256(t, c))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if len(claims.Resource) != 1 || claims.Resource[0] != "https://gw.example.com/mcp/github" {
		t.Errorf("Resource = %#v, want the single string normalized to a one-element slice", claims.Resource)
	}
}

// TestResourceClaimAbsent is the shield#366 regression at the library boundary.
// baseClaims carries an `aud` (ZeroID stamps one on EVERY token, defaulting to
// the issuer URL for JWT-SVID §3) but no `resource`. Resource must stay empty:
// it is the sole signal a PEP may gate resource enforcement on, and a non-empty
// `aud` must never be mistaken for a binding.
func TestResourceClaimAbsent(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	c := baseClaims(issuer) // has `aud`, no `resource`

	claims, err := v.Verify(context.Background(), ks.signRS256(t, c))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if len(claims.Audience) == 0 {
		t.Fatal("precondition: baseClaims must carry an aud for this regression to mean anything")
	}

	if len(claims.Resource) != 0 {
		t.Errorf("Resource = %#v, want empty — a token with aud but no `resource` "+
			"is NOT resource-bound (shield#366)", claims.Resource)
	}
}
