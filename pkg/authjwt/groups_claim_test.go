package authjwt_test

import (
	"context"
	"slices"
	"testing"
)

// TestGroupsClaim verifies the RFC 9068 §2.2.3.1 `groups` claim lands in the
// typed Groups field and not in Custom.
func TestGroupsClaim(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	c := baseClaims(issuer)
	c["groups"] = []string{"engineering", "oncall"}

	claims, err := v.Verify(context.Background(), ks.signRS256(t, c))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !slices.Equal(claims.Groups, []string{"engineering", "oncall"}) {
		t.Errorf("Groups = %#v, want [engineering oncall]", claims.Groups)
	}
	if _, ok := claims.GetCustom("groups"); ok {
		t.Error("groups leaked into Custom (should be typed-only)")
	}
}

// TestGroupsClaimAbsent: a token without the claim has no groups.
func TestGroupsClaimAbsent(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://auth.test.com"
	v := newVerifier(t, ks, issuer)

	claims, err := v.Verify(context.Background(), ks.signRS256(t, baseClaims(issuer)))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Groups != nil {
		t.Errorf("Groups = %#v, want nil", claims.Groups)
	}
}
