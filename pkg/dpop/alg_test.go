package dpop

import "testing"

func TestAllowedAlgorithms_RejectsHazardous(t *testing.T) {
	// These MUST NOT appear in the allow-list. The whole package's security
	// rests on this — if any of them sneak in, algorithm confusion is back.
	hazardous := []string{"none", "None", "NONE", "HS256", "HS384", "HS512"}
	for _, alg := range hazardous {
		if isAllowedAlg(alg) {
			t.Fatalf("alg %q must NOT be in the allow-list", alg)
		}
	}
}

func TestAllowedAlgorithms_AcceptsExpected(t *testing.T) {
	expected := []string{
		"ES256", "ES384", "ES512",
		"EdDSA",
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
	}
	for _, alg := range expected {
		if !isAllowedAlg(alg) {
			t.Fatalf("alg %q must be in the allow-list", alg)
		}
	}
}

func TestAllowedAlgorithms_Sorted(t *testing.T) {
	got := AllowedAlgorithms()
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("AllowedAlgorithms must be sorted: %v", got)
		}
	}
}

func TestAllowedAlgorithms_LengthMatches(t *testing.T) {
	if len(AllowedAlgorithms()) != len(allowedAlgs) {
		t.Fatalf("AllowedAlgorithms() length = %d; want %d", len(AllowedAlgorithms()), len(allowedAlgs))
	}
}
