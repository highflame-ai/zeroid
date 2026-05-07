package service

import "testing"

// TestExtractMappedClaimString covers the v1 claim-mapping shapes the three
// reference IdPs (Okta, Entra, Google) emit. v1 is single-level only — no
// JSONPath, no expressions.
func TestExtractMappedClaimString(t *testing.T) {
	t.Run("string sub from Okta", func(t *testing.T) {
		got, ok := extractMappedClaimString(map[string]any{"sub": "00uABC"}, "sub")
		if !ok || got != "00uABC" {
			t.Fatalf("expected (00uABC, true), got (%q, %v)", got, ok)
		}
	})

	t.Run("numeric oid from Entra is stringified", func(t *testing.T) {
		got, ok := extractMappedClaimString(map[string]any{"oid": float64(42)}, "oid")
		if !ok || got != "42" {
			t.Fatalf("expected (42, true), got (%q, %v)", got, ok)
		}
	})

	t.Run("missing path returns false", func(t *testing.T) {
		_, ok := extractMappedClaimString(map[string]any{"sub": "x"}, "email")
		if ok {
			t.Fatalf("expected ok=false for missing claim")
		}
	})

	t.Run("empty path returns false", func(t *testing.T) {
		_, ok := extractMappedClaimString(map[string]any{"sub": "x"}, "")
		if ok {
			t.Fatalf("empty path means no mapping configured; should be ok=false")
		}
	})

	t.Run("non-stringifiable value returns false", func(t *testing.T) {
		_, ok := extractMappedClaimString(map[string]any{"sub": map[string]any{}}, "sub")
		if ok {
			t.Fatalf("nested object cannot be coerced to string in v1; should be ok=false")
		}
	})
}

// TestCheckExternalIDTokenAlg verifies that the algorithm gate refuses
// none/HS* family tokens up front and respects the configured allow-list.
//
// We exercise it with crafted JWS strings rather than spinning up a real
// signer — the function only reads the protected header.
func TestCheckExternalIDTokenAlg(t *testing.T) {
	// alg=none token: header={"alg":"none","typ":"JWT"}, no signature.
	// Build by hand — base64url("{\"alg\":\"none\",\"typ\":\"JWT\"}") + ".eyJ9." (empty body, empty sig)
	// We don't bother — jws.Parse rejects unsigned tokens.
	// Instead we test alg=HS256 which has the same payload structure but is rejected.
	// HS256 header: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
	hs256 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4In0.AAAA"
	if err := checkExternalIDTokenAlg(hs256, []string{"RS256", "ES256"}); err == nil {
		t.Fatalf("expected HS256 to be rejected as non-asymmetric, got nil")
	}

	// RS256 with explicit allow-list match — header eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
	rs256 := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4In0.AAAA"
	if err := checkExternalIDTokenAlg(rs256, []string{"RS256"}); err != nil {
		t.Fatalf("expected RS256 to pass with allow-list [RS256], got %v", err)
	}

	// RS256 with an allow-list that excludes it.
	if err := checkExternalIDTokenAlg(rs256, []string{"ES256"}); err == nil {
		t.Fatalf("expected RS256 to be rejected when allow-list is [ES256]")
	}

	// Empty allow-list → defaults to the hard whitelist of asymmetric algs.
	if err := checkExternalIDTokenAlg(rs256, nil); err != nil {
		t.Fatalf("expected RS256 to pass with empty allow-list, got %v", err)
	}
}
