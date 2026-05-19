package service

import (
	"strings"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

// The correctness crux of workload-attested signing: a merely-expired
// (rotated / pod-gone) key must still VERIFY historical attestations
// within the audit-retention window; only a REVOKED key fails outright.
// A not_after-only filter cannot express this — these tests pin it.

func TestSigningCredential_VerifiableVsSignable(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name           string
		notAfter       time.Time
		retentionUntil time.Time
		revoked        bool
		wantSignable   bool
		wantVerifiable bool
	}{
		{
			name:           "fresh key: signable and verifiable",
			notAfter:       now.Add(time.Hour),
			retentionUntil: now.Add(400 * 24 * time.Hour),
			wantSignable:   true,
			wantVerifiable: true,
		},
		{
			name:           "expired-but-retained: NOT signable, STILL verifiable",
			notAfter:       now.Add(-2 * time.Hour), // operational window passed (rotation)
			retentionUntil: now.Add(300 * 24 * time.Hour),
			wantSignable:   false,
			wantVerifiable: true, // the property that matters for historical receipts
		},
		{
			name:           "revoked: neither signable nor verifiable (even within retention)",
			notAfter:       now.Add(time.Hour),
			retentionUntil: now.Add(400 * 24 * time.Hour),
			revoked:        true,
			wantSignable:   false,
			wantVerifiable: false,
		},
		{
			name:           "past retention: not verifiable (audit window elapsed)",
			notAfter:       now.Add(-300 * 24 * time.Hour),
			retentionUntil: now.Add(-time.Hour),
			wantSignable:   false,
			wantVerifiable: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &domain.SigningCredential{
				NotAfter:            tc.notAfter,
				AuditRetentionUntil: tc.retentionUntil,
				Revoked:             tc.revoked,
			}

			if got := c.SignableNow(now); got != tc.wantSignable {
				t.Errorf("SignableNow = %v, want %v", got, tc.wantSignable)
			}

			if got := c.VerifiableNow(now); got != tc.wantVerifiable {
				t.Errorf("VerifiableNow = %v, want %v", got, tc.wantVerifiable)
			}
		})
	}
}

func TestMintKID(t *testing.T) {
	const n = 20000

	seen := make(map[string]struct{}, n)

	for i := 0; i < n; i++ {
		k, err := mintKID("receipt", "highflame-shield")
		if err != nil {
			t.Fatalf("mintKID error: %v", err)
		}

		if _, dup := seen[k]; dup {
			t.Fatalf("kid collision after %d iterations: %q", i, k)
		}

		seen[k] = struct{}{}
	}

	// Format: <purpose>-<workload>-<16 hex>.
	k, _ := mintKID("receipt", "highflame-shield")
	if !strings.HasPrefix(k, "receipt-highflame-shield-") {
		t.Fatalf("unexpected kid prefix: %q", k)
	}

	// Hostile workload/purpose must be neutralized — kid is echoed into
	// receipts and the JWKS.
	bad, _ := mintKID("RE CEIPT", "Evil/../Workload\n")
	for _, frag := range []string{"/", "..", "\n", " ", "EVIL", "RE CEIPT"} {
		if strings.Contains(bad, frag) {
			t.Fatalf("kid %q contains un-sanitized fragment %q", bad, frag)
		}
	}

	for _, r := range bad {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			t.Fatalf("kid %q has illegal rune %q", bad, r)
		}
	}
}

func TestAttest_RejectsInvalidInput(t *testing.T) {
	// Validation happens before any repo call, so a nil repo is safe here
	// and proves these requests never reach persistence.
	s := NewSigningCredentialService(nil, 3600, 400, []string{"receipt"}, "receipt", "")
	ctx := t.Context()

	valid := func() AttestRequest {
		return AttestRequest{
			Workload:  "highflame-shield",
			PublicKey: strings.Repeat("A", 43), // 32 bytes base64url ≈ 43 chars
			Algorithm: domain.SigningAlgorithmEdDSA,
			Purpose:   "receipt", // in the test service's AllowedPurposes
		}
	}

	t.Run("missing workload", func(t *testing.T) {
		r := valid()
		r.Workload = ""

		if _, err := s.Attest(ctx, r); err == nil {
			t.Fatal("expected rejection for missing workload")
		}
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		r := valid()
		r.Algorithm = "RS256"

		if _, err := s.Attest(ctx, r); err == nil {
			t.Fatal("expected rejection for non-EdDSA algorithm")
		}
	})

	t.Run("disallowed purpose", func(t *testing.T) {
		r := valid()
		r.Purpose = "exfiltrate"

		if _, err := s.Attest(ctx, r); err == nil {
			t.Fatal("expected rejection for disallowed purpose")
		}
	})

	t.Run("malformed public key", func(t *testing.T) {
		r := valid()
		r.PublicKey = "not-base64url-or-wrong-size"

		if _, err := s.Attest(ctx, r); err == nil {
			t.Fatal("expected rejection for malformed public key")
		}
	})
}
