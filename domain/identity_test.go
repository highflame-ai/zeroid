package domain

import (
	"errors"
	"strings"
	"testing"
)

// TestValidateWIMSEURI pins the shape contract used by /identities/by-wimse:
// only well-formed spiffe:// URIs with a trust domain and a workload path
// pass. Anything else returns a wrapped ErrInvalidWIMSEURI so handlers can
// errors.Is and map to 400.
func TestValidateWIMSEURI(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		if err := ValidateWIMSEURI("spiffe://highflame.dev/acct/proj/agent/my-agent"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("rejection cases", func(t *testing.T) {
		cases := []struct {
			name string
			uri  string
		}{
			{"empty", ""},
			{"missing scheme", "highflame.dev/acct/proj/agent/x"},
			{"wrong scheme", "https://highflame.dev/acct/proj/agent/x"},
			{"missing host", "spiffe:///acct/proj/agent/x"},
			{"bare trust domain", "spiffe://highflame.dev"},
			{"trust domain with empty path", "spiffe://highflame.dev/"},
			{"with query", "spiffe://highflame.dev/acct/proj/agent/x?foo=bar"},
			{"with trailing question mark", "spiffe://highflame.dev/acct/proj/agent/x?"},
			{"with fragment", "spiffe://highflame.dev/acct/proj/agent/x#frag"},
			{"with user-info", "spiffe://user:pass@highflame.dev/acct/proj/agent/x"},
			{"trust domain with port", "spiffe://highflame.dev:443/acct/proj/agent/x"},
			{"path with trailing slash", "spiffe://highflame.dev/acct/proj/agent/x/"},
			{"path with empty segment", "spiffe://highflame.dev/acct//agent/x"},
			{"path segment with space", "spiffe://highflame.dev/acct/proj/agent/my agent"},
			{"path segment with special char", "spiffe://highflame.dev/acct/proj/agent/my$agent"},
			{"too long", "spiffe://highflame.dev/" + strings.Repeat("a", MaxSPIFFEIDBytes)},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := ValidateWIMSEURI(tc.uri)
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.uri)
				}
				if !errors.Is(err, ErrInvalidWIMSEURI) {
					t.Fatalf("error not wrapped with ErrInvalidWIMSEURI: %v", err)
				}
			})
		}
	})
}

// TestIdentityStatusExpired_Valid confirms expired is a valid status.
func TestIdentityStatusExpired_Valid(t *testing.T) {
	if !IdentityStatusExpired.Valid() {
		t.Fatal("IdentityStatusExpired.Valid() = false, want true")
	}
}

// TestIdentityStatusExpired_IsUsable confirms expired identities cannot authenticate.
func TestIdentityStatusExpired_IsUsable(t *testing.T) {
	if IdentityStatusExpired.IsUsable() {
		t.Fatal("IdentityStatusExpired.IsUsable() = true, want false")
	}
}

// TestCanTransitionTo_Expired pins the expired state machine transitions.
func TestCanTransitionTo_Expired(t *testing.T) {
	tests := []struct {
		from   IdentityStatus
		to     IdentityStatus
		expect bool
	}{
		// Into expired
		{IdentityStatusActive, IdentityStatusExpired, true},
		{IdentityStatusSuspended, IdentityStatusExpired, true},
		{IdentityStatusPending, IdentityStatusExpired, false},
		{IdentityStatusDeactivated, IdentityStatusExpired, false},
		// Out of expired
		{IdentityStatusExpired, IdentityStatusDeactivated, true},
		{IdentityStatusExpired, IdentityStatusActive, false},
		{IdentityStatusExpired, IdentityStatusSuspended, false},
		{IdentityStatusExpired, IdentityStatusPending, false},
		{IdentityStatusExpired, IdentityStatusExpired, false},
	}
	for _, tc := range tests {
		name := string(tc.from) + " → " + string(tc.to)
		t.Run(name, func(t *testing.T) {
			got := tc.from.CanTransitionTo(tc.to)
			if got != tc.expect {
				t.Fatalf("CanTransitionTo = %v, want %v", got, tc.expect)
			}
		})
	}
}

// TestBuildWIMSEURI_LengthCap pins the SPIFFE §2.4 invariant: any URI that
// would exceed MaxSPIFFEIDBytes is rejected at construction time, returning
// ErrSPIFFEIDTooLong so callers can errors.Is. Three cases — happy path, the
// inclusive boundary at exactly 2048 bytes, and the rejection just past it.
func TestBuildWIMSEURI_LengthCap(t *testing.T) {
	// Happy path: a typical URI is well under the cap.
	uri, err := BuildWIMSEURI("highflame.dev", "acc_test", "proj_test", IdentityTypeAgent, "orchestrator-1")
	if err != nil {
		t.Fatalf("happy path returned error: %v", err)
	}
	if !strings.HasPrefix(uri, "spiffe://highflame.dev/acc_test/proj_test/agent/") {
		t.Fatalf("unexpected URI shape: %q", uri)
	}

	// Inclusive boundary: assemble an external_id that brings the total to
	// exactly MaxSPIFFEIDBytes. The fixed prefix
	// "spiffe://highflame.dev/acc/proj/agent/" plus the external_id must
	// equal 2048 bytes — anything ≤ 2048 must succeed.
	prefix := "spiffe://highflame.dev/acc/proj/agent/"
	exactExternalID := strings.Repeat("a", MaxSPIFFEIDBytes-len(prefix))
	uri, err = BuildWIMSEURI("highflame.dev", "acc", "proj", IdentityTypeAgent, exactExternalID)
	if err != nil {
		t.Fatalf("boundary case (exactly %d bytes) returned error: %v", MaxSPIFFEIDBytes, err)
	}
	if got, want := len(uri), MaxSPIFFEIDBytes; got != want {
		t.Fatalf("boundary URI length = %d, want %d", got, want)
	}

	// Rejection: one byte over the cap must fail with ErrSPIFFEIDTooLong.
	overExternalID := exactExternalID + "a"
	_, err = BuildWIMSEURI("highflame.dev", "acc", "proj", IdentityTypeAgent, overExternalID)
	if err == nil {
		t.Fatal("URI 1 byte over the cap was accepted; want ErrSPIFFEIDTooLong")
	}
	if !errors.Is(err, ErrSPIFFEIDTooLong) {
		t.Fatalf("error not ErrSPIFFEIDTooLong: %v", err)
	}
}
