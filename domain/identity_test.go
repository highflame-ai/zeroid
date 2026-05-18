package domain

import (
	"errors"
	"strings"
	"testing"
)

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
