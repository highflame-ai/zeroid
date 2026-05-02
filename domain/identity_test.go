package domain

import (
	"strings"
	"testing"
)

// TestBuildWIMSEURIRejectsOver2048Bytes locks in SPIFFE §2.4. Today's
// varchar(255) schema makes this unreachable through the API surface — the
// test exists so a future schema bump can't silently mint over-cap IDs.
func TestBuildWIMSEURIRejectsOver2048Bytes(t *testing.T) {
	// 2200-byte external_id forces the assembled URI past 2048 bytes
	// regardless of any other field.
	tooLong := strings.Repeat("a", 2200)

	_, err := BuildWIMSEURI("highflame.ai", "acct", "proj", IdentityTypeAgent, tooLong)
	if err == nil {
		t.Fatalf("expected error for SPIFFE ID > %d bytes", MaxSPIFFEIDBytes)
	}
	if !strings.Contains(err.Error(), "exceeds 2048 bytes") {
		t.Fatalf("error must name the cap so callers can act on it; got %q", err.Error())
	}
}

// TestBuildWIMSEURIAcceptsTypicalSize covers the happy path so we'd notice
// if a future change tightened the cap by accident.
func TestBuildWIMSEURIAcceptsTypicalSize(t *testing.T) {
	uri, err := BuildWIMSEURI("highflame.ai", "acct-001", "proj-001", IdentityTypeAgent, "agent-1")
	if err != nil {
		t.Fatalf("unexpected error for short URI: %v", err)
	}
	want := "spiffe://highflame.ai/acct-001/proj-001/agent/agent-1"
	if uri != want {
		t.Fatalf("URI shape changed: got %q, want %q", uri, want)
	}
}

// TestBuildWIMSEURIBoundary checks the inclusive boundary at exactly the
// cap. 2048 bytes must succeed; 2049 must fail.
func TestBuildWIMSEURIBoundary(t *testing.T) {
	// Prefix length: "spiffe://" + "d" + "/" + "a" + "/" + "p" + "/" +
	// "agent" + "/" = 9 + 1 + 1 + 1 + 1 + 1 + 1 + 5 + 1 = 21.
	prefixLen := len("spiffe://d/a/p/agent/")
	atCap := strings.Repeat("a", MaxSPIFFEIDBytes-prefixLen)

	if _, err := BuildWIMSEURI("d", "a", "p", IdentityTypeAgent, atCap); err != nil {
		t.Fatalf("URI of exactly %d bytes should be allowed: %v", MaxSPIFFEIDBytes, err)
	}

	overCap := atCap + "a"
	if _, err := BuildWIMSEURI("d", "a", "p", IdentityTypeAgent, overCap); err == nil {
		t.Fatalf("URI of %d bytes should be rejected", MaxSPIFFEIDBytes+1)
	}
}
