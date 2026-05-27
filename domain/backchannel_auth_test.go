package domain_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

// TestParseAuthorizationDetails_BackwardCompatible covers the legacy CIBA
// path: a client that omits the `authorization_details` parameter, or sends
// it as JSON null / empty array, must produce a nil-or-empty typed slice and
// no error. This is the contract that lets pre-RAR clients keep working
// unchanged after the field lands.
func TestParseAuthorizationDetails_BackwardCompatible(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"nil bytes", nil},
		{"empty bytes", []byte{}},
		{"json null", []byte("null")},
		{"empty array", []byte("[]")},
		// Whitespace-only inputs are unreachable from the HTTP path today
		// (Huma's JSON decoder would never hand us bare whitespace bytes),
		// but the function's contract promises they are treated as "no RAR
		// supplied". These cases pin that contract so a future refactor
		// can't silently regress it.
		{"single space", []byte(" ")},
		{"multiple spaces", []byte("   ")},
		{"newline", []byte("\n")},
		{"mixed whitespace", []byte("\t\n  ")},
		{"json null with surrounding whitespace", []byte("  null  ")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := domain.ParseAuthorizationDetails(c.raw)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if len(got) != 0 {
				t.Errorf("expected empty slice, got len=%d", len(got))
			}
		})
	}
}

// TestParseAuthorizationDetails_SingleElement validates a well-formed
// single-element payload: the typed slice has one entry whose Type matches
// and whose Raw preserves the original JSON object bytes verbatim.
func TestParseAuthorizationDetails_SingleElement(t *testing.T) {
	raw := []byte(`[{"type":"highflame_tool_call","tool":"transfer_funds","amount":50000}]`)
	got, err := domain.ParseAuthorizationDetails(raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 element, got %d", len(got))
	}

	if got[0].Type != "highflame_tool_call" {
		t.Errorf("type = %q, want highflame_tool_call", got[0].Type)
	}

	// Raw bytes preserved verbatim (key order, whitespace) for downstream
	// consumers that need to forward the exact payload they received.
	want := `{"type":"highflame_tool_call","tool":"transfer_funds","amount":50000}`
	if string(got[0].Raw) != want {
		t.Errorf("raw = %q, want %q", got[0].Raw, want)
	}
}

// TestParseAuthorizationDetails_MultiElement covers RFC 9396's multi-element
// array: an approver may need to authorize several related actions in one
// request. The parser preserves declaration order so the approver UX can
// render the array in the order the client supplied.
func TestParseAuthorizationDetails_MultiElement(t *testing.T) {
	raw := []byte(`[
		{"type":"transfer","amount":100},
		{"type":"notify","channel":"email"},
		{"type":"log","level":"info"}
	]`)
	got, err := domain.ParseAuthorizationDetails(raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(got))
	}

	wantTypes := []string{"transfer", "notify", "log"}
	for i, want := range wantTypes {
		if got[i].Type != want {
			t.Errorf("element[%d].type = %q, want %q", i, got[i].Type, want)
		}
	}
}

// TestParseAuthorizationDetails_OuterShape covers the malformed-outer cases:
// not a JSON array, not parseable JSON, etc. Every failure must wrap
// ErrAuthorizationDetailsMalformed so callers using errors.Is can detect
// the failure class without parsing the error string.
func TestParseAuthorizationDetails_OuterShape(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"plain string", `"not an array"`},
		{"plain object", `{"type":"foo"}`},
		{"number", `42`},
		{"truncated", `[{"type":"x"`},
		{"comma trailing", `[{"type":"x"},]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := domain.ParseAuthorizationDetails([]byte(c.raw))
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, domain.ErrAuthorizationDetailsMalformed) {
				t.Errorf("expected ErrAuthorizationDetailsMalformed wrap, got %v", err)
			}
		})
	}
}

// TestParseAuthorizationDetails_ElementShape covers per-element failures:
// missing `type`, non-string `type`, empty `type`, non-object element. RFC
// 9396 §2 mandates the `type` discriminator on every element.
func TestParseAuthorizationDetails_ElementShape(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"missing type", `[{"foo":"bar"}]`},
		{"empty string type", `[{"type":""}]`},
		{"non-string type", `[{"type":42}]`},
		{"null type", `[{"type":null}]`},
		{"non-object element", `[42]`},
		{"string element", `["not an object"]`},
		{"nested array element", `[["nope"]]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := domain.ParseAuthorizationDetails([]byte(c.raw))
			if err == nil {
				t.Fatalf("expected error for %q, got nil", c.raw)
			}

			if !errors.Is(err, domain.ErrAuthorizationDetailsMalformed) {
				t.Errorf("expected ErrAuthorizationDetailsMalformed wrap, got %v", err)
			}
		})
	}
}

// TestParseAuthorizationDetails_ErrorCarriesIndex confirms the parser's
// error message names the offending element index. Operator-facing logs
// need this to pinpoint which entry in a multi-element payload is at fault.
func TestParseAuthorizationDetails_ErrorCarriesIndex(t *testing.T) {
	// Two valid elements followed by one malformed → error must reference
	// element[2].
	raw := []byte(`[
		{"type":"ok"},
		{"type":"also_ok"},
		{"foo":"bar"}
	]`)
	_, err := domain.ParseAuthorizationDetails(raw)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "element[2]") {
		t.Errorf("error %q does not name element[2]", err)
	}
}

// TestAuthorizationDetail_RawPreservesUnknownFields verifies that the
// Raw bytes carry every field the client supplied (not just `type`). This
// is the contract per-type validators rely on — they need access to the
// full payload to enforce their own schemas.
func TestAuthorizationDetail_RawPreservesUnknownFields(t *testing.T) {
	raw := []byte(`[{"type":"highflame_tool_call","tool":"transfer","actions":["execute"],"locations":["acct_X"],"datatypes":["pii"]}]`)
	got, err := domain.ParseAuthorizationDetails(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Decode the raw bytes back into a generic map to verify every field
	// survived round-trip.
	var m map[string]any
	if err := json.Unmarshal(got[0].Raw, &m); err != nil {
		t.Fatalf("raw bytes do not decode as JSON object: %v", err)
	}

	for _, key := range []string{"type", "tool", "actions", "locations", "datatypes"} {
		if _, ok := m[key]; !ok {
			t.Errorf("raw bytes lost field %q", key)
		}
	}
}
