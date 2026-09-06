package handler

import (
	"encoding/json"
	"testing"
)

// TestResourceParamUnmarshal pins the three wire encodings RFC 8707 §2 implies.
// The single-string case is the one that matters most in practice: it is what a
// form-encoded request with one `resource` parameter becomes, and what the MCP
// interop harness sends.
func TestResourceParamUnmarshal(t *testing.T) {
	type body struct {
		Resource resourceParam `json:"resource,omitempty"`
	}

	t.Run("bare string binds to a one-element slice", func(t *testing.T) {
		var b body
		if err := json.Unmarshal([]byte(`{"resource":"https://gw.example/mcp/github"}`), &b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(b.Resource) != 1 || b.Resource[0] != "https://gw.example/mcp/github" {
			t.Fatalf("got %#v", b.Resource)
		}
	})

	t.Run("array binds in order", func(t *testing.T) {
		var b body
		if err := json.Unmarshal([]byte(`{"resource":["https://a.example","https://b.example"]}`), &b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(b.Resource) != 2 || b.Resource[0] != "https://a.example" || b.Resource[1] != "https://b.example" {
			t.Fatalf("got %#v", b.Resource)
		}
	})

	t.Run("absent parameter leaves nil", func(t *testing.T) {
		var b body
		if err := json.Unmarshal([]byte(`{}`), &b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if b.Resource != nil {
			t.Fatalf("expected nil, got %#v", b.Resource)
		}
	})

	t.Run("null binds to nil, not an error", func(t *testing.T) {
		var b body
		if err := json.Unmarshal([]byte(`{"resource":null}`), &b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if b.Resource != nil {
			t.Fatalf("expected nil, got %#v", b.Resource)
		}
	})

	t.Run("empty array binds to an empty slice", func(t *testing.T) {
		// Distinct from absent at this layer; the service treats both as "no
		// binding requested", but the binder must not error.
		var b body
		if err := json.Unmarshal([]byte(`{"resource":[]}`), &b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(b.Resource) != 0 {
			t.Fatalf("expected empty, got %#v", b.Resource)
		}
	})

	rejects := map[string]string{
		"number":           `{"resource":42}`,
		"object":           `{"resource":{"uri":"https://a.example"}}`,
		"bool":             `{"resource":true}`,
		"array of numbers": `{"resource":[1,2]}`,
		"mixed array":      `{"resource":["https://a.example",7]}`,
	}
	for name, payload := range rejects {
		t.Run("rejects "+name, func(t *testing.T) {
			var b body
			if err := json.Unmarshal([]byte(payload), &b); err == nil {
				t.Fatalf("expected a binding error, got %#v", b.Resource)
			}
		})
	}
}
