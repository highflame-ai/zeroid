package handler

import (
	"encoding/json"
	"testing"
)

// Direct coverage for pruneEmptyClaims. It was previously exercised only
// transitively, through integration tests that assert on finished discovery
// documents — which pins the three members that are empty today but says
// nothing about the SHAPE rule the function actually promises, and nothing at
// all about the shapes no current member happens to use.
//
// The distinction the table encodes: "zero elements" is about ELEMENTS. An
// empty string, a false boolean and a zero number are all legal, meaningful
// values for their member types, and dropping any of them would flip the
// claim's meaning to "unspecified" rather than making the document conformant.

func TestPruneEmptyClaims_ByValueShape(t *testing.T) {
	cases := []struct {
		name  string
		value any
		keep  bool
		why   string
	}{
		// ── omitted ─────────────────────────────────────────────────────────
		{"empty []string", []string{}, false,
			"the live case — RFC 8414 §2 / OIDC Discovery §3 require omission"},
		{"nil []string", []string(nil), false,
			"typed nil is Kind()==Slice, Len()==0; would marshal to null, also not a legal value"},
		{"empty []any", []any{}, false,
			"the sweep is over any slice type, not just []string"},
		{"empty fixed-size array", [0]string{}, false,
			"serialises to [] exactly like an empty slice, so it must go the same way"},
		{"untyped nil", nil, false,
			"would marshal to null; omission is what the RFC asks for"},

		// ── kept ────────────────────────────────────────────────────────────
		{"non-empty []string", []string{"code"}, true,
			"the whole point"},
		{"slice holding an empty string", []string{""}, true,
			"one element — the clause counts elements, not their contents"},
		{"false", false, true,
			"dropping it flips the claim from 'not supported' to 'unspecified'"},
		{"true", true, true, "obviously"},
		{"empty string", "", true,
			"a legal value for a string-valued member; not an element count"},
		{"zero number", 0, true,
			"same reasoning as false"},
		{"empty map", map[string]any{}, true,
			"an object is not an array; the RFC clause does not reach it, and " +
				"guessing here would be a different bug"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := pruneEmptyClaims(map[string]any{"member": tc.value})

			_, present := body["member"]
			if present != tc.keep {
				verb := map[bool]string{true: "kept", false: "omitted"}
				t.Fatalf("member was %s, want %s — %s",
					verb[present], verb[tc.keep], tc.why)
			}
		})
	}
}

// TestPruneEmptyClaims_Idempotent is load-bearing rather than tidy. The design
// deliberately sweeps TWICE — once at the end of buildASMetadata so the base
// document is conformant for any caller, and again in openidConfigurationOp
// after the OIDC-only members are appended, which the first sweep cannot see.
// That pair is only safe to leave in place because running it twice is
// indistinguishable from running it once. If this test fails, the argument for
// keeping both sweeps fails with it.
func TestPruneEmptyClaims_Idempotent(t *testing.T) {
	build := func() map[string]any {
		return map[string]any{
			"issuer":                            "https://auth.example.com",
			"response_types_supported":          []string{"code"},
			"empty_arr":                         []string{},
			"dpop_bound_access_tokens_required": false,
		}
	}

	once := pruneEmptyClaims(build())
	twice := pruneEmptyClaims(pruneEmptyClaims(build()))

	onceJSON, err := json.Marshal(once)
	if err != nil {
		t.Fatalf("marshalling single-sweep result: %v", err)
	}
	twiceJSON, err := json.Marshal(twice)
	if err != nil {
		t.Fatalf("marshalling double-sweep result: %v", err)
	}
	if string(onceJSON) != string(twiceJSON) {
		t.Fatalf("second sweep changed the document:\n once=%s\ntwice=%s",
			onceJSON, twiceJSON)
	}
	if _, present := once["empty_arr"]; present {
		t.Fatal("the empty member survived the first sweep")
	}
	if _, present := once["dpop_bound_access_tokens_required"]; !present {
		t.Fatal("a false boolean was dropped — that flips its meaning to unspecified")
	}
}

// The sweep mutates its argument and returns it. Both callers rely on the
// return value, but a future one might rely on the mutation instead; pin that
// they are the same map so neither reading is a surprise.
func TestPruneEmptyClaims_MutatesInPlaceAndReturnsSameMap(t *testing.T) {
	body := map[string]any{"empty": []string{}, "kept": []string{"code"}}

	returned := pruneEmptyClaims(body)

	if _, present := body["empty"]; present {
		t.Fatal("the caller's own map still carries the empty member")
	}
	if len(returned) != len(body) {
		t.Fatalf("returned a different map: len %d vs %d", len(returned), len(body))
	}
}
