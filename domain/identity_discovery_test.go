package domain

import "testing"

// TestIdentityStatusDiscovered_Valid confirms discovered is a recognised status.
func TestIdentityStatusDiscovered_Valid(t *testing.T) {
	if !IdentityStatusDiscovered.Valid() {
		t.Fatal("IdentityStatusDiscovered.Valid() = false, want true")
	}
}

// TestIdentityStatusDiscovered_IsUsable pins the platform safety gate: a
// discovered (externally-observed, untrusted) identity can never authenticate
// or receive a token. Same for pending — only active is usable.
func TestIdentityStatusDiscovered_IsUsable(t *testing.T) {
	if IdentityStatusDiscovered.IsUsable() {
		t.Fatal("IdentityStatusDiscovered.IsUsable() = true, want false")
	}
	if IdentityStatusPending.IsUsable() {
		t.Fatal("IdentityStatusPending.IsUsable() = true, want false")
	}
	if !IdentityStatusActive.IsUsable() {
		t.Fatal("IdentityStatusActive.IsUsable() = false, want true")
	}
}

// TestCanTransitionTo_Discovered pins the discovered state machine: adopt
// (→pending), direct activation (→active), and dismiss (→deactivated) are the
// only legal moves out, and `discovered` is entry-only — nothing transitions
// into it.
func TestCanTransitionTo_Discovered(t *testing.T) {
	tests := []struct {
		from   IdentityStatus
		to     IdentityStatus
		expect bool
	}{
		// Out of discovered — the three named transitions.
		{IdentityStatusDiscovered, IdentityStatusPending, true},     // adopt
		{IdentityStatusDiscovered, IdentityStatusActive, true},      // direct activation
		{IdentityStatusDiscovered, IdentityStatusDeactivated, true}, // dismiss
		// Out of discovered — illegal moves.
		{IdentityStatusDiscovered, IdentityStatusSuspended, false},
		{IdentityStatusDiscovered, IdentityStatusExpired, false},
		{IdentityStatusDiscovered, IdentityStatusDiscovered, false},
		// Into discovered — entry-only, never reachable by transition.
		{IdentityStatusPending, IdentityStatusDiscovered, false},
		{IdentityStatusActive, IdentityStatusDiscovered, false},
		{IdentityStatusSuspended, IdentityStatusDiscovered, false},
		{IdentityStatusDeactivated, IdentityStatusDiscovered, false},
		{IdentityStatusExpired, IdentityStatusDiscovered, false},
		// Regression guard: existing transitions still hold.
		{IdentityStatusPending, IdentityStatusActive, true},
		{IdentityStatusActive, IdentityStatusSuspended, true},
	}
	for _, tc := range tests {
		name := string(tc.from) + " → " + string(tc.to)
		t.Run(name, func(t *testing.T) {
			if got := tc.from.CanTransitionTo(tc.to); got != tc.expect {
				t.Fatalf("CanTransitionTo = %v, want %v", got, tc.expect)
			}
		})
	}
}

// TestOrigin_IsExternal pins the provenance discriminator: native (and the
// empty default) are not external; every other value is.
func TestOrigin_IsExternal(t *testing.T) {
	tests := []struct {
		origin Origin
		want   bool
	}{
		{OriginNative, false},
		{"", false}, // unset defaults to native at the service layer
		{OriginOkta, true},
		{OriginEntra, true},
		{OriginGoogleWorkspace, true},
		{"pingid", true}, // open set — an unknown connector is still external
	}
	for _, tc := range tests {
		t.Run(string(tc.origin), func(t *testing.T) {
			if got := tc.origin.IsExternal(); got != tc.want {
				t.Fatalf("Origin(%q).IsExternal() = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}

// TestValidOrigin pins the shape contract: a non-empty lowercase identifier.
// Membership is intentionally not checked (the external set is open).
func TestValidOrigin(t *testing.T) {
	valid := []string{"native", "okta", "entra", "google_workspace", "pingid", "a1"}
	for _, v := range valid {
		if !ValidOrigin(v) {
			t.Errorf("ValidOrigin(%q) = false, want true", v)
		}
	}
	invalid := []string{"", "Okta", "google workspace", "okta-prod", "okta.com", "okta/agents", "naïve"}
	for _, v := range invalid {
		if ValidOrigin(v) {
			t.Errorf("ValidOrigin(%q) = true, want false", v)
		}
	}
}

// TestGetIdentitySchema_DiscoveryAdditions confirms the schema endpoint advertises
// the new discovered status and the origins list so frontends stay in sync.
func TestGetIdentitySchema_DiscoveryAdditions(t *testing.T) {
	schema := GetIdentitySchema()

	hasStatus := func(v string) bool {
		for _, s := range schema.Statuses {
			if s.Value == v {
				return true
			}
		}
		return false
	}
	if !hasStatus(string(IdentityStatusDiscovered)) {
		t.Error("schema.Statuses is missing 'discovered'")
	}

	if len(schema.Origins) == 0 {
		t.Fatal("schema.Origins is empty; want at least native + the launch connectors")
	}
	hasOrigin := func(v string) bool {
		for _, o := range schema.Origins {
			if o.Value == v {
				return true
			}
		}
		return false
	}
	for _, want := range []string{string(OriginNative), string(OriginOkta), string(OriginEntra), string(OriginGoogleWorkspace)} {
		if !hasOrigin(want) {
			t.Errorf("schema.Origins is missing %q", want)
		}
	}
}
