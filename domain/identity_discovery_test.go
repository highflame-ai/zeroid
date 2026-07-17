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
// primary moves out. Dismiss from pending (→discovered) is also legal — it
// reverts an adoption so the agent reappears in the adoption inbox.
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
		// Into discovered — only pending can revert to discovered (dismiss from pending).
		{IdentityStatusPending, IdentityStatusDiscovered, true},
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

// TestCanRetypeDiscovered pins the re-typing rule: a connector re-sync may
// re-classify a still-`discovered` row to (newType, newSub) — the CAP-DSC-003
// fix for identities imported before the classifier could type them — but must
// never touch an adopted row or accept an invalid (identity_type, sub_type) pair.
// The 4th arg is the connector's INCOMING sub_type (adopted alongside the type),
// not the stored one — see the agent→mcp_server case.
func TestCanRetypeDiscovered(t *testing.T) {
	tests := []struct {
		name    string
		status  IdentityStatus
		curType IdentityType
		newType IdentityType
		newSub  SubType
		want    bool
	}{
		// The fix: a discovered OAuth app (connector sends an empty sub_type — the
		// oauth_app marker lives in a label, not the domain sub_type) upgrades to
		// mcp_server.
		{"discovered application → mcp_server", IdentityStatusDiscovered, IdentityTypeApplication, IdentityTypeMCPServer, "", true},
		// A row ingested as agent carries a defaulted tool_agent sub_type, but the
		// connector re-syncs it with an empty sub_type — validating the INCOMING
		// sub_type (not the stored tool_agent) lets it flip and clears the sub_type.
		// Keying on the stored sub_type would pin such rows to agent forever.
		{"discovered agent → mcp_server (incoming empty sub)", IdentityStatusDiscovered, IdentityTypeAgent, IdentityTypeMCPServer, "", true},
		{"discovered mcp_server → agent (incoming valid agent sub)", IdentityStatusDiscovered, IdentityTypeMCPServer, IdentityTypeAgent, SubTypeToolAgent, true},

		// No-op: same type is not a re-type.
		{"discovered application → application", IdentityStatusDiscovered, IdentityTypeApplication, IdentityTypeApplication, "", false},

		// Adopted rows are protected — type may be human-curated past discovered.
		{"pending application → mcp_server", IdentityStatusPending, IdentityTypeApplication, IdentityTypeMCPServer, "", false},
		{"active mcp_server → application", IdentityStatusActive, IdentityTypeMCPServer, IdentityTypeApplication, "", false},
		{"deactivated application → mcp_server", IdentityStatusDeactivated, IdentityTypeApplication, IdentityTypeMCPServer, "", false},

		// Invalid target type is refused.
		{"discovered application → empty", IdentityStatusDiscovered, IdentityTypeApplication, "", "", false},
		{"discovered application → bogus", IdentityStatusDiscovered, IdentityTypeApplication, "bogus", "", false},

		// Never accept an invalid (type, sub_type) pair: mcp_server requires an
		// empty sub_type, and an application/agent sub_type is invalid for it.
		{"discovered application → mcp_server (incoming custom sub)", IdentityStatusDiscovered, IdentityTypeApplication, IdentityTypeMCPServer, SubTypeCustom, false},
		{"discovered agent → application (incoming agent-only sub)", IdentityStatusDiscovered, IdentityTypeAgent, IdentityTypeApplication, SubTypeOrchestrator, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanRetypeDiscovered(tc.status, tc.curType, tc.newType, tc.newSub); got != tc.want {
				t.Fatalf("CanRetypeDiscovered(%q, %q, %q, %q) = %v, want %v",
					tc.status, tc.curType, tc.newType, tc.newSub, got, tc.want)
			}
		})
	}
}
