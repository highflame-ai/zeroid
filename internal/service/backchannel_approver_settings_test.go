package service

import "testing"

// TestEnforceHintsRequiresApproverIdentity pins that the runtime setters keep
// enforce_hints at off unless require_approver_identity is true: the binding
// checks compare against the authenticated approver only.
func TestEnforceHintsRequiresApproverIdentity(t *testing.T) {
	svc := NewBackchannelService(nil, nil, nil, nil, DefaultBackchannelConfig())

	for _, mode := range []string{EnforceHintsShadow, EnforceHintsOn} {
		if err := svc.SetEnforceHints(mode); err == nil {
			t.Fatalf("enforce_hints=%s without require_approver_identity must be refused", mode)
		}
	}
	if _, mode, _ := svc.approverSettings(); mode != EnforceHintsOff {
		t.Fatalf("a refused change must leave enforce_hints unchanged, got %q", mode)
	}

	if err := svc.SetRequireApproverIdentity(true); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetEnforceHints(EnforceHintsOn); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetRequireApproverIdentity(false); err == nil {
		t.Fatal("require_approver_identity=false while enforce_hints=on must be refused")
	}
	if require, _, _ := svc.approverSettings(); !require {
		t.Fatal("a refused change must leave require_approver_identity unchanged")
	}

	if err := svc.SetEnforceHints(EnforceHintsOff); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetRequireApproverIdentity(false); err != nil {
		t.Fatal(err)
	}
}
