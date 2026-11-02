package worker

import (
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

// The refresh-token sweep must keep a rotated-out row at least as long as the
// configured reuse grace window, or a retry within the window would find the
// row gone; and never less than the default lag, so the sweep does not race a
// lookup at the instant of expiry even with the grace disabled.
func TestRefreshTokenRetentionLagCoversReuseGrace(t *testing.T) {
	w := NewCleanupWorker(nil, nil, time.Hour, 0)
	if got := w.refreshTokenRetentionLag(); got != domain.RefreshTokenReuseGraceWindow {
		t.Fatalf("unset grace: lag %v, want %v", got, domain.RefreshTokenReuseGraceWindow)
	}
	w.SetRefreshReuseGrace(0)
	if got := w.refreshTokenRetentionLag(); got != domain.RefreshTokenReuseGraceWindow {
		t.Fatalf("grace disabled: lag %v, want the floor %v", got, domain.RefreshTokenReuseGraceWindow)
	}
	w.SetRefreshReuseGrace(300 * time.Second)
	if got := w.refreshTokenRetentionLag(); got != 300*time.Second {
		t.Fatalf("grace 300s: lag %v, want 300s", got)
	}
}
