package zeroid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RATCHET. pkg/authjwt is the token-VERIFICATION library that resource servers
// (cerberus, shield, authn) import to validate zeroid-issued tokens. The
// authorization server must not depend on it: that is backwards layering, and it
// drags a consumer-facing API — with its compatibility obligations — into the
// server's graph.
//
// This is enforced in code because prose already failed. RELEASING.md stated the
// boundary correctly and justified pinning pkg/authjwt at the v0.0.0 placeholder
// on the strength of it ("imported only from tests/integration"). #211 then added
// internal/service/external_issuer_registry.go importing it from non-test code,
// and #347 added internal/service/client_jwks.go. Nothing failed at either
// moment. What failed, silently, was every release from v1.7.1 onward: consumers
// resolving zeroid got "unknown revision pkg/authjwt/v0.0.0", while in-repo
// builds stayed green because the local `replace` hid it.
//
// The shared JWKS client now lives in pkg/jwks, which both sides may import.
// TEST files may still import pkg/authjwt — tests/integration verifies tokens the
// way a consumer would, which is exactly what that package is for.
func TestNonTestSourceDoesNotImportAuthjwt(t *testing.T) {
	t.Parallel()

	const banned = `"github.com/highflame-ai/zeroid/pkg/authjwt"`

	var offenders []string
	var scanned int
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", "cli", "docs":
				return filepath.SkipDir
			}
			// The nested modules are separate modules with their own rules —
			// pkg/authjwt obviously may import itself, and pkg/jwks is the
			// dependency this boundary exists to route through.
			if path == "pkg" {
				return filepath.SkipDir
			}

			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		scanned++
		if strings.Contains(string(body), banned) {
			offenders = append(offenders, filepath.ToSlash(path))
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// A walk that scans nothing reports no offenders, which reads identically to
	// success. Floor it well below the real count so ordinary deletions never
	// trip it.
	if scanned < 50 {
		t.Fatalf("scanned only %d non-test .go files — the walk is not covering the tree, "+
			"so a clean result here means nothing", scanned)
	}

	if len(offenders) > 0 {
		t.Errorf("zeroid's non-test source must not import pkg/authjwt — it is the "+
			"consumer-facing verification library, and depending on it inverts the layering.\n"+
			"Use github.com/highflame-ai/zeroid/pkg/jwks for remote key sets.\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
