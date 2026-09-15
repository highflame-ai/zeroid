package domain

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Tests for the client-authentication predicates and the ratchet that keeps the
// raw `client_type` column out of security decisions (zeroid#348).
//
// The invariant `client_type == "public"` used to carry — a public client holds
// no credential — stopped being true when private_key_jwt landed: such a client
// holds a real credential while being neither confidential nor secret-bearing.
// Four separate call sites were patched to compensate, two of them added in the
// same PR that broke it, and one of those closed a downgrade that implementing
// private_key_jwt had REOPENED after an earlier fix had already closed it once.
// The defence was an enumeration, and an enumeration is only as good as the next
// author's memory.

func TestRequiresClientAuthentication(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		client *OAuthClient
		want   bool
		why    string
	}{
		"private_key_jwt holds a key": {
			client: &OAuthClient{TokenEndpointAuthMethod: "private_key_jwt", ClientType: "public"},
			want:   true,
			why:    "the whole point: client_type says public, but the client holds a signing key",
		},
		"private_key_jwt typed confidential": {
			client: &OAuthClient{TokenEndpointAuthMethod: "private_key_jwt", ClientType: "confidential"},
			want:   true,
			why:    "the DCR-registered shape of the same client must answer identically",
		},
		"client_secret_basic": {
			client: &OAuthClient{TokenEndpointAuthMethod: "client_secret_basic", ClientType: "confidential"},
			want:   true,
		},
		"client_secret_post": {
			client: &OAuthClient{TokenEndpointAuthMethod: "client_secret_post", ClientType: "confidential"},
			want:   true,
		},
		"none is credential-less": {
			client: &OAuthClient{TokenEndpointAuthMethod: "none", ClientType: "public"},
			want:   false,
			why:    "a public PKCE client proves possession with PKCE, not a credential",
		},
		"legacy row, unset method, confidential type": {
			client: &OAuthClient{ClientType: "confidential"},
			want:   true,
			why:    "rows predating the method column must keep behaving as before",
		},
		"legacy row, unset method, stored secret": {
			client: &OAuthClient{ClientSecret: "$2a$10$hash"},
			want:   true,
			why:    "a stored secret means it authenticates whatever the type column claims",
		},
		"inconsistent row: none + a stored secret": {
			client: &OAuthClient{TokenEndpointAuthMethod: "none", ClientSecret: "$2a$10$hash"},
			want:   true,
			why:    "treating this as credential-less is the unsafe direction — verify the secret",
		},
		"legacy row, unset method, no secret": {
			client: &OAuthClient{ClientType: "public"},
			want:   false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tc.client.RequiresClientAuthentication(); got != tc.want {
				t.Fatalf("got %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}

	t.Run("a nil client requires nothing", func(t *testing.T) {
		var c *OAuthClient
		if c.RequiresClientAuthentication() {
			t.Fatal("nil must not assert a credential requirement")
		}
	})
}

// The same client must behave identically at every endpoint whichever path
// registered it — the divergence zeroid#348 was filed for.
func TestKeyClientBehavesTheSameFromEitherRegistrationPath(t *testing.T) {
	t.Parallel()

	adminShape := &OAuthClient{TokenEndpointAuthMethod: "private_key_jwt", ClientType: "public"}
	dcrShape := &OAuthClient{TokenEndpointAuthMethod: "private_key_jwt", ClientType: "confidential"}

	for _, probe := range []struct {
		name string
		fn   func(*OAuthClient) bool
	}{
		{"RequiresClientAuthentication", (*OAuthClient).RequiresClientAuthentication},
		{"MayObtainAuthorizationCode", (*OAuthClient).MayObtainAuthorizationCode},
		{"UsesPrivateKeyJWT", (*OAuthClient).UsesPrivateKeyJWT},
	} {
		if probe.fn(adminShape) != probe.fn(dcrShape) {
			t.Errorf("%s disagrees between the admin-registered and DCR-registered shape of the same client", probe.name)
		}
	}
}

func TestMayObtainAuthorizationCode(t *testing.T) {
	t.Parallel()

	// Preserved: the inherited pre-CIMD contract still excludes secret-based
	// confidential clients from the authorize endpoint. Widening that is
	// deliberately out of scope for zeroid#348 — this test pins it so a future
	// change to the predicate has to be a deliberate one.
	secretBased := &OAuthClient{TokenEndpointAuthMethod: "client_secret_basic", ClientType: "confidential"}
	if secretBased.MayObtainAuthorizationCode() {
		t.Error("a secret-based confidential client must still be refused at /oauth2/authorize")
	}

	for _, c := range []*OAuthClient{
		{ClientType: "public", TokenEndpointAuthMethod: "none"},
		{ClientType: "public", TokenEndpointAuthMethod: "private_key_jwt"},
		{ClientType: "confidential", TokenEndpointAuthMethod: "private_key_jwt"},
	} {
		if !c.MayObtainAuthorizationCode() {
			t.Errorf("client %+v must be able to obtain an authorization code", c)
		}
	}

	// The hole in the property above, stated rather than left implicit.
	//
	// "A secret-based confidential client is still refused" holds for every
	// client that can be REGISTERED today, because a key-based one is issued no
	// secret and RotateSecret refuses to mint one. It does not hold for a legacy
	// row carrying BOTH a private_key_jwt method and a stored secret — a state
	// that predates zeroid#206 and that client_assertion.go explicitly says may
	// still exist. Such a row was refused here before zeroid#348 and is admitted
	// now.
	//
	// That is the right answer, not a regression to fix: the method is what
	// decides how the client authenticates, so it is key-based, and it must
	// present an assertion at the token endpoint regardless of the stale secret
	// sitting beside it. Asserted so the widening is a recorded decision rather
	// than something a future reader discovers by surprise.
	legacyBoth := &OAuthClient{
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "private_key_jwt",
		ClientSecret:            "$2a$10$hash",
	}
	if !legacyBoth.MayObtainAuthorizationCode() {
		t.Error("a legacy key-based row that also carries a secret is still key-based, and may obtain a code")
	}
	if !legacyBoth.RequiresClientAuthentication() {
		t.Error("it must still be made to authenticate")
	}
	if !legacyBoth.UsesPrivateKeyJWT() {
		t.Error("the registered METHOD decides, not the leftover secret — it must present an assertion")
	}
}

// RATCHET. A bare `ClientType ==` / `!=` comparison outside this package is what
// zeroid#348 exists to prevent: it reads as "holds no credential", which has not
// been true since private_key_jwt landed, and the next author who writes one on
// an auth path writes a silent authentication bypass that looks like correct
// handling of a public client.
//
// Ask the predicates instead. If a genuinely new question needs the raw column,
// add a named predicate here rather than widening this allowance.
//
// Three things this got wrong first time round, all of one kind — a ratchet that
// quietly covers less than it claims is worse than none, because it is believed:
//
//   - The root was `..`, i.e. "whatever is one level above this package", which
//     is the repo root only by coincidence of where domain/ happens to sit. Move
//     the package and the walk silently stops covering cmd/, server.go and
//     tests/ while still passing. It now finds the module root via go.mod.
//   - Nothing asserted the walk had scanned anything. An unreadable root or a
//     future refactor yields zero offenders, which reads identically to success.
//     There is now a floor on files scanned.
//   - The regex caught `==` and `!=` but not `switch c.ClientType`, which
//     branches on the column just as surely and is the natural shape once there
//     are three cases to handle.
func TestNoBareClientTypeComparisonsOutsideDomain(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	comparison := regexp.MustCompile(`ClientType\s*(==|!=)|switch\s+[\w.]*ClientType\s*\{`)

	domainDir := filepath.Join(root, "domain")
	var scanned int
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // unreadable paths are not this test's business
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", "cli", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// This package is where the predicates live — the comparisons belong here.
		if filepath.Dir(path) == domainDir {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		scanned++
		for i, line := range strings.Split(string(body), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue // prose about the column is fine; a branch on it is not
			}
			if comparison.MatchString(line) {
				offenders = append(offenders, filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+"  "+trimmed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// The floor is the difference between "found nothing" and "looked nowhere".
	// Deliberately far below the real count so ordinary deletions never trip it;
	// it exists to catch a walk that has stopped walking.
	const minFilesScanned = 50
	if scanned < minFilesScanned {
		t.Fatalf("scanned only %d .go files under %s — the ratchet is not covering the tree it claims to, "+
			"so a clean result here means nothing", scanned, root)
	}

	if len(offenders) > 0 {
		t.Errorf("bare ClientType comparison(s) outside domain/ — ask a predicate "+
			"(RequiresClientAuthentication / MayObtainAuthorizationCode / UsesPrivateKeyJWT) instead:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// moduleRoot returns the directory holding go.mod, so the ratchet's coverage is
// anchored to the module rather than to this package's position within it.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found walking up from the test directory — cannot anchor the ratchet")
		}
		dir = parent
	}
}
