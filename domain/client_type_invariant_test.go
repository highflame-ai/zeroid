package domain

import (
	"os"
	"path/filepath"
	"regexp"
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
		{"MayUseInteractiveFlows", (*OAuthClient).MayUseInteractiveFlows},
		{"UsesPrivateKeyJWT", (*OAuthClient).UsesPrivateKeyJWT},
	} {
		if probe.fn(adminShape) != probe.fn(dcrShape) {
			t.Errorf("%s disagrees between the admin-registered and DCR-registered shape of the same client", probe.name)
		}
	}
}

func TestMayUseInteractiveFlows(t *testing.T) {
	t.Parallel()

	// Preserved: the inherited pre-CIMD contract still excludes secret-based
	// confidential clients from the authorize endpoint. Widening that is
	// deliberately out of scope for zeroid#348 — this test pins it so a future
	// change to the predicate has to be a deliberate one.
	secretBased := &OAuthClient{TokenEndpointAuthMethod: "client_secret_basic", ClientType: "confidential"}
	if secretBased.MayUseInteractiveFlows() {
		t.Error("a secret-based confidential client must still be refused at /oauth2/authorize")
	}

	for _, c := range []*OAuthClient{
		{ClientType: "public", TokenEndpointAuthMethod: "none"},
		{ClientType: "public", TokenEndpointAuthMethod: "private_key_jwt"},
		{ClientType: "confidential", TokenEndpointAuthMethod: "private_key_jwt"},
	} {
		if !c.MayUseInteractiveFlows() {
			t.Errorf("client %+v must be able to obtain an authorization code", c)
		}
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
func TestNoBareClientTypeComparisonsOutsideDomain(t *testing.T) {
	t.Parallel()

	root := ".."
	comparison := regexp.MustCompile(`ClientType\s*(==|!=)`)

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
		if filepath.Dir(path) == root+"/domain" || filepath.Dir(path) == "." {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		for i, line := range strings.Split(string(body), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue // prose about the column is fine; a branch on it is not
			}
			if comparison.MatchString(line) {
				offenders = append(offenders, filepath.ToSlash(path)+":"+itoa(i+1)+"  "+trimmed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("bare ClientType comparison(s) outside domain/ — ask a predicate "+
			"(RequiresClientAuthentication / MayUseInteractiveFlows / UsesPrivateKeyJWT) instead:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
