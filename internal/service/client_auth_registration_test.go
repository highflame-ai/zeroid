package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// Tests for validateClientAuthMethod — the registration-time gate (zeroid#206
// scope item 3).
//
// Before this existed, token_endpoint_auth_method was stored verbatim: any
// string at all landed in the column, was echoed back on read, advertised in the
// API enum, and never consulted at authentication time. That is how
// private_key_jwt came to be an advertised-but-unenforced method, and a typo
// like "private-key-jwt" was equally silent.
func TestValidateClientAuthMethod(t *testing.T) {
	t.Parallel()

	validJWKS := json.RawMessage(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`)

	t.Run("accepts the methods this server enforces", func(t *testing.T) {
		for _, m := range []string{"none", "client_secret_post", "client_secret_basic"} {
			require.NoError(t, validateClientAuthMethod(m, nil, ""), "method %q must be registrable", m)
		}
		require.NoError(t, validateClientAuthMethod("private_key_jwt", validJWKS, ""))
		require.NoError(t, validateClientAuthMethod("private_key_jwt", nil, "https://client.example.com/jwks.json"))
	})

	t.Run("refuses methods this server cannot enforce", func(t *testing.T) {
		// Registering a promise the server does not keep is the whole bug
		// class. client_secret_jwt is dropped in OAuth 2.1; tls_client_auth is
		// deferred pending an mTLS termination story.
		for _, m := range []string{"client_secret_jwt", "tls_client_auth", "self_signed_tls_client_auth", "private-key-jwt", "", "made_up"} {
			require.Error(t, validateClientAuthMethod(m, nil, ""), "method %q must not be registrable", m)
		}
	})

	t.Run("private_key_jwt without key material is refused", func(t *testing.T) {
		// Otherwise registration succeeds and produces a client that can never
		// authenticate — a failure the operator only discovers as a 401 later,
		// against a client they believe is configured correctly.
		require.Error(t, validateClientAuthMethod("private_key_jwt", nil, ""))
	})

	t.Run("jwks and jwks_uri are mutually exclusive", func(t *testing.T) {
		// RFC 7591 §2. Checked for EVERY method, not just private_key_jwt: an
		// ambiguous key set is a problem whenever it is stored, and a client can
		// change its auth method later.
		require.Error(t, validateClientAuthMethod("private_key_jwt", validJWKS, "https://client.example.com/jwks.json"))
		require.Error(t, validateClientAuthMethod("client_secret_basic", validJWKS, "https://client.example.com/jwks.json"))
	})

	t.Run("an unparseable inline jwks is refused at registration", func(t *testing.T) {
		for _, bad := range []string{`{"keys":[]}`, `{"not":"a jwks"}`, `garbage`} {
			require.Error(t, validateClientAuthMethod("private_key_jwt", json.RawMessage(bad), ""),
				"inline jwks %q must be rejected now, not at first authentication", bad)
		}
	})
}

// Tests for the per-client JWKS cache. Each entry owns a background refresh
// goroutine, so the eviction bound is not merely about memory: without it,
// anyone able to register clients (DCR is open in some deployments) could spawn
// one goroutine and one outbound fetch loop per registration.
func TestClientJWKSCache(t *testing.T) {
	t.Parallel()

	t.Run("reuses one client per client_id and jwks_uri", func(t *testing.T) {
		c := NewClientJWKSCache(4)
		defer c.Close()

		first, err := c.get("client-a", "https://a.example.com/jwks.json")
		require.NoError(t, err)
		again, err := c.get("client-a", "https://a.example.com/jwks.json")
		require.NoError(t, err)
		require.Same(t, first, again, "a repeat lookup must not build a second JWKS client")
	})

	t.Run("a rotated jwks_uri is a cache miss", func(t *testing.T) {
		// Keying on client_id alone would keep serving keys fetched from the
		// OLD endpoint until eviction — a revoked key would keep authenticating.
		c := NewClientJWKSCache(4)
		defer c.Close()

		before, err := c.get("client-b", "https://old.example.com/jwks.json")
		require.NoError(t, err)
		after, err := c.get("client-b", "https://new.example.com/jwks.json")
		require.NoError(t, err)
		require.NotSame(t, before, after, "rotating jwks_uri must not reuse the old endpoint's client")
	})

	t.Run("evicts least-recently-used beyond the cap", func(t *testing.T) {
		c := NewClientJWKSCache(2)
		defer c.Close()

		a, err := c.get("c", "https://1.example.com/jwks.json")
		require.NoError(t, err)
		_, err = c.get("c", "https://2.example.com/jwks.json")
		require.NoError(t, err)

		// Touch #1 so #2 becomes the least-recently-used, then insert #3.
		aAgain, err := c.get("c", "https://1.example.com/jwks.json")
		require.NoError(t, err)
		require.Same(t, a, aAgain)

		_, err = c.get("c", "https://3.example.com/jwks.json")
		require.NoError(t, err)
		require.Equal(t, 2, c.lru.Len(), "the cache must never exceed its cap")

		// #1 was touched most recently, so it survived; #2 was evicted.
		stillA, err := c.get("c", "https://1.example.com/jwks.json")
		require.NoError(t, err)
		require.Same(t, a, stillA, "the most-recently-used entry must survive eviction")
	})

	t.Run("a zero or negative cap falls back to the default", func(t *testing.T) {
		for _, size := range []int{0, -1} {
			c := NewClientJWKSCache(size)
			require.Equal(t, defaultClientJWKSCacheSize, c.maxSize)
			c.Close()
		}
	})

	t.Run("Close is idempotent and empties the cache", func(t *testing.T) {
		c := NewClientJWKSCache(2, authjwt.WithRefreshInterval(0))
		_, err := c.get("c", "https://x.example.com/jwks.json")
		require.NoError(t, err)
		c.Close()
		require.Equal(t, 0, c.lru.Len())
		require.NotPanics(t, c.Close)
	})
}
