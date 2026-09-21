package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/pkg/authjwt"
	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// End-to-end coverage for zeroid#264: a CIMD client that publishes a key set
// authenticates with an RFC 7523 §2.2 assertion.
//
// "End to end" here means the whole path that is new — a real document served
// over HTTPS, fetched, parsed, validated and synthesized by the real
// CIMDService, then handed to the real client-authentication path with a real
// signed assertion. What it deliberately does NOT include is token minting,
// which needs a database and is unchanged by this work; the integration suite
// covers that wiring.
//
// The property under test is narrow and worth stating precisely, because the
// rationale this replaced got it backwards. Accepting private_key_jwt from a
// self-published document does not hand anyone a new identity: the
// self-reference check means a CIMD client_id IS the URL its document came
// from, so the only identity assertable is one for a URL the caller already
// controls — and already controls as a PUBLIC client today. What changes is
// that such a client can now be REQUIRED to prove it, which is strictly more
// authentication than before.

// cimdKeyDocServer serves a self-referencing CIMD document declaring
// private_key_jwt with key's public half published inline, and returns a
// CIMDService wired to trust the origin's self-signed cert.
func cimdKeyDocServer(t *testing.T, key *ecdsa.PrivateKey) (*CIMDService, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"client_id":%q,"client_name":"Key-Based MCP Client",`+
				`"redirect_uris":["http://127.0.0.1:9000/cb"],`+
				`"grant_types":["authorization_code","refresh_token"],`+
				`"token_endpoint_auth_method":"private_key_jwt","jwks":%s}`,
			clientID, inlineJWKS(t, key))
	}))
	t.Cleanup(ts.Close)
	return NewCIMDService(CIMDConfig{Enabled: true, HTTPClient: ts.Client()}), ts.URL
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func TestCIMDKeyBasedClientAuthentication(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t)

	cimdSvc, base := cimdKeyDocServer(t, key)
	clientID := base + "/.well-known/oauth/client-metadata.json"

	// Resolve through the REAL path: fetch, parse, validate, synthesize.
	client, err := cimdSvc.ResolveClient(ctx, clientID)
	require.NoError(t, err, "a document declaring private_key_jwt with an inline jwks must resolve")
	require.True(t, client.UsesPrivateKeyJWT(), "the synthesized client must be key-based")
	require.True(t, client.RequiresClientAuthentication(),
		"the whole point: this client must now be made to prove something")

	svc := clientAssertionSvc(dpop.NewMemoryStore())
	// The assertion's aud must name this server, and clientAssertionSvc pins
	// the issuer it accepts — mintAssertion defaults to exactly that.

	t.Run("a valid assertion authenticates the client", func(t *testing.T) {
		assertion := mintAssertion(t, key, clientID, assertionOpts{})
		err := svc.verifyConfidentialClientAuth(ctx, client, clientID, "", assertion, clientAssertionTypeJWTBearer)
		require.NoError(t, err,
			"a CIMD client that signs with the key its own document publishes must authenticate")
	})

	t.Run("NO credential is refused — the downgrade this closes", func(t *testing.T) {
		// Before zeroid#264 this client could not exist at all. The failure to
		// avoid is it existing and being waved through as a public client,
		// which is exactly what the client_type-shaped test used to do for
		// key-based clients (zeroid#348).
		err := svc.verifyConfidentialClientAuth(ctx, client, clientID, "", "", "")
		require.Error(t, err, "a key-based CIMD client must not authenticate with nothing")
		assert.Contains(t, err.Error(), "must authenticate with a client_assertion")
	})

	t.Run("a client_secret is refused — there is no secret to have", func(t *testing.T) {
		err := svc.verifyConfidentialClientAuth(ctx, client, clientID, "some-secret", "", "")
		require.Error(t, err, "a key-based client must not be authenticable by a secret")
	})

	t.Run("an assertion signed by a DIFFERENT key is refused", func(t *testing.T) {
		// The document's key set is the whole control. If any key verified,
		// publishing a jwks would be decoration.
		attacker := newTestKey(t)
		assertion := mintAssertion(t, attacker, clientID, assertionOpts{})
		err := svc.verifyConfidentialClientAuth(ctx, client, clientID, "", assertion, clientAssertionTypeJWTBearer)
		require.Error(t, err, "only the key the document publishes may authenticate this client")
	})

	t.Run("an assertion is single-use", func(t *testing.T) {
		assertion := mintAssertion(t, key, clientID, assertionOpts{jti: "cimd-replay-probe"})
		require.NoError(t, svc.verifyConfidentialClientAuth(ctx, client, clientID, "", assertion, clientAssertionTypeJWTBearer))
		err := svc.verifyConfidentialClientAuth(ctx, client, clientID, "", assertion, clientAssertionTypeJWTBearer)
		require.Error(t, err, "replay protection must apply to CIMD clients too, not just registered ones")
	})
}

// A CIMD document cannot mint a key-based client for a URL it was not served
// from. This is the load-bearing check under the whole zeroid#264 argument: if
// a document could claim another URL's client_id, then accepting its key WOULD
// be "asserting a confidential client identity" that is not yours, and the
// rationale this change replaced would have been correct.
func TestCIMDKeyBasedClientCannotClaimAnotherURL(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t)

	// An origin that serves a document claiming SOMEONE ELSE's client_id,
	// with the attacker's own key published in it.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"client_id":"https://victim.example.com/client.json","client_name":"Impostor",`+
				`"redirect_uris":["http://127.0.0.1:9000/cb"],`+
				`"token_endpoint_auth_method":"private_key_jwt","jwks":%s}`,
			inlineJWKS(t, key))
	}))
	t.Cleanup(ts.Close)

	cimdSvc := NewCIMDService(CIMDConfig{Enabled: true, HTTPClient: ts.Client()})
	_, err := cimdSvc.ResolveClient(ctx, ts.URL+"/attacker.json")
	require.Error(t, err, "publishing a key must not let a document claim a client_id it was not served from")
}

// The document's key material must survive the fetch → parse → synthesize round
// trip as the SAME bytes the publisher served.
//
// Worth asserting separately because the registered path has already been bitten
// by exactly this: `jwks` is a nullable jsonb column and a database round trip
// turns a nil json.RawMessage into a four-byte `null`, which a naive length
// check reads as "inline key set present" (see TestPrivateKeyJWT_JWKSURIClient in
// the integration suite). A synthesized client never touches the database, so
// the failure mode differs — but the property a caller depends on is the same.
func TestCIMDKeyMaterialSurvivesTheRoundTrip(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t)
	cimdSvc, base := cimdKeyDocServer(t, key)

	client, err := cimdSvc.ResolveClient(ctx, base+"/client.json")
	require.NoError(t, err)

	var served, got map[string]any
	require.NoError(t, json.Unmarshal(inlineJWKS(t, key), &served))
	require.NoError(t, json.Unmarshal(client.JWKS, &got))
	assert.Equal(t, served, got, "the key set the client authenticates against must be the one it published")
	assert.Empty(t, client.JWKSURI, "an inline jwks must not also set jwks_uri")
}

// The synthesized client is ephemeral: a key-based CIMD client is never written
// to the registry, so it cannot become a persistent confidential client by
// having been resolved once.
func TestCIMDKeyBasedClientIsNotPersisted(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t)
	cimdSvc, base := cimdKeyDocServer(t, key)

	client, err := cimdSvc.ResolveClient(ctx, base+"/client.json")
	require.NoError(t, err)
	assert.Equal(t, cimdRegistrationSource, client.RegistrationSource,
		"the source tag is what marks it self-asserted everywhere downstream")
	assert.Empty(t, client.ID, "a synthesized client has no registry row identity")
	assert.True(t, client.CreatedAt.Before(time.Now().Add(time.Minute)))
}

// A CIMD document may only publish keys on its OWN host.
//
// Without this, validateCIMDKeyMaterial accepted any absolute https jwks_uri,
// which made an anonymous document an unauthenticated outbound-fetch primitive
// aimed at a third party. verifyClientAssertion resolves the key set BEFORE it
// verifies the signature (clientVerificationKeys, then jwt.Parse), so no valid
// credential is needed to drive it: measured at 6 outbound requests to an
// unrelated host from 5 garbage-assertion calls, since the JWKS client both
// warms up and loads.
//
// The amplification is the smaller half. Each distinct jwks_uri takes a
// ClientJWKSCache slot — keyed clientID‖jwksURI — and every slot owns a
// background goroutine re-fetching on an interval. N attacker URLs therefore
// evict N legitimate clients' cached key sets, and those clients then pay fresh
// fetches on their next authentication. The 256-entry cap bounds memory and
// goroutines; it does not bound fetch RATE, and the eviction churn IS the harm.
//
// Same-host is also simply the right rule. CIMD's trust anchor is that the
// document's host vouches for the identity; honouring keys served by a different
// host would trust B to speak for A with nothing establishing that it may.
// Inline `jwks` remains the escape hatch for a publisher who keeps keys
// elsewhere, and the 5 KiB document cap fits EC keys comfortably.
func TestCIMDKeyMaterialMustBeOnTheClientsOwnHost(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t)

	var docFetches int32
	// The document origin serves a jwks_uri on a DIFFERENT HOSTNAME. It must be
	// refused at validation — before any attempt to contact that host — which is
	// what the error KIND proves: ErrCIMDInvalidDocument, not ErrCIMDFetch.
	//
	// The hostname has to genuinely differ, and that is the trap this test fell
	// into first time round: two httptest servers both bind 127.0.0.1 and differ
	// only by PORT, so an earlier version of this test passed against a
	// port-sensitive comparison and proved nothing about hosts. A port is not a
	// host — the trust anchor is the DNS name and the TLS identity, neither of
	// which a port changes — so the rule compares Hostname(), and the fixture
	// must too.
	crossHost := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&docFetches, 1)
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Cross-Host Probe",`+
			`"redirect_uris":["http://127.0.0.1:9000/cb"],`+
			`"token_endpoint_auth_method":"private_key_jwt",`+
			`"jwks_uri":"https://keys.elsewhere.example/jwks"}`, clientID)
	}))
	t.Cleanup(crossHost.Close)

	cimdSvc := NewCIMDService(CIMDConfig{Enabled: true, HTTPClient: crossHost.Client()})
	_, err := cimdSvc.ResolveClient(ctx, crossHost.URL+"/client.json")

	require.Error(t, err, "a document must not be able to point jwks_uri at an unrelated host")
	require.ErrorIs(t, err, ErrCIMDInvalidDocument,
		"refusal must come from VALIDATION, not from failing to reach the third-party host — "+
			"if it were a fetch error the unauthenticated outbound-request primitive would still exist")
	require.NotErrorIs(t, err, ErrCIMDFetch)
	assert.Positive(t, atomic.LoadInt32(&docFetches),
		"the document itself must have been fetched, or the test never reached the rule it is testing")

	// The legitimate shape still works: keys on the document's own host.
	sameHost := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(inlineJWKS(t, key))

			return
		}
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Same Host",`+
			`"redirect_uris":["http://127.0.0.1:9000/cb"],`+
			`"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://%s/jwks"}`,
			clientID, r.Host)
	}))
	t.Cleanup(sameHost.Close)

	okSvc := NewCIMDService(CIMDConfig{Enabled: true, HTTPClient: sameHost.Client()})
	client, err := okSvc.ResolveClient(ctx, sameHost.URL+"/client.json")
	require.NoError(t, err, "keys on the document's own host are the supported shape and must still work")
	assert.True(t, client.UsesPrivateKeyJWT())
}

// A CIMD client whose published jwks_uri cannot be loaded is a CLIENT
// authentication failure (401), not a server error (500).
//
// The document is accepted and positively cached on scheme + host alone, so
// without this any anonymous party could publish a jwks_uri that 404s and mint a
// deterministic, repeatable 500 on every authentication attempt — unauthenticated
// noise aimed straight at server-error alerting. A REGISTERED client keeps the
// 500: an operator vetted that URL, so a failed load really is our fault.
func TestCIMDUnloadableJWKSURIIsAClientErrorNotAServerError(t *testing.T) {
	ctx := context.Background()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			http.NotFound(w, r) // the publisher's own endpoint is broken

			return
		}
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Broken Keys",`+
			`"redirect_uris":["http://127.0.0.1:9000/cb"],`+
			`"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://%s/jwks"}`,
			clientID, r.Host)
	}))
	t.Cleanup(origin.Close)

	cimdSvc := NewCIMDService(CIMDConfig{Enabled: true, HTTPClient: origin.Client()})
	clientID := origin.URL + "/client.json"
	client, err := cimdSvc.ResolveClient(ctx, clientID)
	require.NoError(t, err, "the document itself is valid — only its key endpoint is broken")

	svc := clientAssertionSvc(dpop.NewMemoryStore())
	svc.clientJWKS = NewClientJWKSCache(8, authjwt.WithHTTPClient(origin.Client()))

	err = svc.verifyConfidentialClientAuth(ctx, client, clientID, "",
		mintAssertion(t, newTestKey(t), clientID, assertionOpts{}), clientAssertionTypeJWTBearer)
	require.Error(t, err)

	var oerr *OAuthError
	require.ErrorAs(t, err, &oerr)
	assert.Equal(t, http.StatusUnauthorized, oerr.HTTPStatus,
		"an anonymous publisher must not be able to mint 500s on demand")
}
