package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// Tests for RFC 7523 §2.2 private_key_jwt client authentication (zeroid#206
// scope items 1 and 2).
//
// These cover verifyClientAssertion and enforceRegisteredClientAuthMethod
// directly rather than through the token endpoint: the properties under test
// are about the assertion itself (claims, signature, single-use) and about
// which credential a registered method will accept, neither of which needs a
// database or an HTTP round trip. The end-to-end wiring is covered by the
// integration suite.

const testAssertionIssuer = "https://auth.example.com"

// clientAssertionSvc builds an OAuthService with just enough wired for
// client-assertion verification: the issuer (which decides the acceptable aud)
// and a replay ledger.
func clientAssertionSvc(replay clientAssertionReplayGuard) *OAuthService {
	return &OAuthService{issuer: testAssertionIssuer, clientAssertionReplay: replay}
}

// inlineJWKS renders key's PUBLIC half as a one-key JWK Set, the shape a client
// registers in its `jwks` member.
func inlineJWKS(t *testing.T, key *ecdsa.PrivateKey) json.RawMessage {
	t.Helper()
	pub, err := jwk.Import[jwk.Key](&key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "test-key"))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	return raw
}

// privateKeyJWTClient is a client registered for private_key_jwt with key's
// public half published inline.
func privateKeyJWTClient(t *testing.T, clientID string, key *ecdsa.PrivateKey) *domain.OAuthClient {
	t.Helper()
	return &domain.OAuthClient{
		ClientID:                clientID,
		ClientType:              "confidential",
		TokenEndpointAuthMethod: clientAuthMethodPrivateKeyJWT,
		JWKS:                    inlineJWKS(t, key),
		IsActive:                true,
	}
}

// assertionOpts are the knobs a test bends to produce a malformed assertion.
type assertionOpts struct {
	iss      string
	sub      string
	aud      string
	jti      string
	lifetime time.Duration
	omitExp  bool
	omitJTI  bool
	omitAud  bool
}

// mintAssertion builds a client assertion, applying opts over valid defaults so
// each test states only the ONE thing it is making wrong.
func mintAssertion(t *testing.T, key *ecdsa.PrivateKey, clientID string, opts assertionOpts) string {
	t.Helper()

	iss, sub, aud := clientID, clientID, testAssertionIssuer
	if opts.iss != "" {
		iss = opts.iss
	}
	if opts.sub != "" {
		sub = opts.sub
	}
	if opts.aud != "" {
		aud = opts.aud
	}
	jti := "jti-" + t.Name()
	if opts.jti != "" {
		jti = opts.jti
	}
	lifetime := time.Minute
	if opts.lifetime != 0 {
		lifetime = opts.lifetime
	}
	now := time.Now()
	b := jwt.NewBuilder().Issuer(iss).Subject(sub).IssuedAt(now)
	if !opts.omitAud {
		b = b.Audience([]string{aud})
	}
	if !opts.omitExp {
		b = b.Expiration(now.Add(lifetime))
	}
	if !opts.omitJTI {
		b = b.JwtID(jti)
	}
	tok, err := b.Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

func TestVerifyClientAssertion_AcceptsAValidAssertion(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-ok", key)

	err := svc.verifyClientAssertion(context.Background(), client, "client-ok",
		mintAssertion(t, key, "client-ok", assertionOpts{}), clientAssertionTypeJWTBearer)
	require.NoError(t, err)
}

// The aud check is what stops an assertion minted for ANOTHER authorization
// server — which that server observes in the clear on every request — from
// being replayed against this one.
func TestVerifyClientAssertion_RejectsAssertionMintedForAnotherServer(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-aud", key)

	err := svc.verifyClientAssertion(context.Background(), client, "client-aud",
		mintAssertion(t, key, "client-aud", assertionOpts{aud: "https://other-as.example.com"}),
		clientAssertionTypeJWTBearer)
	wantOAuthError(t, err, oautherror.InvalidClient)
}

// RFC 7523 §3 permits either the issuer identifier or the token endpoint URL.
// Accepting only one of them breaks roughly half of conformant clients.
func TestVerifyClientAssertion_AcceptsTokenEndpointAsAudience(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-te", key)

	err := svc.verifyClientAssertion(context.Background(), client, "client-te",
		mintAssertion(t, key, "client-te", assertionOpts{aud: testAssertionIssuer + "/oauth2/token"}),
		clientAssertionTypeJWTBearer)
	require.NoError(t, err)
}

func TestVerifyClientAssertion_RejectsMalformedClaims(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		opts assertionOpts
		why  string
	}{
		"sub is another client": {
			opts: assertionOpts{sub: "someone-else"},
			why:  "sub binds the assertion to this client, not merely to a key in its JWKS",
		},
		"iss is another client": {
			opts: assertionOpts{iss: "someone-else"},
			why:  "iss must be the client_id (RFC 7523 §3 item 1)",
		},
		"no exp": {
			opts: assertionOpts{omitExp: true},
			why:  "an assertion with no expiry is a bearer credential forever",
		},
		"no jti": {
			opts: assertionOpts{omitJTI: true},
			why:  "without jti there is nothing to make single-use",
		},
		"no aud": {
			opts: assertionOpts{omitAud: true},
			why:  "an unaudienced assertion is replayable against any server",
		},
		"exp far in the future": {
			opts: assertionOpts{lifetime: 24 * time.Hour},
			why:  "a long-lived assertion is a standing credential equivalent to the private key",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key := newECKey(t)
			svc := clientAssertionSvc(newFakeReplay())
			client := privateKeyJWTClient(t, "client-x", key)

			err := svc.verifyClientAssertion(context.Background(), client, "client-x",
				mintAssertion(t, key, "client-x", tc.opts), clientAssertionTypeJWTBearer)
			oe := wantOAuthError(t, err, oautherror.InvalidClient)
			if oe.HTTPStatus != 401 {
				t.Fatalf("%s: expected 401, got %d", tc.why, oe.HTTPStatus)
			}
		})
	}
}

// An assertion signed by a key the client never published must fail even though
// every claim is otherwise perfect — this is the whole point of the mechanism.
func TestVerifyClientAssertion_RejectsForeignSigningKey(t *testing.T) {
	t.Parallel()
	registered, attacker := newECKey(t), newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-key", registered)

	err := svc.verifyClientAssertion(context.Background(), client, "client-key",
		mintAssertion(t, attacker, "client-key", assertionOpts{}), clientAssertionTypeJWTBearer)
	wantOAuthError(t, err, oautherror.InvalidClient)
}

func TestVerifyClientAssertion_RejectsReplay(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-replay", key)
	assertion := mintAssertion(t, key, "client-replay", assertionOpts{jti: "fixed-jti"})

	require.NoError(t, svc.verifyClientAssertion(context.Background(), client, "client-replay",
		assertion, clientAssertionTypeJWTBearer))

	err := svc.verifyClientAssertion(context.Background(), client, "client-replay",
		assertion, clientAssertionTypeJWTBearer)
	wantOAuthError(t, err, oautherror.InvalidClient)
}

// A verification failure must not burn the jti — otherwise anyone who can
// observe an assertion can pre-consume its identifier and lock the legitimate
// client out of its own request.
func TestVerifyClientAssertion_FailedVerificationDoesNotConsumeJTI(t *testing.T) {
	t.Parallel()
	registered, attacker := newECKey(t), newECKey(t)
	replay := newFakeReplay()
	svc := clientAssertionSvc(replay)
	client := privateKeyJWTClient(t, "client-burn", registered)

	// Attacker replays the jti with a bad signature first.
	badErr := svc.verifyClientAssertion(context.Background(), client, "client-burn",
		mintAssertion(t, attacker, "client-burn", assertionOpts{jti: "contested"}), clientAssertionTypeJWTBearer)
	require.Error(t, badErr)

	// The real client's assertion with the same jti must still succeed.
	require.NoError(t, svc.verifyClientAssertion(context.Background(), client, "client-burn",
		mintAssertion(t, registered, "client-burn", assertionOpts{jti: "contested"}), clientAssertionTypeJWTBearer))
}

// A missing replay ledger must fail closed. Accepting the assertion would
// silently downgrade single-use to unlimited-use, which is invisible in every
// functional test because the happy path still works.
func TestVerifyClientAssertion_FailsClosedWithoutAReplayStore(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(nil)
	client := privateKeyJWTClient(t, "client-nostore", key)

	err := svc.verifyClientAssertion(context.Background(), client, "client-nostore",
		mintAssertion(t, key, "client-nostore", assertionOpts{}), clientAssertionTypeJWTBearer)
	oe := wantOAuthError(t, err, oautherror.ServerError)
	require.Equal(t, 500, oe.HTTPStatus)
}

func TestVerifyClientAssertion_RejectsWrongAssertionType(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-type", key)

	for _, typ := range []string{"", "urn:ietf:params:oauth:grant-type:jwt-bearer", "made-up"} {
		err := svc.verifyClientAssertion(context.Background(), client, "client-type",
			mintAssertion(t, key, "client-type", assertionOpts{}), typ)
		wantOAuthError(t, err, oautherror.InvalidClient)
	}
}

// A client registered for private_key_jwt with no published keys cannot be
// authenticated. Registration refuses this shape, so reaching it means a
// pre-existing row — it must fail rather than fall through.
func TestVerifyClientAssertion_RejectsClientWithNoPublishedKeys(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := &domain.OAuthClient{
		ClientID:                "client-nokeys",
		TokenEndpointAuthMethod: clientAuthMethodPrivateKeyJWT,
		IsActive:                true,
	}

	err := svc.verifyClientAssertion(context.Background(), client, "client-nokeys",
		mintAssertion(t, key, "client-nokeys", assertionOpts{}), clientAssertionTypeJWTBearer)
	wantOAuthError(t, err, oautherror.InvalidClient)
}

// ── enforceRegisteredClientAuthMethod ────────────────────────────────────────

// The downgrade this whole issue exists to close: a private_key_jwt client
// presenting no credential, or a secret, must not authenticate.
func TestEnforceRegisteredClientAuthMethod_PrivateKeyJWTCannotDowngrade(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-dg", key)

	t.Run("nothing presented", func(t *testing.T) {
		err := svc.enforceRegisteredClientAuthMethod(context.Background(), client, "client-dg", "", "", "")
		wantOAuthError(t, err, oautherror.InvalidClient)
	})

	t.Run("a secret presented", func(t *testing.T) {
		err := svc.enforceRegisteredClientAuthMethod(context.Background(), client, "client-dg", "some-secret", "", "")
		wantOAuthError(t, err, oautherror.InvalidClient)
	})
}

// RFC 6749 §2.3: at most one authentication method per request. Refusing the
// ambiguous case avoids defining a precedence rule an attacker could use to get
// the weaker credential evaluated.
func TestEnforceRegisteredClientAuthMethod_RejectsTwoMethodsAtOnce(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-both", key)

	err := svc.enforceRegisteredClientAuthMethod(context.Background(), client, "client-both",
		"a-secret", mintAssertion(t, key, "client-both", assertionOpts{}), clientAssertionTypeJWTBearer)
	wantOAuthError(t, err, oautherror.InvalidClient)
}

// A client that never registered a signing key cannot authenticate with one.
func TestEnforceRegisteredClientAuthMethod_SecretClientCannotUseAnAssertion(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())

	for _, method := range []string{"client_secret_basic", "client_secret_post", "none", ""} {
		client := &domain.OAuthClient{
			ClientID:                "client-secretish",
			TokenEndpointAuthMethod: method,
			JWKS:                    inlineJWKS(t, key),
			IsActive:                true,
		}
		err := svc.enforceRegisteredClientAuthMethod(context.Background(), client, "client-secretish",
			"", mintAssertion(t, key, "client-secretish", assertionOpts{}), clientAssertionTypeJWTBearer)
		wantOAuthError(t, err, oautherror.InvalidClient)
	}
}

// The secret-based methods stay interchangeable: pinning a client to the exact
// string it registered would break working deployments for no security gain,
// since proving knowledge of the secret is identical either way.
func TestEnforceRegisteredClientAuthMethod_SecretMethodsRemainInterchangeable(t *testing.T) {
	t.Parallel()
	svc := clientAssertionSvc(newFakeReplay())

	for _, method := range []string{"client_secret_basic", "client_secret_post", "none", ""} {
		client := &domain.OAuthClient{ClientID: "c", TokenEndpointAuthMethod: method, IsActive: true}
		require.NoError(t,
			svc.enforceRegisteredClientAuthMethod(context.Background(), client, "c", "the-secret", "", ""),
			"method %q must still accept a secret regardless of which spelling it registered", method)
	}
}

// ── ClientIDFromAssertion ────────────────────────────────────────────────────

// Conformant private_key_jwt clients omit client_id and rely on iss. Failing to
// read it is the same interop break as reading the grant assertion only from
// the legacy `subject` spelling.
func TestClientIDFromAssertion(t *testing.T) {
	t.Parallel()
	key := newECKey(t)

	got, ok := ClientIDFromAssertion(mintAssertion(t, key, "client-iss", assertionOpts{}))
	require.True(t, ok)
	require.Equal(t, "client-iss", got)

	for _, bad := range []string{"", "not-a-jwt", "a.b.c"} {
		_, ok := ClientIDFromAssertion(bad)
		require.False(t, ok, "unparseable input %q must not yield a client_id", bad)
	}
}

// jwtalg.Validate runs BEFORE jwx sees the token, so alg confusion dies on the
// header rather than depending on key selection to refuse it. That ordering
// matters here more than elsewhere: the client registers its own public key, so
// an attacker who can register a client controls one side of the comparison.
func TestVerifyClientAssertion_RejectsSymmetricAlgorithm(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-alg", key)

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer("client-alg").Subject("client-alg").
		Audience([]string{testAssertionIssuer}).
		IssuedAt(now).Expiration(now.Add(time.Minute)).JwtID("hs-jti").
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), []byte("not-a-real-key")))
	require.NoError(t, err)

	err = svc.verifyClientAssertion(context.Background(), client, "client-alg",
		string(signed), clientAssertionTypeJWTBearer)
	wantOAuthError(t, err, oautherror.InvalidClient)
}

// The single-use ledger is keyed per CLIENT, not globally on the bare jti.
//
// RFC 7519 §4.1.7 makes jti uniqueness the ISSUER's responsibility, and for
// client authentication the issuer is the client — so two clients may
// legitimately choose the same value. Keying the shared table on the bare jti
// made one client's assertion lock out another's, surfacing to the victim as
// "client_assertion has already been used (replay)": an error that reads as an
// attack on them. No adversary needed — two clients deriving jti from a
// timestamp collide whenever they authenticate in the same second.
func TestVerifyClientAssertion_JTIIsScopedPerClient(t *testing.T) {
	t.Parallel()
	replay := newFakeReplay()
	svc := clientAssertionSvc(replay)

	keyA, keyB := newECKey(t), newECKey(t)
	clientA := privateKeyJWTClient(t, "client-a", keyA)
	clientB := privateKeyJWTClient(t, "client-b", keyB)

	// Both clients pick the same, entirely ordinary, jti.
	require.NoError(t, svc.verifyClientAssertion(context.Background(), clientA, "client-a",
		mintAssertion(t, keyA, "client-a", assertionOpts{jti: "1"}), clientAssertionTypeJWTBearer))

	require.NoError(t, svc.verifyClientAssertion(context.Background(), clientB, "client-b",
		mintAssertion(t, keyB, "client-b", assertionOpts{jti: "1"}),
		clientAssertionTypeJWTBearer),
		"client B must not be locked out by client A's unrelated choice of jti")

	// Single-use still binds WITHIN a client.
	err := svc.verifyClientAssertion(context.Background(), clientA, "client-a",
		mintAssertion(t, keyA, "client-a", assertionOpts{jti: "1"}), clientAssertionTypeJWTBearer)
	wantOAuthError(t, err, oautherror.InvalidClient)
}

// The ledger key must be fixed-length whatever the client sends. The storage
// column is VARCHAR(512), and an over-long key failed the insert with SQLSTATE
// 22001 — not the duplicate-key sentinel — so caller-controlled input produced a
// 500 on the public token endpoint.
func TestClientAssertionReplayKey_IsBoundedAndPerClient(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 4096)
	require.LessOrEqual(t, len(clientAssertionReplayKey(long, long)), 64,
		"the ledger key must not grow with caller input — the column is VARCHAR(512)")

	// Distinctness across both components.
	require.NotEqual(t, clientAssertionReplayKey("a", "j"), clientAssertionReplayKey("b", "j"))
	require.NotEqual(t, clientAssertionReplayKey("a", "j1"), clientAssertionReplayKey("a", "j2"))

	// No delimiter ambiguity: client_id is operator-supplied and may contain the
	// separator a naive join would use.
	require.NotEqual(t, clientAssertionReplayKey("a", "b:c"), clientAssertionReplayKey("a:b", "c"))
}

// An absurd jti is refused as invalid_client rather than doing work on it.
func TestVerifyClientAssertion_RejectsOverlongJTI(t *testing.T) {
	t.Parallel()
	key := newECKey(t)
	svc := clientAssertionSvc(newFakeReplay())
	client := privateKeyJWTClient(t, "client-longjti", key)

	err := svc.verifyClientAssertion(context.Background(), client, "client-longjti",
		mintAssertion(t, key, "client-longjti", assertionOpts{jti: strings.Repeat("x", 600)}),
		clientAssertionTypeJWTBearer)
	oe := wantOAuthError(t, err, oautherror.InvalidClient)
	require.Equal(t, 401, oe.HTTPStatus, "caller-controlled input must not produce a 5xx")
}
