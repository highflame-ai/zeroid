package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/jwtalg"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// clientAssertionTypeJWTBearer is the only client_assertion_type this server
// accepts (RFC 7523 §2.2, registered by RFC 7521 §4.2). The value is an exact
// match — there is no other registered type we implement, so anything else is
// invalid_request rather than a silent fallback to secret-based auth.
const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// maxClientAssertionLifetime bounds how far in the future a client assertion's
// exp may sit. RFC 7523 §3 requires exp but sets no ceiling, so without this a
// client could mint one assertion with a ten-year expiry and hand out a bearer
// credential equivalent to its private key — the exact failure mode jti
// single-use exists to prevent, except the jti ledger only helps for assertions
// we have actually seen. Capping the window bounds the damage of an assertion
// captured in transit before it is first redeemed.
//
// Measured against exp - now rather than exp - iat: iat is OPTIONAL in RFC 7523
// §3, so an iat-based cap is trivially evaded by omitting iat. This form holds
// regardless.
const maxClientAssertionLifetime = 5 * time.Minute

// clientAssertionClockSkew tolerates modest clock drift between the client and
// this server on exp/nbf. Matches the allowance the external-IdP path uses;
// deliberately small because client assertions are machine-minted seconds
// before use, not carried across a user session.
const clientAssertionClockSkew = 60 * time.Second

// clientAssertionReplayGuard records single-use client-assertion jti values so
// a captured assertion cannot be redeemed twice inside its (already bounded)
// lifetime. Satisfied by the shared Postgres replay store that also backs DPoP
// and actor-key proofs; jtis are namespaced before insertion so they can never
// collide across those three producers in the shared table.
type clientAssertionReplayGuard interface {
	Insert(ctx context.Context, jti string, expiresAt time.Time) error
}

// clientAssertionPresented reports whether the caller supplied EITHER half of
// the RFC 7523 §2.2 client-assertion pair. Both halves are checked because a
// request carrying only one is a malformed attempt at key-based auth, and must
// be told so rather than falling through to the secret-based paths — falling
// through would report "client_secret is required", sending the operator of a
// private_key_jwt client looking for a secret that does not exist.
func clientAssertionPresented(assertion, assertionType string) bool {
	return assertion != "" || assertionType != ""
}

// clientAuthMethodPrivateKeyJWT is the RFC 7591 token_endpoint_auth_method
// value for RFC 7523 §2.2 key-based client authentication.
const clientAuthMethodPrivateKeyJWT = "private_key_jwt"

// ClientIDFromAssertion peeks the UNVERIFIED `iss` claim of a client assertion
// so the caller can resolve which client to verify it against.
//
// Conformant private_key_jwt clients routinely omit the separate `client_id`
// parameter, because RFC 7523 §3 already puts the client identifier in the
// assertion's iss (and sub). A server that insists on `client_id` rejects those
// clients with "unknown client" — the same class of interop failure as reading
// the grant assertion only from the legacy `subject` spelling, where every
// in-house test passed because the harness spoke the server's private dialect.
//
// Peeking before verification is safe and is the pattern the ID-JAG and
// external-IdP paths already use: the unverified iss only SELECTS which
// registered client (and therefore which key set) the assertion is checked
// against. It grants nothing. An attacker who names another client's iss merely
// gets their assertion verified against that client's public keys, which it will
// fail. The value must never be used for anything but lookup.
func ClientIDFromAssertion(assertion string) (string, bool) {
	if assertion == "" {
		return "", false
	}
	peeked, err := jwt.ParseInsecure([]byte(assertion))
	if err != nil {
		return "", false
	}
	iss, ok := peeked.Issuer()
	if !ok || iss == "" {
		return "", false
	}
	return iss, true
}

// enforceRegisteredClientAuthMethod makes a client's REGISTERED
// token_endpoint_auth_method binding at authentication time — closing the
// downgrade where a client that chose key-based auth could authenticate with a
// secret, or with nothing at all.
//
// The enforced boundary is deliberately coarse: secret-based vs assertion-based
// vs none, NOT the exact registered spelling. client_secret_post and
// client_secret_basic are treated as one equivalence class because they differ
// only in where the same secret is carried on the wire, and today's clients use
// them interchangeably — pinning a client to the exact string it registered with
// would break working deployments for no security gain, since proving knowledge
// of the secret is identical either way. What matters, and what this enforces,
// is that a private_key_jwt client can NEVER satisfy authentication with a
// secret or with silence, and that a secret-based client can never satisfy it
// with an assertion signed by a key nobody vetted.
func (s *OAuthService) enforceRegisteredClientAuthMethod(
	ctx context.Context,
	client *domain.OAuthClient,
	clientID, clientSecret, assertion, assertionType string,
) error {
	presented := clientAssertionPresented(assertion, assertionType)

	// RFC 6749 §2.3: "The client MUST NOT use more than one authentication
	// method in each request." Refusing the ambiguous request outright avoids
	// having to define which credential wins — a precedence rule is exactly the
	// kind of thing an attacker uses to get the weaker one evaluated.
	if presented && clientSecret != "" {
		return oauthUnauthorized(
			"client presented both a client_secret and a client_assertion; exactly one authentication method is permitted", nil)
	}

	if client.TokenEndpointAuthMethod == clientAuthMethodPrivateKeyJWT {
		if !presented {
			return oauthUnauthorized(
				"client is registered for private_key_jwt and must authenticate with a client_assertion (RFC 7523 §2.2)", nil)
		}
		return s.verifyClientAssertion(ctx, client, clientID, assertion, assertionType)
	}

	// A client that did NOT register for private_key_jwt cannot authenticate
	// with an assertion. This is not pedantry: for a public (method "none") or
	// secret-based client, nothing at registration vetted a signing key, so
	// accepting an assertion would mean verifying it against whatever `jwks`
	// happened to be stored — or, worse, treating an unverifiable assertion as
	// an authenticated caller.
	if presented {
		return oauthUnauthorized(
			"client is not registered for private_key_jwt and cannot authenticate with a client_assertion", nil)
	}
	return nil
}

// requireNonAssertionClientAuth is the client-authentication precondition for
// surfaces that do NOT accept a client_assertion: currently the CIBA
// bc-authorize and token-poll paths, which authenticate with a client_secret or
// not at all.
//
// It exists because those paths test confidentiality as
// `ClientType == "confidential" || ClientSecret != ""`, and a key-based client
// satisfies NEITHER — registration derives client_type from the separate
// `confidential` flag, so such a client lands client_type=public with an empty
// secret hash and skips the authentication block entirely. On bc-authorize that
// is not a quiet downgrade: the endpoint fires the deployer's notifier, so an
// unauthenticated caller could spam real SMS/push approval prompts at arbitrary
// users under that client's identity.
//
// Note this gap predates private_key_jwt support — #346 added
// rejectUnimplementedClientAuth to the token and inspection paths but not to
// these two, so a client registered for tls_client_auth could already initiate
// CIBA unauthenticated. Both halves are closed here.
//
// A private_key_jwt client is refused rather than verified because these inputs
// carry no client_assertion to verify. Failing closed is the same call #346
// made: refusing is strictly better than proceeding unauthenticated, and it
// cannot regress a working deployment because no such client can be
// authenticating correctly on these paths today. Accepting a client_assertion
// on CIBA (Core §7.1 permits it) is deliberate follow-up, not part of this
// change.
func requireNonAssertionClientAuth(client *domain.OAuthClient) error {
	if err := rejectUnimplementedClientAuth(client); err != nil {
		return err
	}
	if client != nil && client.TokenEndpointAuthMethod == clientAuthMethodPrivateKeyJWT {
		return oauthBadRequest(oautherror.InvalidClient,
			"client is registered for private_key_jwt, which this endpoint does not yet accept; "+
				"it cannot be authenticated here")
	}
	return nil
}

// verifyClientAssertion authenticates a client by RFC 7523 §2.2 private_key_jwt:
// a compact JWS signed by a key the client published in its registered `jwks`
// or `jwks_uri`, proving control of that key without a shared secret.
//
// Claim requirements (RFC 7523 §3):
//
//	iss = client_id   the assertion is self-issued by the client
//	sub = client_id   for client auth the subject IS the client (§3 item 2)
//	aud               an identifier of THIS authorization server (see below)
//	exp               present, in the future, within maxClientAssertionLifetime
//	jti               present and single-use (replay-protected)
//
// The alg allow-list gate runs BEFORE any parsing (jwtalg.Validate), so alg=none
// and the HS* family die on the header rather than depending on jwx's key
// selection to refuse them. This is the same defense-in-depth ordering the
// external-IdP path uses, and it matters more here: a client registers its own
// public key, so an attacker who can register a client controls one side of the
// verification input.
//
// Returns nil on success. Every failure is *OAuthError invalid_client (401) —
// RFC 6749 §5.2 assigns that code to failed client authentication, and the
// distinction between "bad signature" and "wrong aud" is deliberately not
// surfaced to the caller beyond the description string.
func (s *OAuthService) verifyClientAssertion(
	ctx context.Context,
	client *domain.OAuthClient,
	clientID, assertion, assertionType string,
) error {
	if assertionType != clientAssertionTypeJWTBearer {
		// An empty type with a non-empty assertion lands here too: RFC 7521
		// §4.2 makes client_assertion_type REQUIRED whenever client_assertion
		// is present, so we do not infer it.
		return oauthUnauthorized(fmt.Sprintf(
			"client_assertion_type must be %q", clientAssertionTypeJWTBearer), nil)
	}
	if assertion == "" {
		return oauthUnauthorized("client_assertion is required when client_assertion_type is supplied", nil)
	}
	if client == nil {
		return oauthUnauthorized("invalid client credentials", nil)
	}

	if err := jwtalg.Validate(assertion); err != nil {
		return oauthUnauthorized("client_assertion uses an unsupported algorithm", err)
	}

	// Resolve the client's published verification keys. A client registered for
	// private_key_jwt with neither jwks nor jwks_uri cannot be authenticated at
	// all — registration should have refused it (validateClientAuthMethodKeys),
	// so reaching this branch means a pre-existing row. Fail closed.
	keySet, err := s.clientVerificationKeys(ctx, client)
	if err != nil {
		return err
	}

	// WithInferAlgorithmFromKey for the same reason the external-IdP path needs
	// it: a JWK published without an `alg` member supplies no key to jwx
	// otherwise, and plenty of real key-generation tooling omits it. Safe here
	// because jwtalg.Validate has already pinned the header alg to the
	// asymmetric allow-list, and jwx's infer path independently refuses a header
	// alg the key type cannot produce.
	//
	// WithRequireKid(false) because `kid` is OPTIONAL in RFC 7515 §4.1.4, and a
	// client that published exactly one key has no reason to send one. jwx
	// defaults to requiring it and fails closed with "no key ID specified in
	// token" — which would have made private_key_jwt work only for clients that
	// happen to set kid, the same shape of silent interop gap as reading the
	// grant assertion solely from the legacy `subject` parameter. With it off,
	// jwx tries each key in the set; a wrong key simply fails the signature
	// check, so this widens compatibility without widening what verifies.
	//
	// Deliberately parsed WITHOUT jwt.WithAudience: RFC 7523 §3 item 3 permits
	// the token endpoint URL *or* an issuer identifier for this server, and jwx
	// accepts only a single expected value per call. The aud check runs below
	// against the full accepted set.
	verified, err := jwt.Parse([]byte(assertion),
		jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true), jws.WithRequireKid(false)),
		jwt.WithValidate(true),
		jwt.WithIssuer(clientID),
		jwt.WithAcceptableSkew(clientAssertionClockSkew),
	)
	if err != nil {
		return oauthUnauthorized("client_assertion verification failed", err)
	}

	// sub = client_id. jwx does not check sub, and RFC 7523 §3 item 2 is the
	// claim that actually binds the assertion to this client rather than merely
	// to a key that happens to be in its JWKS.
	if sub, ok := verified.Subject(); !ok || sub != clientID {
		return oauthUnauthorized("client_assertion sub must equal the client_id", nil)
	}

	if err := s.checkClientAssertionAudience(verified); err != nil {
		return err
	}

	// exp: jwx validates it only when present, so require it explicitly — an
	// assertion with no expiry is a replayable bearer credential forever.
	exp, ok := verified.Expiration()
	if !ok {
		return oauthUnauthorized("client_assertion missing required exp claim", nil)
	}
	if time.Until(exp) > maxClientAssertionLifetime+clientAssertionClockSkew {
		return oauthUnauthorized(fmt.Sprintf(
			"client_assertion exp is more than %s in the future", maxClientAssertionLifetime), nil)
	}

	jti, ok := verified.JwtID()
	if !ok || jti == "" {
		return oauthUnauthorized("client_assertion missing required jti claim", nil)
	}

	// Single-use enforcement, LAST — after every other check has passed, so a
	// malformed or unverifiable assertion cannot burn a jti and thereby lock out
	// the legitimate assertion that happens to reuse it. Mirrors the ordering
	// the ID-JAG path documents (ADR 0010 D2a).
	//
	// Fail closed on a missing store: reaching here means a private_key_jwt
	// client is authenticating for real, and accepting it with no replay ledger
	// would silently downgrade single-use to unlimited-use.
	if s.clientAssertionReplay == nil {
		return oauthServerError("client assertion replay store is not configured", nil)
	}
	if err := s.clientAssertionReplay.Insert(ctx, "cla:"+jti, exp); err != nil {
		if errors.Is(err, dpop.ErrReplay) {
			return oauthUnauthorized("client_assertion has already been used (replay)", nil)
		}
		return oauthServerError("client assertion replay check failed", err)
	}

	return nil
}

// checkClientAssertionAudience enforces RFC 7523 §3 item 3: the assertion's aud
// must identify THIS authorization server. Both the issuer identifier and the
// token endpoint URL are accepted, because the spec names the token endpoint URL
// while OpenID Connect Core §9 and most client libraries send the issuer — a
// server that accepts only one of them fails against half the conformant clients
// in existence.
//
// Rejecting an aud we do not recognise is what stops a client assertion minted
// for a DIFFERENT authorization server (which that server could capture) from
// being replayed against this one.
func (s *OAuthService) checkClientAssertionAudience(verified jwt.Token) error {
	accepted := s.acceptedClientAssertionAudiences()
	aud, ok := verified.Audience()
	if !ok || len(aud) == 0 {
		return oauthUnauthorized("client_assertion missing required aud claim", nil)
	}
	for _, a := range aud {
		if accepted[a] {
			return nil
		}
	}
	return oauthUnauthorized("client_assertion aud does not identify this authorization server", nil)
}

// acceptedClientAssertionAudiences is the set of aud values that identify this
// server for client-authentication purposes.
func (s *OAuthService) acceptedClientAssertionAudiences() map[string]bool {
	tokenEndpoint := strings.TrimRight(s.issuer, "/") + "/oauth2/token"
	return map[string]bool{
		s.issuer:      true,
		tokenEndpoint: true,
	}
}
