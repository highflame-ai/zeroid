package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/highflame-ai/zeroid/internal/jwtalg"
	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// ErrKeyProofInvalid is returned when an actor-key enrollment/rotation proof
// fails verification — bad signature, wrong aud/sub, missing/over-long lifetime,
// replay, or (for rotation) a missing or mismatched current-key proof. The
// caller is authenticated (its access token is valid) but has not proven control
// of the key, so handlers map this to 403, not 401.
var ErrKeyProofInvalid = errors.New("actor-key proof verification failed")

// maxKeyProofLifetime bounds how long an actor-key-change proof is valid. Proofs
// are single-use (jti) and audience-bound; the short lifetime caps the replay
// window even before the jti store has recorded the proof.
const maxKeyProofLifetime = 2 * time.Minute

// keyProofReplayGuard records single-use proof identifiers (jti) so a captured
// key-change proof cannot be replayed within its lifetime. Satisfied by the
// shared Postgres replay store (also used for DPoP). Proof jtis are namespaced
// before insertion so they never collide with DPoP jtis in the shared table.
type keyProofReplayGuard interface {
	Insert(ctx context.Context, jti string, expiresAt time.Time) error
}

// verifyActorKeyProof validates a proof-of-possession assertion for actor-key
// enrollment or rotation. The proof is a compact ES256 JWS signed by verifyKey,
// proving the caller controls that key. Required claims:
//
//	aud = the public-key endpoint URL  (binds the proof to this operation)
//	sub = the identity's WIMSE URI     (binds the proof to this identity)
//	jti = single-use identifier        (replay-protected)
//	iat, exp                           (lifetime must be <= maxKeyProofLifetime)
//
// When expectNKT is non-empty, the proof must also carry an "nkt" claim equal to
// it — the base64url SHA-256 of the *new* key's SPKI DER. This binds a
// current-key proof to one specific replacement key (RFC 8555 §7.3.5 intent), so
// a captured current-key proof cannot be paired with an attacker's new key.
//
// alg is pinned to ES256 (alg=none / HS* are rejected before parsing).
func verifyActorKeyProof(
	ctx context.Context,
	proofJWS string,
	verifyKey *ecdsa.PublicKey,
	expectedAud, expectedSub, expectNKT string,
	replay keyProofReplayGuard,
) error {
	if err := jwtalg.Validate(proofJWS); err != nil {
		return fmt.Errorf("proof uses an unsupported algorithm: %w", err)
	}

	tok, err := jwt.Parse([]byte(proofJWS),
		jwt.WithKey(jwa.ES256(), verifyKey),
		jwt.WithValidate(true),
		jwt.WithAudience(expectedAud),
	)
	if err != nil {
		return fmt.Errorf("proof signature/validation failed: %w", err)
	}

	if sub, ok := tok.Subject(); !ok || sub != expectedSub {
		return errors.New("proof sub does not match the identity")
	}

	exp, ok := tok.Expiration()
	if !ok {
		return errors.New("proof missing exp claim")
	}
	iat, ok := tok.IssuedAt()
	if !ok {
		return errors.New("proof missing iat claim")
	}
	// Guard the subtraction: if exp precedes iat (malicious or skewed claims),
	// exp.Sub(iat) is negative and would slip under the lifetime cap.
	if exp.Before(iat) {
		return errors.New("proof exp claim is before its iat claim")
	}
	if exp.Sub(iat) > maxKeyProofLifetime {
		return fmt.Errorf("proof lifetime exceeds %s", maxKeyProofLifetime)
	}

	jti, ok := tok.JwtID()
	if !ok || jti == "" {
		return errors.New("proof missing jti claim")
	}

	if expectNKT != "" {
		v, found := tok.Field("nkt")
		nkt, _ := v.(string)
		if !found || nkt != expectNKT {
			return errors.New("proof nkt does not bind the new key")
		}
	}

	// Single-use enforcement: record the jti, namespaced so key-proof jtis never
	// collide with DPoP jtis in the shared replay table. A duplicate is a replay.
	if err := replay.Insert(ctx, "akp:"+jti, exp); err != nil {
		if errors.Is(err, dpop.ErrReplay) {
			return errors.New("proof has already been used (replay)")
		}
		return fmt.Errorf("proof replay check failed: %w", err)
	}

	return nil
}

// newKeyThumbprint is the value a current-key proof must carry in its "nkt"
// claim to authorize a rotation: base64url(SHA-256(SPKI DER)) of the new public
// key. publicKeyPEM is assumed already validated as an SPKI EC P-256 key.
func newKeyThumbprint(publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", errors.New("new public key is not a PUBLIC KEY PEM block")
	}
	sum := sha256.Sum256(block.Bytes)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
