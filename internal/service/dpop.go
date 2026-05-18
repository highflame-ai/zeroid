package service

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/uptrace/bun"
)

// ErrDPoPStorageFailure is returned when the JTI replay-prevention store is
// unavailable. Callers must map this to a 5xx response, not a 4xx "invalid proof".
var ErrDPoPStorageFailure = errors.New("dpop jti store unavailable")

// dpopFreshnessWindow is the maximum age of a DPoP proof's iat claim.
// RFC 9449 §4.2 recommends a window of at most a few minutes; 60 s is conservative.
const dpopFreshnessWindow = 60 * time.Second

// dpopClockSkewTolerance allows proofs whose iat is slightly in the future
// to compensate for minor clock differences between client and server.
const dpopClockSkewTolerance = 5 * time.Second

// dpopMaxJTILen caps the JTI claim at the database column width so an oversized
// jti from a malicious client surfaces as a 4xx proof-invalid error rather than
// a Postgres "value too long for type" that consumeJTI would mis-map to a 5xx.
const dpopMaxJTILen = 512

// dpopJTIRecord is the bun model for the dpop_jti replay-prevention table.
type dpopJTIRecord struct {
	bun.BaseModel `bun:"table:dpop_jti"`
	JTI           string    `bun:"jti,pk"`
	ExpiresAt     time.Time `bun:"expires_at"`
}

// DPoPService validates DPoP proofs (RFC 9449) and prevents proof replay via JTI tracking.
type DPoPService struct {
	db *bun.DB
}

// NewDPoPService creates a new DPoPService backed by the given database.
func NewDPoPService(db *bun.DB) *DPoPService {
	return &DPoPService{db: db}
}

// ValidateProof validates a DPoP proof JWT at the token endpoint.
// method is the HTTP method (e.g. "POST") and htu is the full target URI.
// Returns the base64url JWK thumbprint (RFC 7638 SHA-256) of the proof key on success.
func (s *DPoPService) ValidateProof(ctx context.Context, method, htu, proofJWT string) (string, error) {
	return s.validate(ctx, method, htu, proofJWT, nil)
}

// ValidateProofForToken validates a DPoP proof at a protected resource endpoint for a
// DPoP-bound access token. The proof must carry an ath claim equal to
// base64url(SHA-256(accessToken)). Returns the JWK thumbprint on success.
// Per RFC 9449 §8.2, the authorization server's introspection endpoint returns the
// cnf claim but does not itself validate proofs — resource servers call this method.
func (s *DPoPService) ValidateProofForToken(ctx context.Context, method, htu, proofJWT string, accessToken []byte) (string, error) {
	return s.validate(ctx, method, htu, proofJWT, accessToken)
}

func (s *DPoPService) validate(ctx context.Context, method, htu, proofJWT string, accessToken []byte) (string, error) {
	// 1. Parse the JWS message to access protected headers without verifying the signature yet.
	msg, err := jws.Parse([]byte(proofJWT))
	if err != nil {
		return "", fmt.Errorf("dpop proof is malformed: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return "", errors.New("dpop proof: no signatures present")
	}
	hdr := sigs[0].ProtectedHeaders()

	// 2. typ MUST be "dpop+jwt" (RFC 9449 §4.2).
	typ, _ := hdr.Type()
	if typ != "dpop+jwt" {
		return "", errors.New("dpop proof: typ header must be dpop+jwt")
	}

	// 3. Algorithm MUST be an asymmetric signature algorithm (RFC 9449 §4.2).
	//    We accept ES256 and RS256; symmetric algorithms are not allowed for DPoP.
	alg, ok := hdr.Algorithm()
	if !ok {
		return "", errors.New("dpop proof: alg header is required")
	}
	switch alg {
	case jwa.ES256(), jwa.RS256():
		// accepted
	default:
		return "", fmt.Errorf("dpop proof: algorithm %s is not supported; use ES256 or RS256", alg)
	}

	// 4. jwk header MUST be present and MUST NOT contain a private key (RFC 9449 §4.2).
	embeddedKey, ok := hdr.JWK()
	if !ok || embeddedKey == nil {
		return "", errors.New("dpop proof: jwk header is required")
	}
	switch embeddedKey.(type) {
	case jwk.ECDSAPrivateKey, jwk.RSAPrivateKey, jwk.OKPPrivateKey:
		return "", errors.New("dpop proof: jwk header must not contain a private key")
	}

	// 5. Verify the proof signature using the embedded public key.
	if _, err := jws.Verify([]byte(proofJWT), jws.WithKey(alg, embeddedKey)); err != nil {
		return "", fmt.Errorf("dpop proof: signature verification failed: %w", err)
	}

	// 6. Parse the JWT payload (signature already verified above).
	parsed, err := jwt.ParseInsecure([]byte(proofJWT))
	if err != nil {
		return "", fmt.Errorf("dpop proof: payload is malformed: %w", err)
	}

	// 7. htm MUST match the HTTP method of the request. RFC 9110 §9.1 says method
	//    names are case-sensitive uppercase, and RFC 9449 §4.2 inherits that —
	//    we compare exactly so a lowercase htm cannot slip past on a server that
	//    later adds DPoP-protected resources with case-collision-sensitive methods.
	htm, _ := jwt.Get[string](parsed, "htm")
	if htm != method {
		return "", fmt.Errorf("dpop proof: htm mismatch (expected %s, got %s)", method, htm)
	}

	// 8. htu MUST match the target URI, ignoring query and fragment (RFC 9449 §4.2).
	htuClaim, _ := jwt.Get[string](parsed, "htu")
	normalizedHTU := normalizeHTU(htu)
	if normalizeHTU(htuClaim) != normalizedHTU {
		return "", fmt.Errorf("dpop proof: htu mismatch (expected %s)", normalizedHTU)
	}

	// 9. iat MUST be present, not too far in the future (clock skew), and within the freshness window.
	iat, ok := parsed.IssuedAt()
	if !ok || iat.IsZero() {
		return "", errors.New("dpop proof: iat claim is required")
	}
	now := time.Now()
	if iat.After(now.Add(dpopClockSkewTolerance)) {
		return "", errors.New("dpop proof: iat is too far in the future")
	}
	if now.After(iat.Add(dpopFreshnessWindow)) {
		return "", errors.New("dpop proof: iat is outside the freshness window (proof has expired)")
	}

	// 9a. If the proof carries optional exp / nbf claims (jwt.ParseInsecure
	//     does NOT validate them; jwx v4's WithKey-based jwt.Parse path is
	//     unavailable here because the signing key is the embedded jwk
	//     header rather than a pre-known KeySet), enforce them ourselves.
	//     RFC 9449 §4.2 permits but does not require exp; if a client
	//     provides it, ignoring it would let an explicitly-expired proof
	//     succeed on the iat freshness check alone.
	if exp, ok := parsed.Expiration(); ok && !exp.IsZero() && now.After(exp.Add(dpopClockSkewTolerance)) {
		return "", errors.New("dpop proof: exp has passed")
	}
	if nbf, ok := parsed.NotBefore(); ok && !nbf.IsZero() && now.Add(dpopClockSkewTolerance).Before(nbf) {
		return "", errors.New("dpop proof: nbf is in the future")
	}

	// 10. jti MUST be unique within the freshness window — consumed atomically via DB INSERT.
	jti, _ := parsed.JwtID()
	if jti == "" {
		return "", errors.New("dpop proof: jti claim is required")
	}
	if len(jti) > dpopMaxJTILen {
		// Bounded at the column width; oversized JTIs are a 4xx (malformed
		// proof), not a 5xx storage failure.
		return "", fmt.Errorf("dpop proof: jti exceeds %d bytes", dpopMaxJTILen)
	}
	// Replay-coverage runs on wall clock (now + freshness + skew), not on the
	// client-supplied iat. iat-relative expiry would let a client backdate
	// iat to shorten the row's lifetime in the JTI store; clock-relative
	// expiry decouples replay-defence from anything the client controls.
	if err := s.consumeJTI(ctx, jti, now.Add(dpopFreshnessWindow+dpopClockSkewTolerance)); err != nil {
		return "", fmt.Errorf("dpop proof: %w", err)
	}

	// 11. ath MUST be present and correct when the proof is for a bound access token (RFC 9449 §4.2).
	if accessToken != nil {
		ath, err := jwt.Get[string](parsed, "ath")
		if err != nil || ath == "" {
			return "", errors.New("dpop proof: ath claim is required when presenting a bound access token")
		}
		if ath != computeATH(accessToken) {
			return "", errors.New("dpop proof: ath mismatch")
		}
	}

	// 12. Compute the JWK thumbprint (RFC 7638 SHA-256) — this becomes the cnf.jkt claim value.
	thumbprintBytes, err := embeddedKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop proof: failed to compute key thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprintBytes), nil
}

// consumeJTI atomically inserts a JTI into the replay-prevention table.
// A primary-key conflict (SQLSTATE 23505) means the JTI was already seen — replay.
// Any other DB error is returned as ErrDPoPStorageFailure so callers can map it
// to a 5xx instead of a misleading 4xx "invalid proof" response.
func (s *DPoPService) consumeJTI(ctx context.Context, jti string, expiresAt time.Time) error {
	rec := &dpopJTIRecord{JTI: jti, ExpiresAt: expiresAt}
	_, err := s.db.NewInsert().Model(rec).Exec(ctx)
	if err == nil {
		return nil
	}
	if isDuplicateKeyError(err) {
		return errors.New("jti replay detected")
	}
	return fmt.Errorf("%w: %w", ErrDPoPStorageFailure, err)
}

// normalizeHTU strips the query and fragment from a URL per RFC 9449 §4.2,
// and lowercases scheme + host per RFC 3986 §3.1 / §3.2.2 (both components are
// case-insensitive). Without the case normalisation a client signing
// `https://Example.com/...` and a server seeing `https://example.com/...`
// (or vice-versa via proxy rewrite) would fail an otherwise-valid proof.
func normalizeHTU(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// computeATH computes the base64url-encoded SHA-256 hash of an access token,
// as required by the ath claim of a DPoP proof (RFC 9449 §4.2).
func computeATH(accessToken []byte) string {
	h := sha256.Sum256(accessToken)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
