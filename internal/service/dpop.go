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
	// RFC 9449 §4.2 defines a DPoP proof as a JWT (compact JWS), which has
	// exactly one signature. JWS JSON Serialization allows multiple, and
	// blindly reading sigs[0] would let a forger attach a benign signature
	// at index 0 alongside an attacker-controlled one at index 1 — only the
	// first set of protected headers would be inspected. Reject anything
	// that isn't a single-signature compact JWS.
	if len(sigs) != 1 {
		return "", fmt.Errorf("dpop proof: expected single-signature compact JWS, got %d signatures", len(sigs))
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
	case jwk.SymmetricKey:
		// Defence-in-depth: an oct JWK in the jwk header is a private key
		// (a shared secret). The alg-asymmetric gate at step 3 already
		// rejects HS256-shaped proofs whose signature would require this,
		// but enumerating the type explicitly keeps the policy honest if
		// a future jwx version adds another asymmetric alg that some
		// implementer wires to a symmetric key.
		return "", errors.New("dpop proof: jwk header must not contain a symmetric key")
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
	if !ok {
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
	//     succeed on the iat freshness check alone. jwx's `ok` bool already
	//     signals presence, so an `IsZero()` follow-up would be redundant.
	if exp, ok := parsed.Expiration(); ok && now.After(exp.Add(dpopClockSkewTolerance)) {
		return "", errors.New("dpop proof: exp has passed")
	}
	if nbf, ok := parsed.NotBefore(); ok && now.Add(dpopClockSkewTolerance).Before(nbf) {
		return "", errors.New("dpop proof: nbf is in the future")
	}

	// 10. jti MUST be present and bounded at the column width.
	jti, _ := parsed.JwtID()
	if jti == "" {
		return "", errors.New("dpop proof: jti claim is required")
	}
	if len(jti) > dpopMaxJTILen {
		// Bounded at the column width; oversized JTIs are a 4xx (malformed
		// proof), not a 5xx storage failure.
		return "", fmt.Errorf("dpop proof: jti exceeds %d bytes", dpopMaxJTILen)
	}

	// 11. ath MUST be present and correct when the proof is for a bound access token (RFC 9449 §4.2).
	//     Checked BEFORE consumeJTI so an ath mismatch doesn't burn the proof's
	//     jti — the legitimate client can retry with a corrected ath value.
	if len(accessToken) > 0 {
		ath, err := jwt.Get[string](parsed, "ath")
		if err != nil || ath == "" {
			return "", errors.New("dpop proof: ath claim is required when presenting a bound access token")
		}
		if ath != computeATH(accessToken) {
			return "", errors.New("dpop proof: ath mismatch")
		}
	}

	// 12. Compute the JWK thumbprint (RFC 7638 SHA-256) — this becomes the cnf.jkt claim value.
	//     Done BEFORE consumeJTI so a thumbprint-computation failure (vanishingly
	//     unlikely on an ES256/RS256 key that already passed jws.Verify) doesn't
	//     leave the jti consumed but the response a 5xx.
	thumbprintBytes, err := embeddedKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop proof: failed to compute key thumbprint: %w", err)
	}
	thumbprint := base64.RawURLEncoding.EncodeToString(thumbprintBytes)

	// 13. Consume the jti atomically. This is the last side-effecting step;
	//     anything that can reject the proof on its own merits has already
	//     run, so a successful consume → valid proof and we hand back the
	//     thumbprint with confidence the row in dpop_jti will outlive the
	//     freshness window.
	//
	//     Replay-coverage runs on wall clock (now + freshness + skew), not on
	//     the client-supplied iat. iat-relative expiry would let a client
	//     backdate iat to shorten the row's lifetime in the JTI store;
	//     clock-relative expiry decouples replay-defence from anything the
	//     client controls.
	if err := s.consumeJTI(ctx, jti, now.Add(dpopFreshnessWindow+dpopClockSkewTolerance)); err != nil {
		return "", fmt.Errorf("dpop proof: %w", err)
	}
	return thumbprint, nil
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
// lowercases scheme + host per RFC 3986 §3.1 / §3.2.2 (both components are
// case-insensitive), and strips the scheme's default port per §3.2.3
// (`http://example.com:80` and `http://example.com` are URI-equivalent).
// Without these normalisations a client signing one form and a server seeing
// the other — common when a reverse proxy rewrites either case or default
// port — would fail an otherwise-valid proof.
func normalizeHTU(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" && !isDefaultPort(u.Scheme, port) {
		u.Host = host + ":" + port
	} else {
		u.Host = host
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// isDefaultPort reports whether port is the IANA default for scheme.
// Used by normalizeHTU to fold `https://a.com:443` into `https://a.com`
// (and the http/80 equivalent) before comparison.
func isDefaultPort(scheme, port string) bool {
	switch {
	case scheme == "https" && port == "443":
		return true
	case scheme == "http" && port == "80":
		return true
	}
	return false
}

// computeATH computes the base64url-encoded SHA-256 hash of an access token,
// as required by the ath claim of a DPoP proof (RFC 9449 §4.2).
func computeATH(accessToken []byte) string {
	h := sha256.Sum256(accessToken)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
