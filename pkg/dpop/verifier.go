package dpop

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Default validation parameters per RFC 9449 §4.3 / §11.1.
const (
	defaultMaxAge    = 60 * time.Second
	defaultClockSkew = 5 * time.Second
	// defaultMaxJTILen caps the jti claim at a value comfortably under the
	// VARCHAR(512) column width used by zeroid's bun-backed ReplayStore. An
	// oversized jti from a client is a 4xx (malformed proof), not the 5xx a
	// store-side truncation error would otherwise produce.
	defaultMaxJTILen = 512
)

// Config configures a Verifier. The zero value is NOT valid — Store is
// required.
type Config struct {
	// Store is the durable replay ledger. Required. Pass MemoryStore for
	// tests / single-instance ephemeral services; pass a persistent store
	// (e.g. zeroid's Postgres-backed dpop store) for multi-replica
	// production deployments.
	Store ReplayStore
}

// Verifier validates DPoP proofs. Safe for concurrent use.
type Verifier struct {
	store           ReplayStore
	clockSkew       time.Duration
	maxAge          time.Duration
	maxJTILen       int
	requireBodyHash bool
	nowFn           func() time.Time
	urlNormalize    func(string) string
	logger          zerolog.Logger
}

// NewVerifier constructs a Verifier from the given Config and options.
//
// Returns an error only for config-level problems (nil Store, contradictory
// options).
func NewVerifier(cfg Config, opts ...Option) (*Verifier, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("dpop: Config.Store is required")
	}
	v := &Verifier{
		store:        cfg.Store,
		clockSkew:    defaultClockSkew,
		maxAge:       defaultMaxAge,
		maxJTILen:    defaultMaxJTILen,
		nowFn:        time.Now,
		urlNormalize: normalizeHTU,
		logger:       zerolog.Nop(),
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.clockSkew*2 > v.maxAge {
		return nil, fmt.Errorf("dpop: clockSkew (%s) must be <= maxAge/2 (%s)", v.clockSkew, v.maxAge/2)
	}
	return v, nil
}

// ValidateRequest is the input to Validate. All fields are required except
// AccessToken (set only when verifying a proof presented alongside a bearer
// token) and Body (set when the bh extension claim should be checked).
type ValidateRequest struct {
	// ProofJWT is the value of the DPoP HTTP header.
	ProofJWT string

	// Method is the HTTP request method (case-insensitive).
	Method string

	// URL is the request URL as seen by the server. Will be normalized
	// per the Verifier's urlNormalize before comparison; clients must
	// generate htu the same way.
	URL string

	// AccessToken is the bearer token presented with the proof, if any.
	// When non-empty, the proof's ath claim is required and checked.
	AccessToken string

	// Body is the request body bytes, if any. When non-nil and the proof
	// carries a bh claim, the body's SHA-256 is matched against bh. When
	// non-nil and the Verifier has RequireBodyHash set, the proof MUST
	// carry bh or ErrBodyHashRequired is returned.
	Body []byte
}

// ValidateResult is the output of a successful Validate call. Inspect the
// thumbprint to bind cnf.jkt on any issued credential; inspect JTI for
// audit logging.
type ValidateResult struct {
	Thumbprint string    // RFC 7638 JWK thumbprint, base64url-no-padding
	JTI        string    // proof's jti claim
	IssuedAt   time.Time // proof's iat claim
	Algorithm  string    // signing algorithm
}

// Validate runs the full RFC 9449 validation pipeline against r:
//
//  1. Parse + signature verify (proof.go)
//  2. htm match (case-insensitive per RFC 9110 §9.1)
//  3. htu match (after normalization — query, fragment, scheme+host case,
//     default port stripped)
//  4. iat within [now - maxAge - clockSkew, now + clockSkew]
//  5. exp + nbf if present (RFC 7519 optional but enforced when set)
//  6. ath match (when AccessToken non-empty) — BEFORE the replay insert so
//     a mis-attached proof can be re-presented with a corrected ath without
//     burning the jti
//  7. bh match (when Body non-nil + bh present; required if RequireBodyHash)
//  8. jti insert into ReplayStore (atomic; LAST because it commits state)
//
// The replay-store row's expires_at is computed against the server's wall
// clock (now + maxAge + clockSkew), NOT against the client-supplied iat —
// iat-relative expiry would let a client backdate iat to shorten the row's
// lifetime in the store and re-use a jti within the freshness window.
//
// Returns a *dpop.Error on failure. Use errors.As to inspect the stable
// Code. Storage failures surface as ErrStorageFailure (CodeStorageFailure)
// and should map to 503; all other failures map to 401 invalid_dpop_proof.
func (v *Verifier) Validate(ctx context.Context, r ValidateRequest) (*ValidateResult, error) {
	proof, err := parseAndVerify(r.ProofJWT, v.urlNormalize, v.maxJTILen)
	if err != nil {
		return nil, err
	}

	if !methodEqual(proof.HTM, r.Method) {
		return nil, withCause(ErrHTMMismatch, fmt.Errorf("proof htm=%q, request method=%q", proof.HTM, r.Method))
	}

	wantHTU := v.urlNormalize(r.URL)
	if !constantTimeStringEq(proof.HTU, wantHTU) {
		return nil, withCause(ErrHTUMismatch, fmt.Errorf("proof htu=%q, request URL (normalized)=%q", proof.HTU, wantHTU))
	}

	if err := v.checkIATFreshness(proof.IssuedAt); err != nil {
		return nil, err
	}
	if err := v.checkExpNbf(proof.ExpiresAt, proof.NotBefore); err != nil {
		return nil, err
	}

	if r.AccessToken != "" {
		if err := checkATH(proof.ATH, r.AccessToken); err != nil {
			return nil, err
		}
	}

	if r.Body != nil {
		if err := v.checkBH(proof.BH, r.Body); err != nil {
			return nil, err
		}
	}

	// jti insert is last — it commits state. Earlier failures must NOT
	// poison the replay store. Wall-clock expiry decouples replay defence
	// from anything the client controls.
	expiresAt := v.nowFn().Add(v.maxAge + v.clockSkew)
	if err := v.store.Insert(ctx, proof.JTI, expiresAt); err != nil {
		var de *Error
		if errors.As(err, &de) {
			return nil, de
		}
		return nil, withCause(ErrStorageFailure, err)
	}

	return &ValidateResult{
		Thumbprint: proof.Thumbprint,
		JTI:        proof.JTI,
		IssuedAt:   proof.IssuedAt,
		Algorithm:  proof.Alg,
	}, nil
}

// ValidateBoundToToken runs Validate and additionally enforces that the
// proof's JWK thumbprint matches expectedJKT (typically pulled from the
// access token's cnf.jkt claim). Use this on resource servers where the
// access token claim must match the presented proof key.
func (v *Verifier) ValidateBoundToToken(ctx context.Context, r ValidateRequest, expectedJKT string) (*ValidateResult, error) {
	res, err := v.Validate(ctx, r)
	if err != nil {
		return nil, err
	}
	if expectedJKT == "" {
		return nil, withCause(ErrTokenBindingMismatch, errors.New("expectedJKT is empty; token must carry cnf.jkt to bind"))
	}
	if !constantTimeStringEq(res.Thumbprint, expectedJKT) {
		return nil, withCause(ErrTokenBindingMismatch, fmt.Errorf("proof thumbprint=%q, expected cnf.jkt=%q", res.Thumbprint, expectedJKT))
	}
	return res, nil
}

// checkIATFreshness validates iat is within the configured window. RFC 9449
// §4.3 calls for both lower (now - maxAge) and upper (now + clockSkew)
// bounds — iat must not be in the past beyond maxAge (replay defense),
// and must not be implausibly in the future (clock-skew tolerance).
func (v *Verifier) checkIATFreshness(iat time.Time) error {
	now := v.nowFn()
	lower := now.Add(-v.maxAge - v.clockSkew)
	upper := now.Add(v.clockSkew)
	if iat.Before(lower) {
		return withCause(ErrClockSkew, fmt.Errorf("iat=%s older than %s (now=%s)", iat, v.maxAge+v.clockSkew, now))
	}
	if iat.After(upper) {
		return withCause(ErrClockSkew, fmt.Errorf("iat=%s more than %s in the future (now=%s)", iat, v.clockSkew, now))
	}
	return nil
}

// checkExpNbf enforces RFC 7519 exp / nbf claims when the proof carries them.
// RFC 9449 §4.2 permits both as optional — when present, ignoring them would
// let an explicitly-expired proof slip past on the iat freshness check alone.
// Zero values from time.Unix(0, 0) cannot occur here because parseAndVerify
// only populates these fields when the corresponding claim is present and
// non-zero.
func (v *Verifier) checkExpNbf(exp, nbf time.Time) error {
	now := v.nowFn()
	if !exp.IsZero() && now.After(exp.Add(v.clockSkew)) {
		return withCause(ErrClockSkew, fmt.Errorf("exp=%s has passed (now=%s)", exp, now))
	}
	if !nbf.IsZero() && now.Add(v.clockSkew).Before(nbf) {
		return withCause(ErrClockSkew, fmt.Errorf("nbf=%s is in the future (now=%s)", nbf, now))
	}
	return nil
}

// checkATH validates the proof's ath claim equals base64url(sha256(token)).
// Constant-time comparison defends against timing oracles.
func checkATH(proofATH, accessToken string) error {
	if proofATH == "" {
		return withCause(ErrATHMismatch, errors.New("proof missing ath; access token was presented"))
	}
	sum := sha256.Sum256([]byte(accessToken))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if !constantTimeStringEq(proofATH, want) {
		return withCause(ErrATHMismatch, errors.New("ath does not match access token hash"))
	}
	return nil
}

// checkBH validates the proof's bh claim equals base64url(sha256(body)).
// When the proof carries no bh and RequireBodyHash is not set, this passes
// silently (per the "optional but trusted if present" extension semantics).
func (v *Verifier) checkBH(proofBH string, body []byte) error {
	if proofBH == "" {
		if v.requireBodyHash {
			return ErrBodyHashRequired
		}
		return nil
	}
	sum := sha256.Sum256(body)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if !constantTimeStringEq(proofBH, want) {
		return withCause(ErrBodyHashMismatch, errors.New("bh does not match request body hash"))
	}
	return nil
}

// methodEqual matches RFC 9449 §4.3: method comparison is case-insensitive,
// matching the HTTP/1.1 method-token case rules.
func methodEqual(a, b string) bool {
	return strings.EqualFold(a, b)
}

// constantTimeStringEq is a length-revealing constant-time string compare.
// The length leak is acceptable — DPoP claim values have well-known lengths
// (e.g. base64url-encoded sha256 hashes are always 43 bytes).
func constantTimeStringEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// normalizeHTU strips the query and fragment from a URL, case-folds the
// scheme + host (RFC 9449 §4.3 → RFC 3986 §6.2.2 syntax-based normalization),
// and strips the scheme's default port (§3.2.3 — `https://example.com:443`
// and `https://example.com` are URI-equivalent). Path case is preserved
// (RFC 3986 leaves path case-sensitivity to the scheme).
//
// Without these normalizations a client signing one form and a server seeing
// the other — common when a reverse proxy rewrites case or default port —
// would fail an otherwise-valid proof.
func normalizeHTU(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Don't panic — return the raw value and let comparison fail explicitly
		// at the equality check; a malformed URL is the caller's bug, not ours.
		return raw
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
	u.RawFragment = ""
	return u.String()
}

// isDefaultPort reports whether port is the IANA default for scheme.
// Used by normalizeHTU to fold `https://a.com:443` into `https://a.com`
// (and the http/80 equivalent) so a proof signed against the default-port
// form matches a request that arrived with an explicit port.
func isDefaultPort(scheme, port string) bool {
	switch {
	case scheme == "https" && port == "443":
		return true
	case scheme == "http" && port == "80":
		return true
	}
	return false
}
