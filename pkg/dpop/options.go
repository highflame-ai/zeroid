package dpop

import (
	"time"

	"github.com/rs/zerolog"
)

// Option configures optional Verifier behavior. Required configuration
// (such as the ReplayStore) lives on Config; Option is reserved for tunables
// that have safe defaults.
type Option func(*Verifier)

// WithClockSkew sets the tolerated symmetric clock skew between client and
// server. Default 5s. Increase if clients are known to run on hosts with
// poor NTP discipline; never set above MaxAge / 2.
func WithClockSkew(d time.Duration) Option {
	return func(v *Verifier) { v.clockSkew = d }
}

// WithMaxAge sets the maximum acceptable proof age (now - iat). Default 60s,
// per RFC 9449 §4.3. The replay-store entry TTL is derived from this value.
func WithMaxAge(d time.Duration) Option {
	return func(v *Verifier) { v.maxAge = d }
}

// WithNow overrides the verifier's clock. Intended for tests.
func WithNow(now func() time.Time) Option {
	return func(v *Verifier) { v.nowFn = now }
}

// WithLogger attaches a zerolog logger for structured validation events.
// Defaults to zerolog.Nop().
func WithLogger(l zerolog.Logger) Option {
	return func(v *Verifier) { v.logger = l }
}

// RequireBodyHash enforces that body-bearing requests carry a bh claim. When
// set, Validate returns ErrBodyHashRequired if Body is non-nil and the proof
// has no bh. When unset (default), bh is checked only when present —
// matching the optional-but-trusted-if-present semantics of the extension.
//
// Recommended for gateways and inline guardrails that want to defeat replay
// of a proof against a different request body.
func RequireBodyHash() Option {
	return func(v *Verifier) { v.requireBodyHash = true }
}

// WithURLNormalizer overrides the htu normalization function. Default
// behavior strips query and fragment per RFC 9449 §4.3.
//
// Override only if you have a reverse proxy or path rewriter that produces
// an htu the client could not reproduce — for example, a gateway that
// rewrites /v1/foo to /internal/foo before the request reaches the service.
// In that case, normalize htu the same way on both sides.
func WithURLNormalizer(f func(string) string) Option {
	return func(v *Verifier) { v.urlNormalize = f }
}
