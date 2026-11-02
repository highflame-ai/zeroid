package authjwt

import (
	"github.com/highflame-ai/zeroid/pkg/jwks"
)

// The JWKS client moved to github.com/highflame-ai/zeroid/pkg/jwks so that both
// this package and the zeroid authorization server can use it without either
// depending on the other. zeroid previously imported THIS package purely to get
// the client, which put a token-verification library for resource servers into
// the dependency graph of the authorization server.
//
// These are aliases, not wrappers: `type A = B` makes the names
// interchangeable at the type level, so existing callers — cerberus, shield,
// authn — compile unchanged and can pass jwks.Option and authjwt.JWKSOption
// values to the same function. Nothing here needs to be kept in sync with the
// upstream package beyond the names themselves.
//
// New code should prefer the pkg/jwks names directly. These remain for
// compatibility and carry no deprecation date — removing them would break
// consumers for no benefit.
type (
	// JWKSClient is an alias for jwks.Client.
	JWKSClient = jwks.Client
	// JWKSOption is an alias for jwks.Option.
	JWKSOption = jwks.Option
)

// NewJWKSClient is an alias for jwks.New.
var NewJWKSClient = jwks.New

// Re-exported JWKS client options. Variables rather than functions so they are
// alias-equivalent to the originals rather than new wrappers.
var (
	// WithRefreshInterval sets how often the JWKS is refreshed in the background.
	WithRefreshInterval = jwks.WithRefreshInterval
	// WithRequestTimeout bounds a single JWKS fetch.
	WithRequestTimeout = jwks.WithRequestTimeout
	// WithHTTPClient supplies the HTTP client used for JWKS fetches — the hook
	// zeroid uses to force every fetch through its SSRF-guarded transport.
	WithHTTPClient = jwks.WithHTTPClient
	// WithLogger sets the logger for JWKS fetch/refresh events.
	WithLogger = jwks.WithLogger
)
