# authjwt

Go client library for verifying ZeroID-issued JWTs. Handles JWKS fetching, caching, key rotation, signature validation (ES256 + RS256), and claim extraction.

## Install

```bash
go get github.com/highflame-ai/zeroid/pkg/authjwt
```

## Quick Start

```go
verifier, err := authjwt.NewVerifier(authjwt.VerifierConfig{
    JWKSURL:  "https://your-zeroid-instance/.well-known/jwks.json",
    Issuer:   "https://your-zeroid-instance",
    Audience: "my-mcp-server",
})
if err != nil {
    log.Fatal(err)
}
defer verifier.Close()

// Local validation (fast, good for most operations)
claims, err := verifier.Verify(ctx, tokenString)

// Real-time validation (calls introspection endpoint to check revocation)
claims, err := verifier.VerifyRealTime(ctx, tokenString)
```

## Agent Identity

For NHI tokens (agents, applications, services), extract a typed agent object:

```go
claims, _ := verifier.Verify(ctx, token)

agent := claims.Agent()
if agent == nil {
    // Human token — no agent identity
}

agent.Sub             // WIMSE URI: spiffe://zeroid.dev/acct/proj/agent/my-agent
agent.ExternalID      // Caller-chosen identity ID
agent.IdentityType    // agent, application, service, mcp_server
agent.TrustLevel      // first_party, verified_third_party, unverified
agent.DelegatedBy     // act.sub — who delegated (empty if direct credential)
agent.DelegationDepth // Number of delegation hops
agent.Owner           // User who provisioned this identity
agent.Scopes          // Granted OAuth scopes
```

## Scope Enforcement

```go
// Check inline
if claims.HasScope("repo:read") {
    // allowed
}

// Or return an error
if err := claims.RequireScope("repo:write"); err != nil {
    // returns authjwt.ErrInsufficientScope
}
```

## HTTP Middleware

Drop-in middleware for any `net/http` compatible router:

```go
mw := authjwt.Middleware(authjwt.MiddlewareConfig{
    Verifier:    verifier,
    ExemptPaths: []string{"/health", "/.well-known/"},
})

router.Use(mw)

// In your handler:
claims := authjwt.ClaimsFromContext(r.Context())
```

## Real-Time Verification

For high-stakes operations, verify that the token hasn't been revoked:

```go
verifier, _ := authjwt.NewVerifier(authjwt.VerifierConfig{
    JWKSURL:       "https://your-zeroid-instance/.well-known/jwks.json",
    IntrospectURL: "https://your-zeroid-instance/oauth2/token/introspect",
})

// Performs local validation + server-side introspection (RFC 7662)
claims, err := verifier.VerifyRealTime(ctx, token)
// err == authjwt.ErrTokenRevoked if token was revoked
```

## Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `JWKSURL` | JWKS endpoint URL (required) | — |
| `Issuer` | Expected `iss` claim | — (skip check) |
| `Audience` | Expected `aud` claim | — (skip check) |
| `IntrospectURL` | RFC 7662 introspection endpoint | — (disable real-time) |
| `JWKSOptions` | JWKS client options (refresh interval, timeout, HTTP client) | 5min refresh, 10s timeout |

## Features

- **JWKS caching** with background refresh (default 5 minutes)
- **Automatic key rotation** — unknown `kid` triggers on-demand JWKS refresh
- **ES256 + RS256** via `kid` + `alg` matching (algorithm allowlist prevents confusion attacks)
- **Typed claims** with `Custom` map for deployment-specific fields
- **Zero ZeroID server dependencies** — only `lestrrat-go/jwx` + `zerolog`
