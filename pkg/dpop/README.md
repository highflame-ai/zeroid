# dpop

RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP) — plus the body-hash (`bh`) extension claim. Used by ZeroID to bind issued access tokens to a public key the client holds privately.

DPoP makes a stolen access token useless to an attacker who didn't also steal the matching private key. The client signs a short-lived JWT (the "proof") with that key on every request; the server validates the proof and binds the issued or accepted token to the proof's key via `cnf.jkt`.

This package is a standalone module — depend on it without pulling the rest of ZeroID.

## Install

```bash
go get github.com/highflame-ai/zeroid/pkg/dpop
```

## Quick start

```go
import "github.com/highflame-ai/zeroid/pkg/dpop"

// Production: pass a persistent ReplayStore (e.g. zeroid's Postgres-backed
// implementation). For tests / single-instance ephemeral services, the
// in-memory store is fine.
v, err := dpop.NewVerifier(dpop.Config{
    Store: dpop.NewMemoryStore(),
})
if err != nil {
    return err
}

// On every incoming request that carries a DPoP header:
res, err := v.Validate(ctx, dpop.ValidateRequest{
    ProofJWT:    r.Header.Get("DPoP"),
    Method:      r.Method,
    URL:         "https://api.example.com" + r.URL.Path,
    AccessToken: bearerFromHeader(r),  // optional; required for ath check
    Body:        body,                  // optional; enables bh check
})
if err != nil {
    var de *dpop.Error
    if errors.As(err, &de) {
        // de.Code is one of the stable Code* constants — map to RFC 9449
        // invalid_dpop_proof + WWW-Authenticate as appropriate.
    }
    return err
}
// res.Thumbprint is the RFC 7638 JWK thumbprint. Bind it to cnf.jkt on any
// access token you issue, or compare it to cnf.jkt on a token you accept.
```

## Validating a proof against an existing access token's `cnf.jkt`

```go
res, err := v.ValidateBoundToToken(ctx, dpop.ValidateRequest{
    ProofJWT: r.Header.Get("DPoP"),
    Method:   r.Method,
    URL:      requestURL(r),
}, accessTokenClaims.CNF.JKT)
```

`ValidateBoundToToken` runs the full validation pipeline AND requires the proof's thumbprint to equal the access token's bound thumbprint. Without this, a stolen access token could be paired with a proof signed by a *different* key.

## Algorithm policy

Asymmetric signing only:

- `ES256` `ES384` `ES512` (ECDSA)
- `EdDSA` (Ed25519 / Ed448)
- `RS256` `RS384` `RS512` (RSA-PKCS1)
- `PS256` `PS384` `PS512` (RSA-PSS)

Rejected, unconditionally:

- `none`
- `HS256` `HS384` `HS512` (HMAC — would enable algorithm-confusion attacks where the server's public key bytes are used as the symmetric secret)
- Any unknown alg

The allow-list is enforced **before** any cryptographic work — `parseAndVerify` rejects the proof at header parse time.

## Body-hash extension (`bh`)

When `ValidateRequest.Body` is non-nil AND the proof carries a `bh` claim, the bytes are verified against `base64url(SHA-256(body))`. This binds the proof to a specific request payload, defeating replay of a proof against a different body.

Two modes:

- **Default** — `bh` is optional. If present on the proof, it's checked. If absent, no body validation runs.
- **`RequireBodyHash()` option** — body-bearing requests MUST present a proof with `bh`, or validation fails with `ErrBodyHashRequired`. Recommended for inline gateways and guardrails.

```go
v, _ := dpop.NewVerifier(cfg, dpop.RequireBodyHash())
```

## Replay store

RFC 9449 §11.1 requires that a proof's `jti` be honored at most once within the freshness window. This package delegates persistence to a `ReplayStore` interface so applications can plug in Postgres, Redis, DynamoDB, or whatever fits their topology.

Two reference implementations ship in this package:

| Store | Use when |
|---|---|
| `MemoryStore` | Tests, single-instance dev/staging, ephemeral services |
| `NullStore` | Tests focused on non-replay validation only; benchmarks |

Production multi-replica deployments must provide a persistent, atomic store. ZeroID's main module ships a Postgres-backed `ReplayStore`; importing it doesn't require importing this package's interface separately — they compose at the type level.

**Implementer's contract**: `Insert` must be atomic — concurrent calls for the same JTI must result in exactly one `nil` return; every other must return `ErrReplay`. A non-atomic implementation (read, then write) is a TOCTOU bug that defeats the replay defense.

## Validation pipeline

```
1. parseAndVerify          (proof.go)
   - Reject empty proof
   - Parse compact JWS
   - typ must be "dpop+jwt"
   - alg must be in allow-list
   - jwk must be present, public-only, match alg
   - Verify signature against embedded jwk
   - Parse claims; jti, htm, htu, iat required
   - Compute RFC 7638 thumbprint
2. htm match (case-insensitive)
3. htu match (after Verifier.urlNormalize — default strips query + fragment)
4. iat in [now - maxAge, now + clockSkew]
5. ath match  (if ValidateRequest.AccessToken non-empty)
6. bh  match  (if ValidateRequest.Body non-nil; required if RequireBodyHash)
7. ReplayStore.Insert(jti, expires_at)  ← atomic; LAST because it commits state
```

The order is deliberate: cheap checks first, atomic store insert last. Earlier failures must not poison the replay store.

## Error model

Validate returns `*dpop.Error` on every validation failure. Each Error carries:

- `Code` — stable string identifier (see `Code*` constants); part of the public contract
- `Message` — human-readable diagnostic, safe to log
- Wrapped `cause` — `errors.Unwrap` accessible for inspection

```go
var de *dpop.Error
if errors.As(err, &de) {
    switch de.Code {
    case dpop.CodeReplay:
        // 401 invalid_dpop_proof; include error_description="dpop_replay_detected"
    case dpop.CodeStorageFailure:
        // 503 — replay store is down, not the client's fault
    default:
        // 401 invalid_dpop_proof; include de.Code in error_description
    }
}

// IsClientFault returns true iff the error maps to a 4xx (everything except CodeStorageFailure).
if dpop.IsClientFault(err) {
    w.WriteHeader(http.StatusUnauthorized)
    w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
}
```

## Tunables

| Option | Default | Notes |
|---|---|---|
| `WithMaxAge(d)` | 60s | Max acceptable proof age (`now - iat`). RFC 9449 §4.3. |
| `WithClockSkew(d)` | 5s | Symmetric clock tolerance. `clockSkew * 2 <= maxAge` enforced at construction. |
| `WithNow(fn)` | `time.Now` | Inject a clock. Tests only. |
| `RequireBodyHash()` | off | Strict `bh` enforcement for body-bearing requests. |
| `WithLogger(l)` | nop | zerolog for structured validation events. |
| `WithURLNormalizer(fn)` | strip query + fragment | Override for reverse-proxy / path-rewrite topologies. |

## References

- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) — JSON Web Key (JWK) Thumbprint
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) — OAuth 2.0 Token Exchange (`cnf` semantics)
- The `bh` body-hash proof claim is a ZeroID extension — no RFC or IETF draft of its own. For standards-track request-body integrity, see [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) (HTTP Message Signatures) over a signed [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) `Content-Digest`.

## License

Apache 2.0 (see repository root).
