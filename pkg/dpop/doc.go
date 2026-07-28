// Package dpop implements RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession
// (DPoP) — plus the body-hash (bh) extension claim used by Highflame's agent
// hook flow.
//
// DPoP binds an OAuth access token to a public key held by the client. The
// client proves possession of the matching private key by signing a short-lived
// JWT (the "proof") for each request. A stolen access token alone is useless —
// an attacker also needs the private key.
//
// # Quick start
//
//	v, err := dpop.NewVerifier(dpop.Config{
//	    Store: dpop.NewMemoryStore(),  // production: pass a persistent store
//	})
//	if err != nil { return err }
//
//	res, err := v.Validate(ctx, dpop.ValidateRequest{
//	    ProofJWT:    r.Header.Get("DPoP"),
//	    Method:      r.Method,
//	    URL:         "https://api.example.com" + r.URL.Path,
//	    AccessToken: extractBearer(r),  // optional; required for ath check
//	    Body:        bodyBytes,         // optional; enables bh check
//	})
//	if err != nil {
//	    // err exposes a stable Code via *dpop.Error — map to RFC 9449
//	    // invalid_dpop_proof + WWW-Authenticate as appropriate.
//	    return err
//	}
//	// res.Thumbprint is the RFC 7638 JWK thumbprint — bind to cnf.jkt of
//	// any access token issued or accepted on this request.
//
// # Algorithm policy
//
// Accepts asymmetric signing algorithms only: ES256/384/512, EdDSA, RS256/384/512,
// PS256/384/512. Rejects alg=none, HS* (HMAC), and any unknown alg — preventing
// algorithm-confusion attacks where a client presents an HMAC-signed proof with
// the server's public key bytes used as the symmetric secret.
//
// # Body-hash extension (bh)
//
// RFC 9449 §4.2 reserves the bh claim for body-hash binding. This package
// supports it as an optional check: when ValidateRequest.Body is non-nil AND
// the proof carries a bh claim, the bytes are verified against the proof's
// bh value (base64url(SHA-256(body))). Set RequireBodyHash on the Verifier to
// reject proofs without bh on body-bearing requests (recommended for
// gateways / inline guardrails).
//
// # Replay prevention
//
// RFC 9449 §11.1 requires the server to refuse proof reuse within the freshness
// window (default 60s; tunable via Config.MaxAge). This package delegates the
// (jti, expires_at) ledger to a pluggable ReplayStore. Two implementations
// ship in this package:
//
//   - MemoryStore — in-memory, ttl-pruned. For tests, local dev, ephemeral
//     services. Loses state on restart.
//   - NullStore — accepts every jti without recording. NEVER use in production;
//     provided only for opt-out testing.
//
// Production deployments should provide a persistent ReplayStore (e.g. the
// Postgres-backed implementation that ships in zeroid's main module).
//
// # Token binding (cnf.jkt + ath)
//
// When an access token is presented alongside a proof, two checks fire:
//
//  1. ath — the proof's ath claim must equal base64url(SHA-256(access-token)).
//     This binds the proof to a specific token.
//  2. cnf.jkt — when the caller passes the access token's cnf.jkt confirmation
//     claim to ValidateBoundToToken, the proof's JWK thumbprint must match.
//     This binds the proof to a specific key.
//
// Together these prevent both token replay (attacker has proof but not token)
// and proof replay (attacker has token but not key).
//
// # References
//
//   - RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
//   - RFC 7638 — JSON Web Key (JWK) Thumbprint
//   - RFC 8693 — OAuth 2.0 Token Exchange (cnf claim semantics)
//   - draft-ietf-oauth-dpop-bh — body-hash extension claim (community draft)
package dpop
