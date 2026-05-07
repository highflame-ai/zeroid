# Attestation

> Cryptographic proof that an identity actually runs in the environment it claims — used to elevate trust before issuing a credential.

Until PR #93 the attestation path was a stub: any submitted proof flipped the identity's `is_verified` flag and promoted its trust level. This document is the reference for the replacement — a pluggable verifier framework with per-tenant policy, fail-closed by default, and the OIDC verifier as the first implementation.

---

## Overview

An **attestation** is a piece of proof material an identity submits to ZeroID claiming "I am the workload I say I am, running where I say I run." On successful verification, ZeroID:

1. Promotes the identity's `trust_level` (software/platform → `verified_third_party`, hardware → `first_party`).
2. Issues a bootstrap credential the workload uses for subsequent flows.
3. Records the verified subject, issuer, and expiry on the attestation row for audit.

The framework is **fail-closed**: missing verifier, missing tenant policy, or a verifier-side rejection all leave the identity un-promoted and no credential issued.

### Supported proof types

| Proof type | Verifier | Status |
|---|---|---|
| `oidc_token` | OIDC verifier (this PR) | Production-ready |
| `image_hash` | Dev stub | Stub-only — real verifier pending |
| `tpm` | Dev stub | Stub-only — real verifier pending |

The dev stub accepts any proof for `image_hash` / `tpm` so demo flows that submit those keep working until real verifiers land. It is currently **on by default** during the rollout (see [Operator runbook](#operator-runbook)). The OIDC verifier runs fail-closed regardless.

---

## Architecture

Two types in `internal/attestation/` collaborate:

```
                 ┌──────────────────────┐
                 │  AttestationService  │
                 │  (internal/service)  │
                 └──────────┬───────────┘
                            │ verify(record, accountID, projectID)
                            ▼
        ┌───────────────────────────────────────────────┐
        │  internal/attestation/                        │
        │                                               │
        │   ┌──────────────┐    ┌──────────────────┐    │
        │   │   Registry   │    │  PolicyService   │    │
        │   │              │    │                  │    │
        │   │  ProofType → │    │  per-tenant      │    │
        │   │  Verifier    │◄───│  config + write- │    │
        │   │              │    │  time gate       │    │
        │   └──────┬───────┘    └─────────┬────────┘    │
        │          │                      │             │
        │          ▼                      ▼             │
        │   ┌──────────────┐    ┌──────────────────┐    │
        │   │ OIDCVerifier │    │ DevStubVerifier  │    │
        │   └──────────────┘    └──────────────────┘    │
        └───────────────────────────────────────────────┘
```

- **`Registry`** maps `domain.ProofType → Verifier`. Built at server startup, read-only at request time. Verifiers are wired via `Register(v)` in `server.go`.
- **`Verifier` interface** — one implementation per proof type:
  ```go
  type Verifier interface {
      ProofType() domain.ProofType
      Verify(ctx context.Context, record *domain.AttestationRecord, policyConfig []byte) (*Result, error)
  }
  ```
- **`PolicyService`** manages per-tenant `AttestationPolicy` rows. It is co-located with the registry because the policy is read on every verify call, and because `UpsertPolicy` uses the registry as a write-time gate: a policy cannot be created for a proof type that has no verifier wired in this deployment.

### Verify flow

```
client submits proof          ZeroID admin API
       │                              │
       │ POST /attestation/submit     │
       ├─────────────────────────────►│
       │                              │ store AttestationRecord
       │                              │ (is_verified=false)
       │                              │
       │ POST /attestation/verify     │
       ├─────────────────────────────►│
       │                              │
       │            ┌─────────────────┤
       │            │ AttestationService.VerifyAttestation
       │            ▼
       │  1. fail-closed: re-verify guard, registry.Get(),
       │     policySvc.GetPolicy() — any miss → 400 reject
       │  2. verifier.Verify(record, policy.Config)
       │  3. credentialSvc.IssueCredential(...)        ← credential first
       │  4. identitySvc.UpdateIdentity(trust=verified)← then promote
       │  5. repo.Update(record + verified flags)     ← then commit
       │            │
       │            ▼
       │   200 with token + credential + verified record
       ◄──────────────────────────────┤
```

Write ordering is deliberate: credential issuance is the most-likely failure point, so it runs first; promotion and record update run after. A failure between steps 4 and 5 would leave trust promoted with the record unmarked — the re-verify guard (`ErrAttestationAlreadyVerified`) prevents a retry from minting a second credential. The full fix for that narrow window is tracked in [issue #98](https://github.com/highflame-ai/zeroid/issues/98).

---

## OIDC verifier

The OIDC verifier accepts JWTs from upstream OIDC providers (GitHub Actions, GCP Workload Identity, Kubernetes projected SA tokens, AWS IAM OIDC, etc.) without per-provider code. Every major agent runtime ships an OIDC token issuer, so this one verifier covers most realistic deployment shapes.

### Verification steps

1. **Parse JWT header insecurely** to read the `iss` claim. No signature check yet.
2. **Match `iss` against the tenant's allowlist** (`OIDCPolicyConfig.Issuers`). Unknown issuers are rejected here — no JWKS fetch, no network call.
3. **Resolve JWKS** for the matched issuer. Fetched via OIDC discovery (`/.well-known/openid-configuration` → `jwks_uri`), cached per-issuer for 1 hour. The discovery doc's `issuer` field is verified to match the fetch URL (RFC 8414 §3.3) so a DNS or MITM attacker can't redirect `jwks_uri`.
4. **Verify signature + standard time claims** (`exp`, `iat`, `nbf`) with 30s clock skew tolerance. The cached key set's `kid` must match the token's `kid`.
5. **Audience check** — if `Audiences` is configured, the JWT's `aud` claim must contain at least one configured value.
6. **Required-claim check** — for each `(key, value)` in `RequiredClaims`, the token must contain `key` with the exact string value.

On success the verifier returns the JWT's `sub`, `iss`, `exp`, and the full claim map. Those propagate to the `AttestationRecord` for audit.

### Security properties

- **Issuer allowlist is the trust anchor.** A perfectly-signed JWT from an issuer not in the policy is rejected before any network call to that issuer's discovery endpoint.
- **HTTPS required for non-loopback issuers.** OIDC discovery is unauthenticated — over plain HTTP a network attacker could substitute their own keys. `https://` is required at policy write time. Loopback addresses (`localhost`, `127.0.0.1`, `::1`) are exempted for local-dev and `httptest`-based integration tests.
- **Discovery doc body is capped at 1 MiB.** A compromised issuer can't OOM the verifier by streaming an arbitrarily large response.
- **JWKS fetched from the issuer's own discovery doc, not policy config.** Operators don't paste public keys into ZeroID — the issuer publishes them, ZeroID fetches them, and the discovery `issuer` field must match the URL we fetched from.
- **Trailing-slash normalisation on `iss` matching.** `https://accounts.google.com` and `https://accounts.google.com/` are treated as the same issuer; mild config typos don't lock clients out.

---

## Configuring an `AttestationPolicy`

A policy ties a tenant + proof type to the rules a submitted proof must satisfy. One policy per `(account_id, project_id, proof_type)`.

### Endpoint

```
PUT /api/v1/attestation-policies
Content-Type: application/json

{
  "proof_type": "oidc_token",
  "config": { ... per-proof-type schema ... },
  "is_active": true
}
```

`PUT` is upsert. `is_active=false` soft-disables. Two concurrent PUTs for the same key are race-safe (atomic `INSERT … ON CONFLICT`).

### `OIDCPolicyConfig` schema

```jsonc
{
  "issuers": [
    {
      "url": "https://token.actions.githubusercontent.com",
      "audiences": ["https://github.com/myorg"],          // optional
      "required_claims": {                                  // optional
        "repository": "myorg/myrepo",
        "ref": "refs/heads/main"
      }
    }
  ]
}
```

- `issuers` — at least one entry; the JWT's `iss` claim must match one (after trailing-slash normalisation).
- `audiences` — if non-empty, JWT's `aud` claim must contain at least one of these. If empty, no audience check.
- `required_claims` — exact string match on each key. Use this to bind tokens to a specific workload (the GitHub Actions example bound to a single repo + branch is the canonical pattern).

### Worked example: GitHub Actions OIDC

A workflow in `myorg/myrepo` on `main` is allowed to attest. Anything else is rejected.

```bash
curl -X PUT https://zeroid.example.com/api/v1/attestation-policies \
  -H "Content-Type: application/json" \
  -H "X-Account-ID: acct_123" -H "X-Project-ID: proj_456" \
  -d '{
    "proof_type": "oidc_token",
    "config": {
      "issuers": [{
        "url": "https://token.actions.githubusercontent.com",
        "audiences": ["https://github.com/myorg"],
        "required_claims": {
          "repository": "myorg/myrepo",
          "ref": "refs/heads/main"
        }
      }]
    }
  }'
```

In the workflow:

```yaml
- uses: actions/github-script@v7
  with:
    script: |
      const token = await core.getIDToken('https://github.com/myorg');
      // POST to /api/v1/attestation/submit with proof_type=oidc_token, proof_value=token
      // then POST /api/v1/attestation/verify with the returned record id
```

### Worked example: GCP Workload Identity Federation

```jsonc
{
  "issuers": [{
    "url": "https://accounts.google.com",
    "audiences": ["//iam.googleapis.com/projects/.../locations/global/workloadIdentityPools/.../providers/zeroid"],
    "required_claims": {
      "google.compute_engine.project_id": "my-prod-project",
      "google.compute_engine.zone":       "us-central1-a"
    }
  }]
}
```

### Worked example: Kubernetes projected service-account tokens

The cluster's API-server JWKS is published at `https://<api-server>/openid/v1/jwks`. The cluster issuer (whatever `kubectl get --raw '/.well-known/openid-configuration'` returns as `issuer`) goes in the policy:

```jsonc
{
  "issuers": [{
    "url": "https://kubernetes.default.svc.cluster.local",
    "audiences": ["zeroid"],
    "required_claims": {
      "kubernetes.io/serviceaccount/namespace": "production",
      "kubernetes.io/serviceaccount/service-account.name": "agent-runner"
    }
  }]
}
```

Each pod requests a token with `aud=zeroid` via projected service-account volume; the workload submits that token as the attestation proof.

---

## Operator runbook

### Configuration

| YAML key | Env var | Default | Effect |
|---|---|---|---|
| `attestation.allow_unsafe_dev_stub` | `ZEROID_ALLOW_UNSAFE_DEV_STUB` | `true` (transitional) | (1) Registers the dev stub for `image_hash` and `tpm`. (2) Enables the missing-policy bypass on `/verify` for **all** registered proof types — see [Permissive bypass](#permissive-bypass-during-the-rollout-transitional). Prints a startup WARN whenever true; per-request WARN whenever the bypass fires. |

When the stub is active, the server logs:

```
WARN ATTESTATION: AllowUnsafeDevStub is enabled — any submitted proof will verify. DO NOT enable in production.
```

The stub **only** covers proof types whose real verifier hasn't shipped (`image_hash`, `tpm`). The OIDC verifier is wired regardless of this flag and runs fail-closed.

### Why is the default `true` today?

Until real `image_hash` and `tpm` verifiers ship, fail-closing those proof types would break existing demo flows that submit them. The transitional default keeps current customer integrations working without forcing them to add config. Deployments that don't use `image_hash` or `tpm` should set `ZEROID_ALLOW_UNSAFE_DEV_STUB=false`. Once the real verifiers land, the default flips back to `false`.

### Fail-closed contract

`/attestation/verify` rejects with HTTP 400 (and `ErrAttestationRejected` underneath) when:

- The proof type has no verifier registered in this deployment.
- The tenant has no active `AttestationPolicy` for the proof type **and** the permissive bypass is disabled (see below).
- The verifier itself rejects (bad signature, untrusted issuer, claim mismatch, etc.).

Re-verifying an already-verified record returns 409 `ErrAttestationAlreadyVerified`. This guards against retry-driven duplicate credential issuance.

### Permissive bypass during the rollout (transitional)

When `cfg.Attestation.AllowUnsafeDevStub=true` (the current default — see [Why is the default `true` today?](#why-is-the-default-true-today)), the missing-policy gate is bypassed for **any** proof type whose verifier is registered:

- The registered verifier is **not** invoked (the OIDC verifier requires a non-empty policy config to mean anything; the dev stub doesn't read config).
- The service synthesises a stub-shape `Result` so the rest of the pipeline (issue credential → promote trust → mark record verified) runs unchanged.
- A `WARN`-level log fires per request, including `account_id`, `project_id`, `proof_type`, `attestation_id` and `identity_id` — operators use this to find tenants that still need a real policy before the flag is flipped off.

The verifier-must-be-registered gate stays strict in this mode: a typo'd or unsupported proof type still rejects, so the bypass can't paper over schema bugs.

Net effect on existing tenants:

| Tenant state | Strict mode (`flag=false`) | Permissive mode (`flag=true`, current default) |
|---|---|---|
| Submits any proof, no policy | ❌ 400 "no attestation policy configured" | ✅ 200, WARN logged |
| Submits `oidc_token`, has policy | ✅ if real OIDC verification passes | ✅ if real OIDC verification passes (bypass does not apply when policy is present) |
| Submits proof with no registered verifier | ❌ 400 "no verifier registered" | ❌ 400 "no verifier registered" (bypass does not skip this gate) |

The bypass disappears the day `AllowUnsafeDevStub` is flipped to `false`.

### Concurrent-write safety

`UpsertPolicy` uses `INSERT … ON CONFLICT DO UPDATE` so two simultaneous admin PUTs for the same `(tenant, proof_type)` race only on the row lock. Neither produces a 500. `TestAttestationPolicyUpsertIsConcurrencySafe` (8-way parallel) covers this.

### Rate limiting / DoS posture

- OIDC discovery + JWKS fetches are cached per-issuer for 1 hour.
- The discovery response body is capped at 1 MiB.
- Policy validation runs at write time, so misconfigurations (missing issuer list, malformed URL, `http://` issuer) surface as 400 immediately rather than at /verify time.

---

## Adding a new verifier

To add a verifier for a new proof type — e.g. an `image_hash` verifier that compares container digests against a per-tenant allowlist:

1. **Implement the `Verifier` interface** in `internal/attestation/<proof_type>.go`:

   ```go
   type ImageHashVerifier struct{ /* ... */ }
   func (v *ImageHashVerifier) ProofType() domain.ProofType { return domain.ProofTypeImageHash }
   func (v *ImageHashVerifier) Verify(ctx context.Context, record *domain.AttestationRecord, policyConfig []byte) (*Result, error) {
       // 1. Parse policyConfig into the typed struct for image_hash.
       // 2. Look up record.ProofValue against the policy's allowlist.
       // 3. Return Result{Subject: digest, ExpiresAt: nil, Claims: ...} or an error.
   }
   ```

2. **Define the typed config** in `domain/attestation_policy.go`:

   ```go
   type ImageHashPolicyConfig struct {
       Allowlist []ImageHashEntry `json:"allowlist"`
   }
   ```

3. **Add the typed config validator branch** in `internal/attestation/policy.go::validatePolicyConfig`:

   ```go
   case domain.ProofTypeImageHash:
       var cfg domain.ImageHashPolicyConfig
       if err := json.Unmarshal(rawCfg, &cfg); err != nil { ... }
       if len(cfg.Allowlist) == 0 { ... }
       // typed validation
   ```

4. **Register in `server.go`**:

   ```go
   attestationVerifiers.Register(attestation.NewImageHashVerifier(/* deps */))
   ```

5. **Add integration tests** in `tests/integration/attestation_<proof_type>_test.go` covering happy path, bad input, write-time policy validation, fail-closed without policy.

The dev stub for that proof type can stay registered alongside (last-write wins on `Register`) until you're confident the real verifier covers all flows; then drop the stub from `server.go`.

---

## Migration notes

### Schema (`migrations/014_attestation_policies.up.sql`)

Adds `attestation_policies` with a unique constraint on `(account_id, project_id, proof_type)` and a partial index on `is_active = TRUE` for the verify hot path.

### Behavior change for existing tenants

Before: any submitted proof verified. After: tenants must configure an `AttestationPolicy` for every proof type they want to accept. Existing demo flows submitting `oidc_token` proofs against a tenant with no policy will start receiving 400 `attestation proof rejected: no attestation policy configured`. The fix is to PUT the policy.

For `image_hash` and `tpm`, the dev stub keeps the legacy "any proof verifies" behavior alive while the real verifiers are built. See the [Operator runbook](#operator-runbook) for how to flip it off.

### Auditability

Every verification — pass or fail — leaves a row trail:

- `AttestationRecord.is_verified` flips only on success.
- `verified_at`, `expires_at`, `credential_id` are populated atomically with the success state.
- `proof_hash` (sha256 of the original `proof_value`) is recorded at submit time so audit can detect proof reuse without storing the raw token.

---

## References

- RFC 7519 — JSON Web Token
- RFC 7517 — JSON Web Key
- RFC 8414 — OAuth 2.0 Authorization Server Metadata (the §3.3 issuer-pinning rule the verifier follows)
- OpenID Connect Discovery 1.0 — `.well-known/openid-configuration` shape
- GitHub Actions OIDC: <https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect>
- GCP Workload Identity Federation: <https://cloud.google.com/iam/docs/workload-identity-federation>
- Kubernetes projected service-account tokens: <https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection>

## Source map

| Concern | File |
|---|---|
| `Verifier` interface + `Registry` | `internal/attestation/verifier.go` |
| OIDC verifier | `internal/attestation/oidc.go` |
| Dev stub | `internal/attestation/stub.go` |
| Policy service + write-time gate | `internal/attestation/policy.go` |
| Policy repository | `internal/store/postgres/attestation_policy.go` |
| Verify orchestration | `internal/service/attestation.go` |
| HTTP handlers | `internal/handler/attestation.go`, `internal/handler/attestation_policy.go` |
| Domain types | `domain/attestation.go`, `domain/attestation_policy.go` |
| Schema | `migrations/014_attestation_policies.up.sql` |
| Tests | `tests/integration/attestation_oidc_test.go` |
