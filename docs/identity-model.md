# ZeroID identity model — composing claims from upstream IdPs

ZeroID is an identity layer for autonomous agents and human users. When the
calling principal is a human authenticated by an external OIDC provider
(Okta, Entra ID, Auth0, Google Workspace, custom OIDC), there are two paths
for getting that identity into a ZeroID-issued token:

1. **Direct OIDC IdP federation** — the spec-aligned default. ZeroID itself
   verifies the upstream IdP's ID token signature.
2. **Trusted-service broker** — a fallback for narrow operational cases. A
   deployer-controlled service does the IdP-side verification and tells
   ZeroID who the user is.

**For new deployments, default to direct federation.** The broker path
remains available but is strictly lossier: it cannot answer the question
"which IdP authenticated this user?" from the issued token alone.

## Direct OIDC IdP federation (preferred)

### What it is

ZeroID accepts an upstream OIDC ID token at `/oauth2/token` via RFC 8693
token exchange and verifies it directly against the issuer's published JWKS
before minting a ZeroID-signed token.

Standards anchor:

- **RFC 8693 §3** defines `subject_token_type =
urn:ietf:params:oauth:token-type:id_token` for exactly this case.
- **RFC 9068** specifies `acr` / `amr` / `auth_time` as
  authentication-context claims. These are only meaningful when the issuer
  that authenticated the subject is the one that signed the claims.
- **NIST SP 800-63C §4.1** requires federation assertions to name the IdP
  that authenticated the subject — not an aggregator or relay.

### Request shape

```
POST /oauth2/token
  grant_type           = urn:ietf:params:oauth:grant-type:token-exchange
  subject_token        = <upstream IdP's ID token>
  subject_token_type   = urn:ietf:params:oauth:token-type:id_token
  account_id           = <tenant>
  project_id           = <tenant>
  scope                = <optional>
```

`application_id` is optional. When present it must resolve to an active
identity in the caller's tenant — same IDOR guard the broker path uses.

### Issued-token claim shape

| Claim            | Source                                              | Purpose                                                    |
| ---------------- | --------------------------------------------------- | ---------------------------------------------------------- |
| `iss`            | ZeroID's configured issuer                          | Standard.                                                  |
| `sub`            | Upstream → `claim_mapping.user_id`                  | The principal — the stable subject identifier downstream services check. (The token-endpoint JSON response also echoes it as `user_id`; the JWT itself carries it only as `sub`.) |
| `user_id_iss`    | Upstream `iss`                                      | **IdP-granular provenance** — the headline addition.       |
| `user_email`     | Upstream → `claim_mapping.email`                    | Optional.                                                  |
| `user_name`      | Upstream → `claim_mapping.name`                     | Optional.                                                  |
| `auth_time`      | Upstream `auth_time` (when configured to propagate) | RFC 9068 — copied through, never synthesized.              |
| `acr`            | Upstream `acr` (when configured to propagate)       | RFC 9068.                                                  |
| `amr`            | Upstream `amr` (when configured to propagate)       | RFC 9068.                                                  |
| `token_exchange` | Constant `external_id_token`                        | Distinguishes from the broker path's `external_principal`. |

ZeroID never default-fills `auth_time` / `acr` / `amr`. If the upstream
omitted them, they are absent from the issued token. Synthesizing them
would defeat the entire point of carrying authentication-context claims.

### Configuration

```yaml
external_issuers:
  - issuer: "https://auth.example.okta.com"
    jwks_uri: "https://auth.example.okta.com/.well-known/jwks.json"
    audience: "https://zeroid.example.com"
    algorithms: ["RS256", "ES256"] # default
    max_token_age: 10m # iat must not exceed this
    jwks_cache_ttl: 5m # JWKS refresh interval
    claim_mapping:
      user_id: sub # required
      email: email # optional
    allowed_accounts: ["acct-prod"] # empty = any tenant
    propagate_claims: ["auth_time", "acr", "amr"]
```

The deployer is the trust anchor: only issuers listed here are accepted.
There is no auto-discovery, no OIDF chain, no implicit trust.

### Verification semantics

For each request:

1. The upstream `iss` is read from the subject_token (without verifying
   yet) and looked up against the configured allowlist.
2. The token's algorithm is checked against the issuer's `algorithms`
   list. Anything outside the asymmetric RS/ES/PS family is rejected
   regardless of configuration — `none` and HS-family tokens never reach
   verification.
3. `iss`, `aud`, `exp`, `nbf` are all enforced. `iat` is required and
   capped by `max_token_age` to prevent replay of old tokens.
4. The signature is verified against the cached JWKS. On unknown `kid` the
   JWKS is refreshed once and verification is retried — covers upstream
   key rotation without a server restart.
5. Claim mapping extracts `user_id` (required), `email`, `name`. Missing
   `user_id` is `invalid_grant`.
6. `account_id` is checked against the issuer's `allowed_accounts` list.
7. ZeroID issues an RS256 token (15-minute TTL) carrying the provenance
   claims above.

`TrustedServiceValidator` is not consulted on this path — the JWKS
signature check, issuer allowlist, and audience binding are the trust
proof.

## Trusted-service broker (fallback)

### What it is

A deployer-controlled service authenticates the upstream user (perhaps
because it already does OIDC for many backend services), then calls ZeroID
with pre-validated user claims. ZeroID validates the **caller** via
`TrustedServiceValidator` but does **not** re-verify the upstream JWT.

### When to use it

| Constraint                                                   | Use the broker                          |
| ------------------------------------------------------------ | --------------------------------------- |
| Existing gateway already does OIDC for many services         | ✅ avoids duplication                   |
| Complex internal claim-normalization logic                   | ✅ keeps it out of ZeroID               |
| Air-gapped / egress-restricted ZeroID                        | ✅ broker does the IdP call             |
| Per-IdP provenance required (finance, healthcare, regulated) | ❌ insufficient — use direct federation |

### Request shape

```
POST /oauth2/token
  grant_type    = urn:ietf:params:oauth:grant-type:token-exchange
  subject_token = <pre-validated jwt>      # NOT re-verified by ZeroID
  account_id    = <tenant>
  project_id    = <tenant>
  user_id       = <external user ID>
```

`subject_token_type` is left blank (or anything other than `id_token`).
The broker path is the default when `actor_token` is absent and the
subject token type is not `id_token`.

### Issued-token claim shape

The broker path emits `trusted_by: <service-name>` instead of
`user_id_iss`. Consumers can see _which service vouched_ but not _which
IdP authenticated_. For regulated deployments where per-IdP provenance is
required, this is insufficient — direct federation is the answer.

## Choosing between paths

If you can use direct federation, do. The broker path remains for the
narrow operational cases above; for everything else direct federation is
simpler, more spec-aligned, and carries strictly more information forward
to downstream consumers.
