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

Trusted issuers come from the static `external_issuers` list below
(`federation.issuer_store: config`, standalone) or from per-account rows
managed through the admin API (`federation.issuer_store: db`). With rows the
tenant, the agent and the person are derived rather than requested; see
[external-issuers.md](external-issuers.md). This page describes the static
list.

### Request shape

```
POST /oauth2/token
  grant_type           = urn:ietf:params:oauth:grant-type:token-exchange
  subject_token        = <upstream IdP's ID token>
  subject_token_type   = urn:ietf:params:oauth:token-type:id_token
  account_id           = <tenant>
  project_id           = <tenant>
  scope                = <optional>
  + private_key_jwt client authentication as the ID token's relying party
```

`application_id` is optional. When present it must resolve to an active
identity in the caller's tenant — same IDOR guard the broker path uses.

The redeeming client must be the ID token's relying party (its `client_id` in
`aud`, and equal to `azp` when present) and must authenticate with
`private_key_jwt`; a client secret is refused (ADR 0042 D3a). The subject
token must be positively an ID token: `iss`, `sub`, `aud`, `exp` and `iat`
present, and no `scp`, `scope` or `typ` of `at+jwt`. Workload subjects (Entra
`idtyp=app`, Kubernetes service accounts, SPIFFE IDs) are refused, and an entry
with `kind: workload` is not accepted on this grant.

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
    allowed_accounts: ["acct-prod"] # REQUIRED, non-empty; an empty list is refused at startup
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

## Enterprise-Managed Authorization (ID-JAG)

The same `external_issuers` entries also back the MCP Enterprise-Managed
Authorization profile (draft-ietf-oauth-identity-assertion-authz-grant). The
client redeems an Identity Assertion JWT Authorization Grant that its
enterprise IdP issued with `aud` = ZeroID's issuer.

### Request shape

```
POST /oauth2/token
  grant_type  = urn:ietf:params:oauth:grant-type:jwt-bearer
  assertion   = <ID-JAG, JWS typ oauth-id-jag+jwt>
  + client authentication as registered (client_secret_basic / _post, or
    private_key_jwt with client_assertion + client_assertion_type)
  resource    = <optional; narrows the ID-JAG's resource claim>
  application_id = <optional>
```

This is the request draft §4.4 and the MCP extension §5 define. It carries
**no `account_id` or `project_id`**, and none is needed.

### How the tenant is derived

With issuer rows, the agent is the ID-JAG's `act.sub` mapped through a binding
and the tenant is that agent's ([external-issuers.md](external-issuers.md)).
With a static issuer, the tenant is derived from server-side facts and never
chosen by the caller:

- the **account** must be one of the issuer's `allowed_accounts`, and
- the **account and project** come from the authenticated client's
  registration: the identity its `identity_id` links to.

So a client that redeems ID-JAGs must be created with `identity_id` set to an
identity in the tenant its tokens belong to. A client that links no identity,
or links one outside the issuer's `allowed_accounts`, or one that is not active,
is refused with `invalid_grant`. An issuer with several `allowed_accounts` never
lets the request pick one.

`account_id` and `project_id` are still accepted for compatibility, but they
are only checked: when present, each must equal the derived value, otherwise
the request is refused with `invalid_grant`.

The ID-JAG's `client_id` claim must equal the authenticated client, and the
grant is single-use (`jti`).

### Client ID Metadata Document clients

A client that is not pre-registered may use its Client ID Metadata Document URL
as `client_id` (MCP Enterprise-Managed Authorization §5). When `cimd.enabled`
is on, the grant resolves such a client from its document, after the registry
(a registry row for the URL always wins, and a deactivated one still blocks
it). The document must:

- declare `token_endpoint_auth_method: private_key_jwt` and publish its key
  (`jwks` or `jwks_uri`). The client authenticates with an RFC 7523 §2.2
  `client_assertion`, and `none` is refused.
- list `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types`. If it
  lists `urn:ietf:params:oauth:grant-profile:id-jag` in
  `authorization_grant_profiles_supported`, it must also list
  `urn:ietf:params:oauth:grant-type:token-exchange` (draft §8).

**On a static issuer such a client cannot redeem.** Its tenant has to come
from an identity it is bound to (ADR 0042 D6), and static issuers have no
bindings, so a CIMD client that passes every check above is refused with
`invalid_grant`. The request's `account_id`/`project_id` never supply the
tenant. With a static issuer, the way to use a Client Identifier URL on this
grant is to pre-register it (CIMD §7.2): create an OAuth client whose
`client_id` is the URL, with `private_key_jwt`, its key, and an `identity_id`
in the right tenant. With issuer rows the agent and its tenant come from a binding on the ID-JAG's `act.sub`, which serves a CIMD client too
([external-issuers.md](external-issuers.md#p1b-id-jag)).

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
