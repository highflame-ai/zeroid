# ZeroID OAuth 2.0 / OIDC Extensions for Agent Identity

| | |
|---|---|
| **Document** | `draft-highflame-zeroid-oauth-extensions-00` |
| **Category** | Informational (implementation specification) |
| **Status** | Authoritative for the ZeroID reference implementation on `main` |
| **Published** | 2026-06-01 |
| **Source of truth** | The ZeroID Go source tree. Where this document and the code disagree, the code wins; file a bug. |

## Abstract

ZeroID is an OAuth 2.1 / OpenID Connect authorization server purpose-built for
non-human (agent) identity. To represent agents, delegation chains, and
out-of-band approval, ZeroID layers a small set of extensions on top of the
baseline IETF and OpenID specifications it implements. This document specifies
those extensions — and *only* those extensions — at the wire level: the
additional JWT claims, request parameters, URI scheme, gating rules,
event types, workload identity federation, and discovery metadata. It is the
normative reference an
independent implementer or a resource server would use to interoperate with
ZeroID without reading its source.

Baseline conformance (the parts of OAuth 2.1, RFC 8693, RFC 9449, OpenID CIBA
Core 1.0, RFC 9396, RFC 7591/7592, RFC 7662/7009, RFC 8414, and RFC 9728 that
ZeroID implements *as written*) is **out of scope** here. This document covers
the deltas only.

## Status of This Document

This is an implementation specification, not an IETF/OpenID standards-track
document. The `urn`/draft naming is a convenience for citation. None of the
extensions defined here are registered with IANA; the registry in
[Section 13](#13-claim--parameter-registry-iana-style) is informative and scoped
to ZeroID deployments.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Conventions and Terminology](#2-conventions-and-terminology)
3. [Identity Model and WIMSE URIs](#3-identity-model-and-wimse-uris)
4. [JWT Claim Extensions](#4-jwt-claim-extensions)
5. [RFC 8693 Delegation Extensions](#5-rfc-8693-delegation-extensions)
6. [CIBA Extensions](#6-ciba-extensions)
7. [DPoP Extensions](#7-dpop-extensions)
8. [Reserved-Claims Gating](#8-reserved-claims-gating)
9. [CAE / SSF Signals](#9-cae--ssf-signals)
10. [Workload Identity Federation](#10-workload-identity-federation)
11. [Discovery Metadata Extensions](#11-discovery-metadata-extensions)
12. [Security Considerations](#12-security-considerations)
13. [Claim / Parameter Registry (IANA-style)](#13-claim--parameter-registry-iana-style)
14. [References](#14-references)

---

## 1. Introduction

OAuth 2.x and OIDC authenticate a *human to a service*. They have no native
model for a credential whose holder is an autonomous agent, for one agent
delegating an attenuated subset of its authority to another, for the resulting
multi-hop chain to remain cryptographically attributable, or for an agent to
pause mid-task and obtain a human's out-of-band approval.

ZeroID exists to solve **Agent Identity**. Human identity (the domain of
OAuth/OIDC IdPs) and general workload / machine identity (the domain of
SPIFFE/SPIRE, cloud IAM, and secret managers) are separate, mature ecosystems;
ZeroID builds on their primitives — WIMSE/SPIFFE URIs, OIDC, RFC 8693 — and
federates with them rather than replacing them. What it adds is the
agent-shaped layer those baselines do not model.

Because agents do not act in isolation — they call services, applications, and
MCP servers — ZeroID also represents those non-agent principals so the wire
claims are uniform. This document calls the whole set **NHIs** (non-human
identities, Section 3.2) and reserves **agent** for the specialization that
additionally carries the agent-shaped semantics: delegation depth, the `act`
chain, an agent role, and agent metadata. NHI is the umbrella; agent is one kind
of NHI; the two are kept distinct throughout (Section 2). The extensions below
say which layer each belongs to.

ZeroID closes those gaps with the smallest possible set of extensions. The
design rule is: **extend the standard, never fork it.** Every extension is
either (a) an additional claim that standard verifiers ignore, (b) an
additional, optional request parameter, or (c) an additional discovery field. A
baseline-only
OAuth client or resource server continues to work against ZeroID; it simply
sees less.

This document enumerates each extension grouped by the baseline spec it builds
on.

## 2. Conventions and Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when,
and only when, they appear in all capitals.

This document uses the following terms:

- **NHI (Non-Human Identity)** — the umbrella category for every non-human
  principal ZeroID registers: a `service`, an `application`, an `mcp_server`,
  **or** an `agent` (the four `identity_type`s of Section 3.2). Every NHI,
  whatever its kind, gets a stable WIMSE URI (Section 3) and the core identity
  claims — `identity_type`, `trust_level`, `status`, `external_id`.
- **Agent** — the `identity_type = agent` **specialization** of an NHI. Every
  agent is an NHI; not every NHI is an agent. An agent additionally carries the
  *agent-shaped* claims a plain service or application does not: an agent
  `sub_type` (Section 3.2), the delegation semantics `delegation_depth` and the
  `act` chain (Sections 4.3, 4.4, 5), and the optional agent metadata and
  coding-agent task claims (Sections 4.2, 4.8). This document writes **NHI**
  for statements true of any non-human principal and **agent** only for the
  agent specialization; the two are not interchangeable.
- **Identity** — a persistent ZeroID record for an NHI (or, for the
  human-delegation flows, a synthesised principal). Carries a stable WIMSE URI
  (Section 3), a type, a sub-type, a trust level, and a status.
- **Credential** — an issued, signed JWT (an `issued_credentials` row).
- **Delegation tree** — the set of credentials reachable from a root credential
  by following `parent_jti` edges. Identified by `mission_id` (Section 5.4).
- **Deployer** — the operator embedding the ZeroID library/service and supplying
  its pluggable hooks (`BackchannelNotifier`, `TrustedServiceValidator`,
  `RevocationNotifier`, `ClaimsEnricher`, grant handlers).
- **Trusted service** — an internal caller that has passed the deployer's
  `TrustedServiceValidator` gate (Section 5.5).

Tenancy is universal: every identity, credential, signal, and request is scoped
to an `(account_id, project_id)` pair, surfaced as claims on every token.

## 3. Identity Model and WIMSE URIs

### 3.1 WIMSE URI scheme

Every ZeroID identity is assigned a stable, globally unique identity URI in the
SPIFFE ID syntax, used as the JWT `sub` of every credential issued to that
identity. The template is:

```
spiffe://{trust_domain}/{account_id}/{project_id}/{identity_type}/{external_id}
```

- `trust_domain` — a per-deployment configurable host label (e.g.
  `zeroid.dev`, `auth.highflame.ai`, `highflame.dev`). It is NOT derived from
  the request; it is server configuration.
- `account_id`, `project_id` — the tenant scope.
- `identity_type` — one of the values in Section 3.2.
- `external_id` — the registrant-supplied stable identifier for the principal,
  unique within `(account_id, project_id, identity_type)`.

Constraints:

- Each path segment **MUST** consist only of the characters `a-z A-Z 0-9 . - _`.
  Registration **MUST** reject any segment outside this set. Because the set
  excludes `/ ? # @ :`, a segment cannot introduce an empty segment, a query
  string, a fragment, user-info, or an embedded port. (ZeroID's implementation
  intentionally permits uppercase letters `A-Z` in path segments — more
  permissive than a strict-lowercase SPIFFE profile. The `trust_domain` is
  server configuration, not request input, and is therefore not re-validated
  per request.)
- The assembled URI **MUST NOT** exceed **2048 bytes**. Registration **MUST**
  reject a longer URI rather than persist a non-conformant subject.

A resource server parses the account/project scope back out of a `sub` by
stripping the `spiffe://{trust_domain}/` prefix and splitting the remainder into
at most four segments; segments 1 and 2 are `account_id` and `project_id`.

### 3.2 Identity classification vocabularies

`identity_type` (the `/{identity_type}/` URI segment and the `identity_type`
claim) is one of:

| Value | Meaning |
|---|---|
| `agent` | An autonomous or semi-autonomous AI agent |
| `application` | A user-facing application / OAuth client persona |
| `mcp_server` | A Model Context Protocol server |
| `service` | A backend service or internal worker |

`identity_type = agent` denotes an **Agent Identity** — the specialization that
also carries the agent-shaped claims of Sections 4–5 (an agent `sub_type`,
`delegation_depth`, the `act` chain, and the optional agent metadata / task
claims). The other three types are **non-agent NHIs**: they carry the core
identity claims and any descriptive metadata, but the agent-shaped claims are
absent or not meaningful for them. Everything in this document that is scoped to
a `sub_type` of `agent` applies to Agent Identities specifically; everything
keyed only on the WIMSE URI or the core claims applies to every NHI.

`sub_type` (the `sub_type` claim) refines the type. The defined values are:

| `sub_type` | Valid for `identity_type` |
|---|---|
| `orchestrator`, `autonomous`, `tool_agent`, `human_proxy`, `evaluator`, `code_agent` | `agent` |
| `chatbot`, `assistant`, `api_service`, `custom` | `application` |
| `llm_provider` | `service` |

`trust_level` (the `trust_level` claim), in ascending order of trust:
`unverified` → `verified_third_party` → `first_party`. Trust level is elevated
only by the attestation framework (see `docs/attestation.md`); it cannot be
self-asserted.

`status` (the `status` claim): `pending` → `active` ⇄ `suspended` →
`deactivated`. Tokens are issued only for an `active` identity; the cleanup
worker and CAE cascade move identities out of `active` fail-closed.

## 4. JWT Claim Extensions

ZeroID-issued access tokens are JWS-signed JWTs. NHI flows
(`client_credentials`, `jwt_bearer`, `token_exchange`) sign with **ES256**;
human / SDK flows (`api_key`, `authorization_code`, external-principal exchange,
CIBA) sign with **RS256**. The claims below are emitted for the relevant NHI;
the ones flagged *agent-shaped* characterise an Agent Identity
(`identity_type = agent`, Section 3.2) and are normally absent on a plain
service, application, or MCP-server NHI. The `kid` header selects the verifying key
from the JWKS; `typ` is `JWT`. Beyond the RFC 7519 registered claims, ZeroID
emits the following.

### 4.1 Tenancy and grant claims (always present)

| Claim | Type | Description |
|---|---|---|
| `account_id` | string | Tenant account scope. |
| `project_id` | string | Tenant project scope. |
| `grant_type` | string | The grant that minted this credential. Most grants serialize in short form: `client_credentials`, `jwt_bearer`, `token_exchange`, `api_key`, `authorization_code`, `refresh_token`. CIBA is the exception — its claim value is the full URN `urn:openid:params:grant-type:ciba`. (Note: on the **request** the `grant_type` parameter for `token_exchange` and `jwt_bearer` uses the full IETF URN forms, e.g. `urn:ietf:params:oauth:grant-type:token-exchange`; the **claim** uses the short form for those two. CIBA matches in both places.) |
| `mission_id` | string | Delegation-tree identifier; see Section 5.4. Always present. Opaque to consumers. |

`aud` is always present; when the request supplies no audience it defaults to
the issuer URL (JWT-SVID §3 requires `aud`).

### 4.2 Identity claims

**Core identity claims** — present on every NHI-backed credential, regardless of
kind:

| Claim | Type | Presence | Description |
|---|---|---|---|
| `external_id` | string | always (may be empty) | Registrant-assigned stable id. |
| `identity_type` | string | always | Section 3.2. |
| `sub_type` | string | always (may be empty) | Section 3.2. For an agent this is an agent role (`orchestrator`, …); for other NHIs it is that type's own sub-type or empty. |
| `trust_level` | string | always | Section 3.2. |
| `status` | string | always | Section 3.2. |
| `owner_user_id` | string | when non-empty | The user who **registered/owns** this identity. Distinct from `sub` (the principal) and from `act.sub` (the principal it acts for). |
| `name` | string | when non-empty | Human-readable identity name. |

**Agent metadata claims** — *agent-shaped*: descriptive metadata that
characterises an Agent Identity. Optional and chiefly set on agents
(`identity_type = agent`); a non-agent NHI normally omits them:

| Claim | Type | Presence | Description |
|---|---|---|---|
| `framework` | string | when non-empty | Agent framework (e.g. `langgraph`). |
| `version` | string | when non-empty | Agent / software version. |
| `publisher` | string | when non-empty | Publisher of the agent. |
| `capabilities` | JSON | when non-empty and not `[]` | Agent capability manifest, verbatim. |

The metadata claims are embedded so a resource server can make identity-aware
decisions without calling back to ZeroID. The remaining agent-shaped claims —
`delegation_depth`, the delegation `act` chain, and the coding-agent task
claims — are specified in Sections 4.3, 4.4, and 4.8.

### 4.3 Authorization-context claims

| Claim | Type | Presence | Description |
|---|---|---|---|
| `scopes` | array&lt;string&gt; | when non-empty | Granted scopes. (ZeroID emits the JSON array `scopes`, in addition to the standard space-delimited `scope` on the token *response*.) |
| `delegation_depth` | number | when &gt; 0 | Number of `token_exchange` hops from the root; see Section 5.2. Omitted (≡ 0) for a directly-issued credential. |
| `application_id` | string | when set | OAuth client / application the token was issued for (`api_key`, `authorization_code`). |
| `user_email` | string | when set | End-user email (human/external-principal/CIBA paths). |
| `user_name` | string | when set | End-user display name (same paths). |

### 4.4 Delegation actor claim (`act`)

ZeroID populates the RFC 8693 §4.1 `act` claim as a single-level object
`{"sub": "<principal>"}`, used in two mutually-exclusive ways on a given token:

1. **Agent delegation** (*agent-shaped*) — `act.sub` is the **orchestrator
   agent's WIMSE URI** (the agent that delegated). Set on `token_exchange`-issued
   tokens; this is the orchestrator → sub-agent chain of Section 5.
2. **User context** (any NHI) — `act.sub` is the **end-user id** the NHI is
   acting for. Set when an NHI acts on behalf of a human (e.g. `jwt_bearer`,
   `authorization_code`-delegated flows). This case is not agent-specific.

A token carries at most one `act`. ZeroID's `act` is a single object, not the
nested `act` chain RFC 8693 permits; the full lineage is reconstructable from
the `parent_jti` edges rather than by nesting.

### 4.5 Sender-constraint claim (`cnf.jkt`)

When the token request carries a valid DPoP proof (Section 7), ZeroID binds the
issued token to the proof key by setting:

```json
"cnf": { "jkt": "<RFC 7638 JWK SHA-256 thumbprint, base64url, no padding>" }
```

and the token **response** `token_type` becomes `DPoP` instead of `Bearer`.
`cnf` is set **only** from a server-validated proof; it can never be supplied by
a caller (Section 8).

### 4.6 Exchange-provenance claims

Set by the trusted-service external-principal exchange (Section 5.5):

| Claim | Type | Value | Description |
|---|---|---|---|
| `token_exchange` | string | `external_principal` or `ciba` | Marks a synthesised-principal token and which path minted it. |
| `trusted_by` | string | service name | The trusted internal service (from `TrustedServiceValidator`) that vouched for the external principal. Only on the `external_principal` path. |
| `role` | string | gated | Authorization role. Settable **only** on the trusted external-principal path, from a dedicated request field — never via `additional_claims`. See Section 8. |
| `privilege_scope` | array&lt;string&gt; | gated | Authorization privilege scopes. Same gating as `role`. |

### 4.7 CIBA token claims

CIBA-issued tokens (Section 6) additionally carry:

| Claim | Type | Description |
|---|---|---|
| `token_exchange` | string | `ciba`. |
| `backchannel_client_id` | string | The OAuth client that initiated the bc-authorize request. |
| `binding_message` | string | The human-readable binding message shown to the approver, when one was supplied. |
| `authorization_details` | JSON array | The granted RFC 9396 payload (Section 6.2). Always present on CIBA tokens; a legacy request with no RAR stores the canonical empty array `[]`. |

The CIBA token's `sub` is the **approving user**, its `grant_type` claim is
`urn:openid:params:grant-type:ciba`, it is RS256-signed, and its default TTL is
900 seconds.

### 4.8 Deployment-specific claims

Deployers MAY inject additional claims through two mechanisms:

- the `ClaimsEnricher` hook (server-side, applies to issuance), and
- the `additional_claims` request field on the external-principal exchange
  (caller-supplied, blocklist-gated per Section 8).

Coding-agent task fields surfaced by the SDKs (`session_id`, `task_id`,
`task_type`, `allowed_tools`, `workspace`, `environment`) are **not**
first-class ZeroID claims; they travel through these deployment-specific
mechanisms and are subject to the reserved-claims blocklist. Implementers
relying on them MUST treat them as deployment convention, not protocol.

## 5. RFC 8693 Delegation Extensions

ZeroID's `token_exchange` (`urn:ietf:params:oauth:grant-type:token-exchange`)
implements RFC 8693 and adds the following normative behaviour. The exchange
mechanism itself is NHI-general — any NHI may be a subject or actor — but the
`act` chain and `delegation_depth` it produces are the *agent-shaped* semantics
that make agent orchestration attributable. The terms **orchestrator** and
**sub-agent** below are agent roles (Section 3.2); a delegation between
non-agent NHIs uses the same mechanism without those role labels.

### 5.1 Scope attenuation (three-way intersection)

On an NHI delegation exchange the issued scope set **MUST** equal the
intersection of:

1. the scopes **requested** (`scope` parameter),
2. the scopes the **orchestrator** (subject_token) actually holds, and
3. the `allowed_scopes` of the **sub-agent's** (actor) credential policy.

A delegated credential can therefore never hold a scope its delegator lacked,
nor one the sub-agent's policy forbids. Requesting a scope outside the
intersection is silently narrowed (the scope is dropped), not granted.

### 5.2 Delegation depth tracking and capping

Each exchange increments `delegation_depth` by 1 relative to the subject token.
The actor's credential policy `max_delegation_depth` caps the chain: an exchange
that would exceed it **MUST** be rejected. `delegation_depth` is emitted as a
claim only when &gt; 0 (Section 4.3).

### 5.3 NHI delegation requires an actor proof-of-possession

For NHI → NHI delegation, both `subject_token` (the orchestrator's active
credential) and `actor_token` (a JWT assertion the sub-agent self-signs with the
private key matching its registered public key) are **REQUIRED**. The
`actor_token`:

- **MUST** use an asymmetric `alg`; `none` and HMAC algorithms are rejected
  (JWT-SVID §3, same allow-list as Section 7.2);
- **MUST** carry `iss` equal to the actor identity's WIMSE URI;
- **MUST** carry `aud` equal to the ZeroID issuer;
- **MUST** carry `sub` and `exp` — RFC 7523 §3 mandatory assertion claims,
  inherited by the RFC 8693 token-exchange assertion contract (§1.2). ZeroID
  enforces their presence explicitly, because the underlying JWT library honors
  these claims when present but does not require them.

ZeroID validates the assertion signature against the actor identity's registered
ES256 public key before issuing. The issued token's `act.sub` is set to the
orchestrator's WIMSE URI (Section 4.4 case 1).

### 5.4 `mission_id` — delegation-tree identifier

`mission_id` is an opaque, stable identifier shared by every credential in a
delegation tree:

- On a first-issuance grant (no inbound `mission_id`), ZeroID sets
  `mission_id` to the new credential's own `jti`, making it the tree root.
- On `token_exchange`, the value propagates verbatim from the subject token.

The value is opaque to consumers. The "root happens to be a JTI" detail is an
implementation artifact and **MUST NOT** be relied on through any API.
`mission_id` scopes the Delegation Explorer queries and the CAE signal stream.

### 5.5 External-principal exchange (synthesised subject, no actor)

ZeroID adds a second exchange mode for a **trusted internal service** to mint a
token for an external (typically human) principal it has already authenticated —
e.g. a gateway translating an upstream IdP session into a ZeroID token. This
mode:

- **MUST** pass the deployer's `TrustedServiceValidator` gate; an untrusted
  caller cannot reach it.
- Takes `account_id`, `project_id`, `user_id` (becomes `sub` via subject
  override), and OPTIONAL `user_email`, `user_name`, `application_id`,
  `additional_claims`, `role`, `privilege_scope`.
- Does **not** require an `actor_token`.
- Emits `token_exchange=external_principal` and `trusted_by=<service>`.
- Is RS256-signed with a short (900 s) TTL.

### 5.6 Cascade revocation

Revoking any credential revokes the entire subtree beneath it (all credentials
whose `parent_jti` chain reaches the revoked `jti`). Revoking an identity
(deactivation) revokes all of its active credentials and, transitively, their
delegated descendants. Cascade is bounded (see migration `007`/`029`).
Revocation events are observable through the `RevocationNotifier` hook, one event
per revoked `jti`; ZeroID ships no built-in deny-set transport.

## 6. CIBA Extensions

ZeroID implements OpenID CIBA Core 1.0 (poll / ping / push) and extends the
`POST /oauth2/bc-authorize` request as follows.

### 6.1 `group_hint` — role/group-targeted approval

CIBA Core §7.1 requires at least one of `login_hint_token`, `id_token_hint`, or
`login_hint` to identify the target user. ZeroID adds an extension parameter:

| Parameter | Type | Constraints |
|---|---|---|
| `group_hint` | string | Opaque, deployer-namespaced. Max **255 codepoints** (multi-byte UTF-8 accepted). |

- The bc-authorize request **MUST** carry at least one of `login_hint` **or**
  `group_hint`. ZeroID accepts either to satisfy the CIBA "one hint" requirement.
- `group_hint` is **opaque** to ZeroID. It is a deployer-namespaced selector for
  approval by *whoever currently holds a role / fills a queue* rather than a
  specific user — e.g. `highflame:role:finance_lead`, `pd:schedule:P12345`.
- ZeroID passes `group_hint` verbatim to the deployer's `BackchannelNotifier`,
  which resolves it to a set of approvers at fan-out time.
- First-approver-wins is enforced by ZeroID's existing atomic single-use CAS on
  `auth_req_id`; a `group_hint` fan-out to N approvers still yields exactly one
  issued token.

Both JSON and form-encoded bc-authorize bodies are accepted.

### 6.2 Rich Authorization Requests on CIBA (RFC 9396)

ZeroID accepts an RFC 9396 `authorization_details` JSON array on bc-authorize so
the approver can be shown *exactly what is being authorized* at finer
granularity than a scope string (e.g.
`{"type":"tool_call","tool":"transfer_funds","amount":50000}`).

- ZeroID validates the **outer shape** (a JSON array whose every element is an
  object with a string `type`). Per-`type` schema validation is opt-in via the
  `RegisterAuthorizationDetailValidator(type, fn)` hook.
- A rejected payload maps to the RFC 9396 §5 error code
  `invalid_authorization_details`.
- The raw parsed slice is threaded verbatim to the `BackchannelNotifier` for a
  per-action approval UX.
- On approval the granted payload is (a) embedded in the access-token JWT as the
  `authorization_details` claim (§6.1), (b) returned on the token response body
  (§5.2), and (c) exposed via introspection (§7). A resource server can read the
  typed grant from either the JWT or `/oauth2/token/introspect`.

See `docs/rar.md` for worked examples.

### 6.3 Delivery-mode and notification client metadata

Two OAuth-client fields govern CIBA delivery (advertised in discovery,
Section 11.1):

| Client field | Values | Meaning |
|---|---|---|
| `backchannel_token_delivery_mode` | `poll` (default), `ping`, `push` | How the issued token reaches the client. |
| `client_notification_endpoint` | HTTPS URL | Ping/push callback target. SSRF-guarded; private endpoints rejected unless the deployer sets `AllowPrivateNotificationEndpoints`. |

## 7. DPoP Extensions

ZeroID implements RFC 9449 DPoP (proof at `/oauth2/token`, `cnf.jkt` binding,
atomic `jti` replay store, resource-server-side validation). The portable
verifier lives in the standalone module `pkg/dpop`. ZeroID adds one extension
claim.

### 7.1 Body-hash claim (`bh`) — ZeroID extension

`bh` is a **ZeroID extension** to the DPoP proof, not a standardized claim.
RFC 9449 covers only the HTTP method and URI (`htm`/`htu`) and the access-token
hash (`ath`); it leaves request-body integrity out of scope but notes that
additional signed information may be added to a proof — `bh` is such an
addition. There is no adopted IETF draft for a DPoP body-hash claim, and the
standards momentum is elsewhere: the standards-track way to obtain full
request-body integrity is **HTTP Message Signatures (RFC 9421)** over a signed
**`Content-Digest` (RFC 9530)**. In the IETF WIMSE track that role is filled by
the workload-to-workload HTTP-Message-Signatures profile
(`draft-schwenkschuster-s2s-http-sig`), while the WIMSE Workload Proof Token
(`draft-ietf-wimse-wpt`) deliberately does **not** cover the body. ZeroID's `bh`
is a lighter-weight, DPoP-inline alternative used by the agent hook flow;
deployments that need full message-signature semantics should layer RFC 9421
instead. The verifier binds a proof to a specific request payload as:

```
bh = base64url( SHA-256( request-body ) )   // no padding
```

- **Default mode:** `bh` is OPTIONAL. If the request has a body **and** the
  proof carries `bh`, the verifier **MUST** recompute and compare (constant-time)
  and reject on mismatch (`ErrBodyHashMismatch`). If `bh` is absent, no body
  check runs.
- **Strict mode (`RequireBodyHash()`):** a body-bearing request whose proof
  lacks `bh` **MUST** be rejected (`ErrBodyHashRequired`). RECOMMENDED for inline
  gateways and guardrails.

### 7.2 Algorithm policy

The DPoP proof `alg` **MUST** be asymmetric: one of `ES256` `ES384` `ES512`
`EdDSA` `RS256` `RS384` `RS512` `PS256` `PS384` `PS512`. `none` and all HMAC
algorithms (`HS*`) and any unknown alg **MUST** be rejected **before** any
cryptographic work, to foreclose algorithm-confusion attacks. (ZeroID's
*issued-token* DPoP-alg discovery advertises the subset it accepts on the proof
header; see Section 11.1.)

### 7.3 Validation order

The verifier applies checks cheap-first, committing replay state last:
parse + `typ=dpop+jwt` + alg allow-list + embedded public JWK + signature →
`htm` → `htu` (normalized) → `iat` freshness → `ath` (if access token present) →
`bh` (if body present / required) → atomic `jti` replay insert. Earlier failures
**MUST NOT** write to the replay store.

See `docs/dpop-and-dcr.md` for the full DPoP + Dynamic Client Registration
reference.

## 8. Reserved-Claims Gating

The external-principal exchange accepts a caller-supplied `additional_claims`
map for deployment-specific data (e.g. `gateway_id`). To prevent
privilege-escalation by claim injection, ZeroID maintains a **reserved-claims
blocklist**. Any key in the blocklist supplied via `additional_claims` is
**silently dropped** (never overrides the server-derived value), on **every**
grant.

The reserved set is:

```
# RFC 7519 registered
iss sub aud exp nbf iat jti
# ZeroID identity
account_id project_id user_id owner_user_id external_id identity_type
sub_type trust_level status name framework version publisher capabilities
scopes grant_type delegation_depth user_email user_name
# ZeroID internal / provenance
act token_exchange trusted_by
# RFC 9449 sender-constraint
cnf
# Authorization (gated)
role privilege_scope
```

Special cases:

- `cnf` is reserved so a trusted-service caller cannot forge a token that
  *appears* DPoP-bound to an attacker-chosen key. `cnf.jkt` is set **only** from
  a server-validated proof (Section 4.5).
- `role` and `privilege_scope` are reserved against `additional_claims` on
  **all** grants, but MAY be set on the trusted external-principal path through
  **dedicated request fields** (`role`, `privilege_scope`) — i.e. only *after*
  the `TrustedServiceValidator` gate. Empty values are omitted, preserving
  byte-identical tokens for callers that don't use them.

This makes the `additional_claims` route fail closed regardless of which grant
is in play.

## 9. CAE / SSF Signals

ZeroID consumes Continuous Access Evaluation signals (OpenID Shared Signals
Framework / CAEP family) to drive real-time revocation. The signal vocabulary
is a ZeroID-defined extension.

### 9.1 Signal types

| `signal_type` | Meaning |
|---|---|
| `credential_change` | A credential's state changed. |
| `session_revoked` | A session was revoked upstream. |
| `ip_change` | Source IP changed unexpectedly. |
| `anomalous_behavior` | Behavioural anomaly detected. |
| `policy_violation` | A policy was violated. |
| `retirement` | Identity is being retired. |
| `owner_change` | The owner of an identity changed. |
| `identity_expired` | A time-bound identity reached its expiry. |

### 9.2 Severity

`severity` ∈ { `low`, `medium`, `high`, `critical` }. A signal of severity
`high` or `critical` triggers credential revocation (and cascade per
Section 5.6).

### 9.3 Signal shape and scoping

A signal carries `identity_id`, `signal_type`, `severity`, a `source` string,
and an arbitrary JSON `payload`. Signals are tenant-scoped and may carry
`mission_id` so subscribers can filter to one delegation tree.

## 10. Workload Identity Federation

ZeroID participates in workload identity federation (WIF) in **both
directions**, neither of which uses a long-lived secret:

- **Inbound — ZeroID as relying party (§10.1–10.4).** A workload presents an
  upstream platform OIDC token (GitHub Actions, GCP Workload Identity,
  Kubernetes projected service-account tokens, AWS IAM/EKS, …); ZeroID verifies
  it as an attestation and issues a ZeroID credential. Realised through the
  attestation framework's OIDC verifier (see `docs/attestation.md`).
- **Outbound — ZeroID as a federation issuer (§10.4).** A ZeroID-issued token is
  itself federated by a downstream WIF relying party (e.g. Anthropic, GCP, AWS,
  Azure); the workload uses its ZeroID credential to obtain access at that
  provider with no provider-native secret. Realised purely through ZeroID's
  standard, externally-verifiable token + JWKS surface — no provider-specific
  code on either side.

This section specifies both wire contracts.

### 10.1 Inbound — proof types

An attestation submission carries a `proof_type`:

| `proof_type` | Status | Use |
|---|---|---|
| `oidc_token` | Implemented | Federate an upstream platform OIDC token — the WIF path. |
| `image_hash` | Reserved (not yet implemented) | Container image-digest attestation. |
| `tpm` | Reserved (not yet implemented) | Hardware / TPM attestation. |

The verifier contract is **fail-closed**: a missing verifier, a missing policy,
or any verification failure yields no trust promotion and no credential.

### 10.2 Inbound — per-tenant issuer policy (`oidc_token`)

A tenant authorises upstream issuers through an `AttestationPolicy` whose
`proof_type` is `oidc_token` and whose config is an `OIDCPolicyConfig`:

| Field | Type | Meaning |
|---|---|---|
| `issuers` | array of issuer configs | Allowlist. The submitted token's `iss` **MUST** match one entry's `url` or verification fails; at least one issuer is required. |

Each `issuers[]` entry (`OIDCIssuerConfig`):

| Field | Type | Meaning |
|---|---|---|
| `url` | string | Issuer URL. Matched against the token `iss` **and** used to discover the JWKS via `{url}/.well-known/openid-configuration`. The discovery fetch is size-bounded and **MUST** use HTTPS (loopback hosts excepted, for local dev/test). |
| `audiences` | array&lt;string&gt; (OPTIONAL) | If non-empty, the token `aud` **MUST** contain at least one of these. Empty disables the audience check. |
| `required_claims` | map&lt;string,string&gt; (OPTIONAL) | Exact-string-match requirements that bind the token to a specific workload. Every listed key **MUST** be present on the token and equal the configured value. E.g. for GitHub Actions OIDC: `{"repository":"myorg/myrepo","ref":"refs/heads/main"}`. |

Issuer allowlisting and claim binding are configured per `(account_id,
project_id)` — there is no global trust.

### 10.3 Inbound — verification and trust-elevation flow

WIF is a two-step exchange:

1. The workload **submits** its platform OIDC token as an attestation record
   bound to an identity.
2. A **verify** step runs the OIDC verifier against that record and, on success,
   **promotes the identity's trust level and issues a credential** in a single
   transaction.

The OIDC verifier applies, in order:

1. Parse the submitted token; match its `iss` against the tenant's issuer
   allowlist (Section 10.2). No match → reject.
2. Discover the matched issuer's JWKS (`/.well-known/openid-configuration`,
   HTTPS, size-bounded) and verify the token signature.
3. If the issuer config sets `audiences`, require the token `aud` to contain one.
4. Enforce every `required_claims` exact match.
5. Require and validate `exp`; require `sub` and `iss`.
6. On success, record the verified `sub` / `iss` / expiry, promote the
   identity's trust level (mapping the attestation level to `first_party` or
   `verified_third_party`, per Section 3.2), and issue a credential through the
   credential service under the identity's policy.

A workload therefore presents only its platform-issued OIDC token; ZeroID never
holds a secret for it, and rotation is the platform's concern.

### 10.4 Outbound — ZeroID as a federation issuer

ZeroID-issued tokens are ordinary, externally-verifiable JWTs, so a downstream
**WIF relying party** can be configured to trust ZeroID as an external OIDC
issuer and accept a ZeroID credential in place of its own provider-native
secret. The federation mechanism is **RFC 7523** (JWT-bearer assertion): the
workload mints a ZeroID access token, then presents it to the relying party's
token endpoint as the assertion in a
`urn:ietf:params:oauth:grant-type:jwt-bearer` exchange; the relying party
validates the signature against ZeroID's published JWKS and maps it — via a
federation rule keyed on `iss`, `aud`, the `sub` prefix, and ZeroID claims such
as `trust_level` — to a short-lived credential bound to one of its own
service accounts. This is the outward mirror of ZeroID's own inbound RFC 7523 /
RFC 8693 exchanges (Section 5), and requires no ZeroID-specific integration on
either side — only ZeroID's standard issuer surface:

- **Verifiable tokens.** Every issued token carries `iss` (the ZeroID issuer
  URL), `sub` (the workload's WIMSE URI, Section 3.1), `aud`, `exp`, and a `kid`
  header, signed ES256 (NHI flows) or RS256.
- **JWKS at `/.well-known/jwks.json`.** Keys are published with `use="sig"`
  (RFC 7517 §4.2) **specifically so external WIF validators accept them** — the
  Anthropic, Azure, GCP, and AWS WIF validators reject keys whose `use` is
  anything other than `sig`/`enc`. This is asserted by ZeroID's JWKS
  compatibility test.
- **Issuer discovery.** `/.well-known/oauth-authorization-server` (Section 11.1)
  advertises `issuer` and `jwks_uri`; a relying party either points its JWKS
  source at that discovery document or is given the JWKS URL explicitly. ZeroID
  does not publish an `/.well-known/openid-configuration` document.
- **SPIFFE consumers.** `/.well-known/spiffe-trust-bundle.json` (Section 11.3)
  serves the same keys with `use="JWT-SVID"` for SPIFFE-strict validators.

A relying party configures (a) the trusted issuer = ZeroID's issuer URL,
(b) the JWKS URI = `{issuer}/.well-known/jwks.json`, and (c) whatever audience /
subject / claim constraints it enforces, then maps the verified ZeroID `sub`
(a WIMSE URI) to a local principal. The workload presents its ZeroID access
token to the relying party; no provider-native secret is involved.

**Anthropic Workload Identity Federation** is a verified relying party for this
path: configured to trust the ZeroID issuer and its JWKS, it accepts a
ZeroID-issued token as a federated workload credential — granting Anthropic API
access without a static Anthropic API key. GCP Workload Identity Federation,
AWS, and Azure follow the same configuration shape.

> **Audience note.** The public `/oauth2/token` endpoint does not expose an
> `audience` / `resource` parameter; issued tokens default `aud` to the ZeroID
> issuer URL. A relying party that enforces a specific audience **MUST**
> therefore be configured to accept the ZeroID issuer URL as the expected
> audience (rather than expecting ZeroID to mint a caller-chosen `aud`).

## 11. Discovery Metadata Extensions

### 11.1 Authorization Server Metadata (RFC 8414)

`GET /.well-known/oauth-authorization-server` includes, beyond the RFC 8414
baseline:

| Field | Value (reference deployment) | Source spec |
|---|---|---|
| `dpop_signing_alg_values_supported` | `["ES256","RS256"]` | RFC 9449 §5.1 |
| `backchannel_authentication_endpoint` | `<issuer>/oauth2/bc-authorize` | CIBA Core |
| `backchannel_token_delivery_modes_supported` | `["poll","ping","push"]` | CIBA Core |
| `backchannel_user_code_parameter_supported` | `false` | CIBA Core |
| `backchannel_authentication_request_signing_alg_values_supported` | `[]` (signed bc-authorize requests unsupported) | CIBA Core |

### 11.2 Protected Resource Metadata (RFC 9728)

`GET /.well-known/oauth-protected-resource`:

| Field | Value |
|---|---|
| `resource` | `<issuer>` |
| `resource_name` | `ZeroID` |
| `jwks_uri` | `<issuer>/.well-known/jwks.json` |
| `bearer_methods_supported` | `["header"]` |
| `dpop_bound_access_tokens_required` | `false` (DPoP optional) |

### 11.3 SPIFFE trust bundle

`GET /.well-known/spiffe-trust-bundle.json` publishes the JWKS as a SPIFFE
JWT-SVID trust bundle: each key's `use` is `JWT-SVID`, and the document carries
`spiffe_sequence` and `spiffe_refresh_hint` per the SPIFFE bundle format. This
lets SPIFFE-aware verifiers consume ZeroID's `sub` (a SPIFFE ID) natively.

## 12. Security Considerations

- **No authority amplification on delegation.** Scope attenuation (5.1) and
  depth capping (5.2) are enforced server-side; a delegated token is always a
  subset of its delegator's authority capped by the sub-agent's policy. A
  resource server SHOULD still enforce its own least-privilege check.
- **Reserved-claims gating (8)** is the single chokepoint preventing
  caller-injected privilege claims (`role`, `privilege_scope`, `cnf`, identity
  claims). Any new authorization-bearing claim added in future **MUST** be added
  to the reserved set in the same change.
- **`cnf` provenance.** A resource server validating a DPoP-bound token **MUST**
  obtain `cnf.jkt` from the token/introspection (set by ZeroID), not from any
  caller-controlled input, and **MUST** validate a fresh per-request proof
  against it. The `bh` extension (7.1) further binds a proof to its body; inline
  guardrails SHOULD run in strict mode.
- **`group_hint` is opaque and trust-sensitive.** ZeroID does not interpret it;
  the deployer's `BackchannelNotifier` resolves it to approvers. A deployer
  **MUST** namespace and authorize `group_hint` values so an agent cannot target
  an approval queue it shouldn't reach. The 255-codepoint cap bounds persisted
  row size.
- **CIBA single-use.** `auth_req_id` is atomically single-use; group fan-out
  cannot yield multiple tokens.
- **External-principal exchange is a trust boundary.** It mints tokens for
  arbitrary `user_id`s and is gated **only** by `TrustedServiceValidator`. The
  deployer **MUST** restrict that gate to genuinely trusted internal callers; it
  is effectively an impersonation capability.
- **Cascade revocation latency.** Revocation cascade and the `RevocationNotifier`
  fan-out are asynchronous; a resource server requiring hard real-time
  revocation **MUST** introspect rather than rely solely on local JWT
  verification.
- **Metadata is non-confidential.** The discovery documents (Section 11) expose
  structural metadata; they are tenant-scoped but SHOULD be treated as readable
  by anyone holding a tenant credential.
- **Outbound federation extends the trust boundary.** When a relying party
  federates ZeroID as an external issuer (Section 10.4), it inherits a
  dependency on ZeroID's key custody and issuer security, and — if it validates
  only signature + `exp` — it will **not** observe ZeroID-side revocation or CAE
  cascade. Relying parties that need real-time revocation MUST introspect or
  rely on short token TTLs; deployers SHOULD scope the `aud`/`sub`/claim
  constraints a relying party accepts as tightly as the provider allows.

## 13. Claim / Parameter Registry (IANA-style)

Informative registry of every identifier this document defines, for ZeroID
deployments. "Std" marks an identifier defined by a baseline spec but
*populated* with ZeroID semantics.

### 13.1 JWT claims

| Claim | Kind | Defined in |
|---|---|---|
| `account_id` | string | §4.1 |
| `project_id` | string | §4.1 |
| `grant_type` | string | §4.1 |
| `mission_id` | string | §4.1, §5.4 |
| `external_id` | string | §4.2 |
| `identity_type` | string | §4.2 |
| `sub_type` | string | §4.2 |
| `trust_level` | string | §4.2 |
| `status` | string | §4.2 |
| `owner_user_id` | string | §4.2 |
| `name` `framework` `version` `publisher` | string | §4.2 |
| `capabilities` | JSON | §4.2 |
| `scopes` | array | §4.3 |
| `delegation_depth` | number | §4.3, §5.2 |
| `application_id` | string | §4.3 |
| `user_email` `user_name` | string | §4.3 |
| `act` | object | §4.4 (Std: RFC 8693) |
| `cnf` | object | §4.5 (Std: RFC 9449) |
| `token_exchange` | string | §4.6, §4.7 |
| `trusted_by` | string | §4.6 |
| `role` | string | §4.6, §8 (gated) |
| `privilege_scope` | array | §4.6, §8 (gated) |
| `backchannel_client_id` | string | §4.7 |
| `binding_message` | string | §4.7 |
| `authorization_details` | array | §4.7, §6.2 (Std: RFC 9396) |

### 13.2 Request parameters

| Parameter | Endpoint | Defined in |
|---|---|---|
| `group_hint` | `/oauth2/bc-authorize` | §6.1 |
| `authorization_details` | `/oauth2/bc-authorize` | §6.2 |
| `role`, `privilege_scope` | `/oauth2/token` (ext-principal exchange) | §5.5, §8 |
| `additional_claims` | `/oauth2/token` (ext-principal exchange) | §4.8, §8 |

### 13.3 DPoP proof claim

| Claim | Defined in |
|---|---|
| `bh` | §7.1 (ZeroID extension — not in RFC 9449, no adopted IETF draft) |

### 13.4 Signal types & severities

See §9.1 / §9.2.

### 13.5 Discovery fields

See §11.1 / §11.2 / §11.3.

### 13.6 Workload Identity Federation

Inbound: proof types (`oidc_token`, `image_hash`, `tpm`) and the
`OIDCPolicyConfig` / `OIDCIssuerConfig` policy fields (`issuers`, `url`,
`audiences`, `required_claims`) — §10.1–10.3. Outbound: the
ZeroID-as-federation-issuer surface — JWKS `use="sig"`,
`oauth-authorization-server` `issuer`/`jwks_uri`, and the SPIFFE trust bundle
(§10.4).

## 14. References

### 14.1 Normative (baseline specs extended)

| Specification | Used for |
|---|---|
| RFC 2119 / RFC 8174 | Requirement keywords |
| RFC 6749 / OAuth 2.1 | OAuth framework |
| RFC 7519 | JSON Web Token |
| RFC 7638 | JWK Thumbprint (`cnf.jkt`) |
| RFC 7591 / RFC 7592 | Dynamic Client Registration / Management |
| RFC 7662 / RFC 7009 | Introspection / Revocation |
| RFC 8414 | Authorization Server Metadata |
| RFC 8693 | OAuth 2.0 Token Exchange (`act`, delegation) |
| RFC 9396 | Rich Authorization Requests (`authorization_details`) |
| RFC 9449 | DPoP |
| RFC 9728 | Protected Resource Metadata |
| OpenID CIBA Core 1.0 | Backchannel Authentication |
| OpenID Shared Signals Framework / CAEP | CAE signals |
| SPIFFE / WIMSE | Identity URI scheme and trust bundle |

### 14.2 Informative

- The `bh` body-hash proof claim (Section 7.1) is a ZeroID extension with no RFC
  or IETF draft of its own. For the standards-track approach to request-body
  integrity, see the related work below.
- RFC 9421 — HTTP Message Signatures (application-layer request integrity,
  including the body when a `Content-Digest` is signed).
- RFC 9530 — Digest Fields (`Content-Digest`).
- `draft-ietf-wimse-wpt` — WIMSE Workload Proof Token (key-bound request PoP;
  binds target URI and token hashes, not the body).
- `draft-schwenkschuster-s2s-http-sig` — WIMSE workload-to-workload via HTTP
  Message Signatures (the WIMSE body-integrity path; ZeroID's `bh` is a lighter
  inline alternative).
- OpenID Foundation, *Identity Management for Agentic AI* (Oct 2025).
- Companion guides in this repository: `docs/dpop-and-dcr.md`, `docs/rar.md`,
  `docs/attestation.md`, `docs/vs_entra_agentidentity.md`.

---

*This specification documents the ZeroID reference implementation maintained by
[Highflame](https://highflame.ai). Apache-2.0.*
