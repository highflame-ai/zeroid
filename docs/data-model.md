# ZeroID Data Model

This document describes every persistent object in ZeroID and the claims embedded in the JWTs it issues. It is the authoritative reference for integrators, SDK authors, and anyone building on top of ZeroID.

---

## Table of contents

- [Tenant context](#tenant-context)
- [Identity](#identity)
- [Agent](#agent)
- [OAuth Client](#oauth-client)
- [API Key](#api-key)
- [Credential Policy](#credential-policy)
- [Issued Credential (JWT record)](#issued-credential)
- [Refresh Token](#refresh-token)
- [CAE Signal](#cae-signal)
- [Attestation Record](#attestation-record)
- [WIMSE Proof Token](#wimse-proof-token)
- [JWT Claims Reference](#jwt-claims-reference)
- [Grant Types](#grant-types)
- [State machines](#state-machines)
- [Object relationships](#object-relationships)

---

## Tenant context

Every object in ZeroID is scoped to an `account_id` and `project_id`. These are free-form strings that map to your organisational hierarchy (e.g. an Okta org and an application, or a cloud account and a deployment environment). All admin API calls require `X-Account-ID` and `X-Project-ID` request headers.

```
account_id: "acct_prod_ecommerce"
project_id: "proj_checkout_service"
```

---

## Identity

An **Identity** is the core record in ZeroID. It represents any non-human principal — an AI agent, a microservice, an MCP server, or an application — that can be issued credentials.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key. |
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `external_id` | string | Caller-assigned stable identifier. Must be unique within the tenant. |
| `name` | string | Human-readable display name. |
| `wimse_uri` | string | Globally unique SPIFFE-format URI (see below). |
| `identity_type` | string | Category of principal. One of `agent`, `application`, `mcp_server`, `service`. |
| `sub_type` | string | Specialisation within the type (see sub-types table below). |
| `trust_level` | string | One of `unverified`, `verified_third_party`, `first_party`. |
| `status` | string | Lifecycle state. One of `pending`, `active`, `suspended`, `deactivated`. |
| `owner_user_id` | string | The human user responsible for this identity. |
| `allowed_scopes` | string[] | Scopes this identity may request. `null` = unrestricted. |
| `public_key_pem` | string | PEM-encoded public key for jwt_bearer authentication. Empty for API-key-only identities. |
| `framework` | string | AI framework in use (e.g. `langchain`, `crewai`, `openai-agents`). |
| `version` | string | Version of the agent or service. |
| `publisher` | string | Organisation that publishes this agent. |
| `description` | string | Free-text description. |
| `capabilities` | JSON | Arbitrary structured metadata describing what the agent can do. |
| `labels` | JSON | Key-value tags for filtering and grouping. |
| `metadata` | JSON | Additional opaque metadata. |
| `created_by` | string | User ID of the creator. |
| `created_at` | timestamp | |
| `updated_at` | timestamp | |

### WIMSE URI format

```
spiffe://{wimseDomain}/{accountID}/{projectID}/{identityType}/{externalID}
```

Example:
```
spiffe://zeroid.dev/acct_prod/proj_checkout/agent/payment-processor-v2
```

The WIMSE URI is the `sub` claim in all issued JWTs and is the globally unique, portable identity for the principal across federated deployments.

### Identity types

| `identity_type` | Description |
|-----------------|-------------|
| `agent` | AI agent with autonomous decision-making. |
| `application` | Traditional software application or chatbot. |
| `mcp_server` | Model Context Protocol server. |
| `service` | Backend microservice or API. |

### Sub-types

| `identity_type` | `sub_type` | Description |
|-----------------|------------|-------------|
| `agent` | `orchestrator` | Top-level agent that delegates to sub-agents. |
| `agent` | `autonomous` | Fully autonomous agent with no human in the loop. |
| `agent` | `tool_agent` | Specialised agent exposed as a callable tool. |
| `agent` | `human_proxy` | Agent acting on behalf of a human principal. |
| `agent` | `evaluator` | Agent that judges or scores outputs. |
| `application` | `chatbot` | Conversational interface. |
| `application` | `assistant` | Productivity assistant. |
| `application` | `api_service` | API-first application. |
| `application` | `code_agent` | Code generation or execution agent. |
| `application` | `custom` | Unclassified application type. |

### Trust levels

Trust levels are ranked: `unverified` (0) < `verified_third_party` (1) < `first_party` (2).

| `trust_level` | Meaning |
|---------------|---------|
| `unverified` | External or unknown origin — treat with least privilege. |
| `verified_third_party` | Third-party agent with a known publisher signature. |
| `first_party` | Owned and operated by your organisation. |

CredentialPolicies can require a minimum trust level before issuing tokens.

---

## Agent

An **Agent** is a shortcut registration type that atomically creates an Identity and an API key in a single call. It is the recommended starting point for new AI agents.

Agents share all fields with Identity. Additional fields returned only from `/api/v1/agents`:

| Field | Type | Description |
|-------|------|-------------|
| `api_key_prefix` | string | First 16 characters of the API key, for identification. |

On registration, the response includes a one-time `api_key` field containing the full plaintext key (`zid_sk_*`). This is the **only time the plaintext key is returned**. Store it securely.

---

## OAuth Client

An **OAuth Client** is a registered client application that participates in OAuth 2.1 flows (authorization code + PKCE, client credentials). Every OAuth Client is linked to an Identity via `identity_id`.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key. |
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `client_id` | string | The `client_id` parameter sent in OAuth flows. |
| `client_secret` | string | Bcrypt-hashed secret. Never returned in API responses. For public PKCE clients, this is empty. |
| `name` | string | Display name. |
| `identity_id` | string | The linked Identity ID. |
| `grant_types` | string[] | Permitted grant types for this client. |
| `redirect_uris` | string[] | Allowed redirect URIs for authorization code flows. |
| `scopes` | string[] | Scopes this client may request. |
| `is_active` | bool | Whether the client can request tokens. |
| `created_at` | timestamp | |
| `updated_at` | timestamp | |

On creation, the response includes a one-time `client_secret` in plaintext. Store it securely.

---

## API Key

An **API Key** is a long-lived credential with the prefix `zid_sk_`. API keys are not used directly as Bearer tokens — they are exchanged for short-lived JWTs via the `api_key` grant. The plaintext key is derived from 24 bytes of `crypto/rand` (192 bits of entropy), base64url-encoded, and SHA-256 hashed before storage.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key. |
| `name` | string | Human-readable name. |
| `description` | string | Optional description. |
| `key_prefix` | string | First 16 characters of the key, for identification. |
| `key_version` | int | Monotonically increasing version counter. |
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `identity_id` | string | The Identity this key authenticates. Empty for human/CLI keys. |
| `created_by` | string | User who created the key. |
| `scopes` | string[] | Scopes the key may request. `null` = unrestricted. |
| `environment` | string | Environment tag (e.g. `production`, `staging`). |
| `expires_at` | timestamp | Optional expiry. `null` = never expires. |
| `state` | string | One of `active`, `revoked`, `expired`. |
| `revoked_at` | timestamp | When the key was revoked. |
| `revoked_by` | string | User who revoked the key. |
| `revoke_reason` | string | Reason for revocation. |
| `last_used_at` | timestamp | Last successful token exchange. |
| `last_used_ip` | string | IP address of the last exchange. |
| `usage_count` | int | Total number of token exchanges. |
| `metadata` | JSON | Arbitrary metadata. |
| `ip_allowlist` | string[] | If set, only these CIDR ranges may use the key. |
| `credential_policy_id` | string | Policy governing tokens issued by this key. |
| `rate_limit_rps` | int | Requests per second limit. `0` = unlimited. |
| `replaced_by` | string | ID of the key that replaced this one on rotation. |
| `created_at` | timestamp | |
| `updated_at` | timestamp | |

---

## Credential Policy

A **Credential Policy** is a reusable governance template that constrains token issuance. Policies are attached to API keys via `credential_policy_id`. When a key is used, ZeroID evaluates all six constraints before signing the JWT.

Every tenant gets a system-created `default` policy automatically.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key. |
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `name` | string | Display name. The reserved name `default` identifies the auto-created tenant policy. |
| `description` | string | Optional description. |
| `max_ttl_seconds` | int | Hard ceiling on issued token lifetime. Default: `3600` (1 hour). |
| `allowed_grant_types` | string[] | Grant types this policy permits. Default: `["api_key", "client_credentials"]`. |
| `allowed_scopes` | string[] | Scopes this policy permits. `null` = unrestricted. |
| `required_trust_level` | string | Minimum trust level the requesting identity must have. |
| `required_attestation` | string | Attestation level required (`software`, `platform`, `hardware`). Empty = none. |
| `max_delegation_depth` | int | Maximum RFC 8693 delegation chain depth. Default: `1`. |
| `is_active` | bool | Whether the policy can be applied. |
| `created_at` | timestamp | |
| `updated_at` | timestamp | |

### The six enforcement constraints

When a token is requested, ZeroID checks (in order):

1. **TTL** — requested TTL ≤ `max_ttl_seconds`.
2. **Grant type** — `grant_type` is in `allowed_grant_types`.
3. **Scopes** — all requested scopes are in `allowed_scopes`.
4. **Trust level** — identity's `trust_level` ≥ `required_trust_level`.
5. **Attestation** — identity has a verified attestation record at the required level.
6. **Delegation depth** — `delegation_depth` ≤ `max_delegation_depth`.

---

## Issued Credential

An **Issued Credential** is a server-side record of every JWT ZeroID has signed. It enables introspection, revocation, and audit without decoding the JWT itself.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key. |
| `identity_id` | UUID | The Identity that received this token. |
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `jti` | string | JWT ID — unique per token, used for lookup and revocation. |
| `subject` | string | The `sub` claim (WIMSE URI of the identity). |
| `issued_at` | timestamp | When the token was issued. |
| `expires_at` | timestamp | When the token expires. |
| `ttl_seconds` | int | Requested lifetime. |
| `scopes` | string[] | Scopes granted. |
| `is_revoked` | bool | Whether the token has been revoked. |
| `revoked_at` | timestamp | When the token was revoked. |
| `revoke_reason` | string | Reason for revocation. |
| `grant_type` | string | The grant type used to issue this token. |
| `delegation_depth` | int | Depth in the RFC 8693 delegation chain. `0` = not delegated. |
| `parent_jti` | string | JTI of the token that was exchanged to produce this one (token_exchange only). |
| `delegated_by_wimse_uri` | string | WIMSE URI of the orchestrator that delegated authority (token_exchange only). |

Revocation is synchronous — a CAE signal with severity `high` or `critical` immediately sets `is_revoked = true` on all active credentials for the affected identity.

---

## Refresh Token

A **Refresh Token** is a long-lived opaque credential (prefix `zid_rt_`) used to obtain new access tokens without re-authenticating. ZeroID implements **family-based rotation with reuse detection**: every use invalidates the old token and issues a new one in the same family. If a reused (already-rotated) token is presented, the entire family is revoked.

Refresh tokens are stored as SHA-256 hashes — the plaintext token is never persisted.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key. |
| `token_hash` | string | SHA-256 hash of the plaintext token. Never returned in API responses. |
| `client_id` | string | The OAuth client that holds this token. |
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `user_id` | string | The user (human or agent) associated with this session. |
| `identity_id` | UUID | The Identity this token authenticates (nullable). |
| `scopes` | string | Space-separated scope string. |
| `family_id` | UUID | Rotation family. All tokens derived from the same authorization share a family. Compromised family → full family revocation. |
| `state` | string | One of `active`, `revoked`. |
| `expires_at` | timestamp | Token expiry (default 90 days from issuance). |
| `revoked_at` | timestamp | When the token was revoked. |
| `created_at` | timestamp | |

---

## CAE Signal

A **CAE Signal** is a risk event ingested from an external source or internal component. Signals trigger real-time access re-evaluation (Continuous Access Evaluation). High and critical signals immediately revoke all active credentials for the affected identity synchronously.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key. |
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `identity_id` | UUID | The identity the signal applies to. |
| `signal_type` | string | Type of risk event (see table below). |
| `severity` | string | One of `low`, `medium`, `high`, `critical`. |
| `source` | string | System that generated the signal (e.g. `k8s-admission`, `siem`, `zeroid-internal`). |
| `payload` | JSON | Arbitrary signal-specific data. |
| `processed_at` | timestamp | When the signal was evaluated. `null` = not yet processed. |
| `created_at` | timestamp | |

### Signal types

| `signal_type` | Description | `high`/`critical` effect |
|---------------|-------------|--------------------------|
| `credential_change` | API key rotated or secret changed. | Revoke all active tokens. |
| `session_revoked` | Session explicitly terminated. | Revoke all active tokens. |
| `ip_change` | Source IP address changed unexpectedly. | Revoke all active tokens. |
| `anomalous_behavior` | Detected by SIEM or anomaly detector. | Revoke all active tokens. |
| `policy_violation` | Request violated a CredentialPolicy constraint. | Revoke all active tokens. |
| `retirement` | Identity is being decommissioned. | Revoke all active tokens. |
| `owner_change` | `owner_user_id` changed. | Revoke all active tokens. |

### Severity-driven response

| Severity | Action |
|----------|--------|
| `low` | Logged only. |
| `medium` | Logged; may trigger re-evaluation depending on policy. |
| `high` | Synchronous revocation of all active credentials. |
| `critical` | Synchronous revocation of all active credentials. |

---

## Attestation Record

An **Attestation Record** is a submitted proof that a workload is running a known, trusted software image or hardware configuration. Records are used by CredentialPolicies with a non-empty `required_attestation` field.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key. |
| `identity_id` | UUID | The identity being attested. |
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `level` | string | Attestation level: `software`, `platform`, or `hardware`. |
| `proof_type` | string | Type of proof: `image_hash`, `oidc_token`, or `tpm`. |
| `proof_value` | string | The raw proof material (e.g. container image digest, OIDC token). |
| `proof_hash` | string | SHA-256 hash of `proof_value` for tamper detection. |
| `verified_at` | timestamp | When ZeroID verified the proof. `null` = not yet verified. |
| `is_verified` | bool | Whether the proof has been verified. |
| `expires_at` | timestamp | When the attestation expires. |
| `is_expired` | bool | Whether the attestation has expired. |
| `credential_id` | UUID | The IssuedCredential that was gated on this attestation. |
| `created_at` | timestamp | |

### Attestation levels

| `level` | Description |
|---------|-------------|
| `software` | Container image hash or binary measurement. Cheapest to obtain. |
| `platform` | Hypervisor or OS-level measurement (e.g. vTPM, AMD SEV). |
| `hardware` | Physical TPM or HSM-anchored proof. Highest assurance. |

### Proof types

| `proof_type` | Description |
|--------------|-------------|
| `image_hash` | OCI container image digest (sha256:…). |
| `oidc_token` | OIDC token from a workload identity provider (e.g. GitHub Actions, GCP WIF, AWS IMDS). The primary mechanism for secretless bootstrap. |
| `tpm` | TPM 2.0 quote or attestation statement. |

---

## WIMSE Proof Token

A **WIMSE Proof Token (WPT)** is a single-use, bound proof of possession used in WIMSE protocol handshakes. The DB `UNIQUE` constraint on `nonce` provides atomic replay prevention without a separate pre-check query.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key. |
| `identity_id` | string | The identity presenting the proof. |
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `jti` | string | JWT ID of the WPT. |
| `nonce` | string | Unique nonce. DB UNIQUE constraint ensures single-use. |
| `audience` | string | Intended audience (the resource server URL). |
| `issued_at` | timestamp | |
| `expires_at` | timestamp | Short-lived (typically 60 seconds). |
| `is_used` | bool | Whether the WPT has been consumed. |
| `used_at` | timestamp | When it was consumed. |
| `created_at` | timestamp | |

---

## JWT Claims Reference

Every JWT issued by ZeroID carries the following claims. Standard RFC 7519 claims use short names; ZeroID extensions use snake_case.

### Standard claims

| Claim | Description |
|-------|-------------|
| `iss` | Issuer — ZeroID's base URL. |
| `sub` | Subject — the WIMSE URI of the identity. |
| `aud` | Audience — the intended resource server(s). |
| `iat` | Issued-at (Unix timestamp). |
| `exp` | Expiry (Unix timestamp). |
| `jti` | Unique JWT ID — used for introspection and revocation. |

### ZeroID extension claims

| Claim | Type | Description |
|-------|------|-------------|
| `account_id` | string | Tenant account. |
| `project_id` | string | Tenant project. |
| `external_id` | string | Caller-assigned stable identifier of the identity. |
| `identity_type` | string | `agent`, `application`, `mcp_server`, or `service`. |
| `sub_type` | string | Specialisation within the identity type. |
| `trust_level` | string | `unverified`, `verified_third_party`, or `first_party`. |
| `status` | string | Identity status at issuance time. |
| `name` | string | Display name of the identity. |
| `user_id` | string | Human user associated with this session (authorization code / refresh token grants). |
| `scopes` | string[] | Granted scopes. |
| `grant_type` | string | The grant type used to issue this token. |
| `delegation_depth` | int | Depth in the RFC 8693 delegation chain. `0` = not delegated. |
| `framework` | string | AI framework in use. |
| `version` | string | Agent version. |
| `publisher` | string | Agent publisher. |
| `capabilities` | JSON | Agent capabilities metadata. |
| `act` | object | RFC 8693 actor claim — present on delegated tokens only (see below). |

### The `act` claim (RFC 8693 delegation)

When an orchestrator agent delegates authority to a sub-agent via token_exchange, the issued JWT carries an `act` claim identifying the orchestrator:

```json
{
  "sub": "spiffe://zeroid.dev/acct/proj/agent/sub-agent",
  "act": {
    "sub": "spiffe://zeroid.dev/acct/proj/agent/orchestrator",
    "iss": "https://zeroid.dev"
  },
  "delegation_depth": 1,
  ...
}
```

`delegation_depth` increases by 1 at each hop. CredentialPolicies enforce `max_delegation_depth` to prevent unbounded delegation chains.

---

## Grant Types

ZeroID supports six OAuth 2.1 grant types. Both URN and short-form identifiers are accepted.

| Short form | URN / alternative | RFC | Use case |
|------------|-------------------|-----|----------|
| `api_key` | — | — | SDK and CLI authentication. Exchanges a `zid_sk_*` key for a short-lived JWT. |
| `client_credentials` | — | RFC 6749 §4.4 | Machine-to-machine — OAuth client authenticates with `client_id` + `client_secret`. |
| `jwt_bearer` | `urn:ietf:params:oauth:grant-type:jwt-bearer` | RFC 7523 | Secretless bootstrap — workload presents an OIDC token from k8s, AWS IMDS, or GitHub Actions. |
| `token_exchange` | `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 | Agent-to-agent delegation — orchestrator exchanges its token for a constrained sub-agent token. |
| `authorization_code` | — | RFC 6749 §4.1 + PKCE | Human-authorised flows — CLI and MCP clients. |
| `refresh_token` | — | RFC 6749 §6 | Long-lived sessions — rotate access tokens without re-authenticating. |

---

## State machines

### Identity status

```
pending ──────────► active ◄──────── suspended
                       │                  │
                       ▼                  │
                 suspended ───────────────┘
                       │
                       ▼
                 deactivated  (terminal)
                       │
                       ▼ (re-activation)
                    active
```

| Transition | Permitted? |
|------------|-----------|
| `pending` → `active` | Yes |
| `pending` → `suspended` | Yes |
| `active` → `suspended` | Yes |
| `active` → `deactivated` | Yes |
| `suspended` → `active` | Yes |
| `suspended` → `deactivated` | Yes |
| `deactivated` → `active` | Yes (re-activation) |
| Any → `pending` | No |

Only `active` identities can be issued tokens (`IsUsable()` check).

### API key state

```
active ──► revoked  (terminal)
active ──► expired  (terminal)
```

Expiry is evaluated lazily at exchange time. Revocation is permanent.

### Refresh token state

```
active ──► revoked  (terminal)
```

Rotation replaces `active` with a new token in the same family. Reuse of a rotated token revokes the entire family.

### CAE signal processing

```
ingested ──► processed
```

High/critical signals trigger synchronous credential revocation before the HTTP response is returned.

---

## Object relationships

```
CredentialPolicy ◄──── APIKey ──────► Identity
                                          │
                              ┌───────────┼───────────┐
                              │           │           │
                         OAuthClient  AttestationRecord  CAESignal
                              │
                         RefreshToken
                              │
                         IssuedCredential ◄── ProofToken
```

Key relationships:

- **APIKey → Identity**: an API key authenticates a specific identity. Multiple keys can authenticate the same identity (e.g. per-environment keys).
- **APIKey → CredentialPolicy**: the policy gates every token issued via this key. Missing `credential_policy_id` falls back to the tenant default policy.
- **Identity → IssuedCredential**: one identity may have many active tokens simultaneously.
- **IssuedCredential → IssuedCredential** (`parent_jti`): captures the RFC 8693 delegation chain — a sub-agent token links back to the orchestrator token that produced it.
- **OAuthClient → Identity**: every OAuth client is backed by an identity for scoping and trust-level enforcement.
- **RefreshToken → OAuthClient**: refresh tokens are scoped to the issuing OAuth client.
- **CAESignal → Identity**: signals target a specific identity and may trigger mass revocation of all its `IssuedCredential` records.
- **AttestationRecord → IssuedCredential**: records which token issuance was gated on an attestation proof.
