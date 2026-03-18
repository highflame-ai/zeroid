<p align="center">
  <h1 align="center">ZeroID</h1>
  <p align="center"><strong>Identity Infrastructure for Autonomous Agents</strong></p>
  <p align="center">
    Issue short-lived agent credentials · Delegate between agents · Attest · Revoke in real-time
    <br/>
    OAuth 2.1 &middot; WIMSE/SPIFFE &middot; RFC 8693 delegation &middot; Developer SDKs
  </p>
  <p align="center">
    <a href="https://github.com/highflame-ai/zeroid/actions/workflows/release.yml">
      <img src="https://github.com/highflame-ai/zeroid/actions/workflows/release.yml/badge.svg" alt="CI" />
    </a>
    <a href="https://goreportcard.com/report/github.com/highflame-ai/zeroid">
      <img src="https://goreportcard.com/badge/github.com/highflame-ai/zeroid" alt="Go Report Card" />
    </a>
    <a href="https://github.com/highflame-ai/zeroid/releases">
      <img src="https://img.shields.io/github/v/release/highflame-ai/zeroid?color=green" alt="Latest Release" />
    </a>
    <a href="https://pkg.go.dev/github.com/highflame-ai/zeroid">
      <img src="https://pkg.go.dev/badge/github.com/highflame-ai/zeroid.svg" alt="Go Reference" />
    </a>
    <a href="https://github.com/highflame-ai/zeroid/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" />
    </a>
    <a href="https://discord.gg/zeroid">
      <img src="https://img.shields.io/discord/zeroid?label=discord" alt="Discord" />
    </a>
  </p>
</p>

---

## The Problem

When an AI agent takes an action, commits code, calls an API, or modifies a record, the question every security and compliance team asks is:

> *"Which agent did this, acting on whose authority, with what permissions?"*

Today's agents often answer this question badly—or not at all. They impersonate users via shared service accounts, creating no auditable distinction between the human who authorized the action and the agent that executed it. OAuth/OIDC tokens weren't designed for agents that spawn sub-agents, operate without humans in the loop, or need their delegation chains verified across a multi-step workflow.

The [OpenID Foundation's October 2025 whitepaper on Identity Management for Agentic AI](https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf) identifies this as the industry's most urgent unsolved problem: *"User impersonation by agents should be replaced by delegated authority. True delegation requires explicit 'on-behalf-of' flows where agents prove their delegated scope while remaining identifiable as distinct from the user they represent."*

**ZeroID** is the open source implementation of Agent Identity.

## What Is ZeroID

ZeroID is identity infrastructure for autonomous agents: a system that issues cryptographically verifiable credentials, enforces delegated authority through chains of agents, and revokes access in real time. Built on OAuth 2.1, WIMSE/SPIFFE, and RFC 8693, it implements the industry's emerging standards for agent identity before they become requirements.

Each agent gets a stable, globally unique identity URI. When one agent delegates to another, scope is automatically attenuated—the sub-agent can only receive permissions the orchestrator already holds, capped by the sub-agent's own policy. Every token carries the full on-behalf-of chain: who authorized it, what scope was granted, and how deep the delegation goes. Every action is attributable, cryptographically.

At Highflame, we have been using ZeroID to power our Agent Control & Governance Platform for several months now and we are contributing this to open source to further the state of the industry to solve this important problem. 

**The model:**

```
Root authority (human, policy, or orchestrator agent) authorizes Agent A
        ↓
Agent A gets a scoped credential with its WIMSE identity URI
        ↓
Agent A delegates a subset of its scope to Agent B (RFC 8693 token exchange)
        ↓
Agent B's token carries: its own identity + delegation chain + original authorizer
        ↓
Any system Agent B calls can verify the full chain cryptographically
```

The root can be a human, org policy, or another agent. Fully autonomous workflows work without anyone in the loop.

## Why Not OAuth/OIDC or Service Accounts?

OAuth 2.1 works well for Human identity, it works partially for a single agent accessing tools within one trust domain. But, the model completely breaks down the moment agents operate asynchronously, spawn sub-agents, or cross organizational boundaries. Service accounts are worse: they're shared, opaque, and leave no delegation trail at all.

|  | Service Accounts | OAuth/OIDC | ZeroID |
|---|---|---|---|
| Per-agent identity | ❌ Shared | ✅ | ✅ |
| Agent-specific metadata (type, framework, version) | ❌ | ❌ | ✅ |
| On-behalf-of (OBO) delegation chain | ❌ | ❌ | ✅ RFC 8693 |
| Scope attenuation at each delegation step | ❌ | ❌ | ✅ |
| Delegation depth enforcement | ❌ | ❌ | ✅ |
| Real-time revocation with cascade | ❌ | ❌ | ✅ CAE / SSF signals |
| Autonomous workflows (no human in the loop) | ❌ | ❌ | ✅ |
| Open source, standards-based | ❌ | Partial | ✅ |

## The Core Distinction: 
OAuth/OIDC authenticates a human to a service. **ZeroID implements true delegated authority.** Agents are distinct from the users who authorize them, and every token proves it.

## Features

- **Agent Identity Registry** — Register agents, MCP servers, services, and applications as first-class entities. Classify by role (`orchestrator`, `autonomous`, `tool_agent`), enrich with metadata (`framework`, `version`, `publisher`, `capabilities`), assign trust levels, and manage the full lifecycle: register → activate → deactivate → de-provision.
- **OAuth 2.1 Token Issuance** — Full OAuth 2.1 support: `client_credentials`, `jwt_bearer` (RFC 7523), `token_exchange` (RFC 8693) for delegation, `api_key`, `authorization_code` (PKCE), `refresh_token`.
- **On-Behalf-Of (OBO) Delegation** — RFC 8693 token exchange with automatic scope attenuation at each hop, delegation depth tracking, and cascade revocation when any upstream credential is revoked. The `act` claim carries the full chain per RFC 8693, closing the auditability gap that plagues shared service accounts.
- **WIMSE/SPIFFE URIs** — Stable, globally unique identity URIs: `spiffe://{domain}/{account}/{project}/{type}/{id}` for every agent. Tokens carry the WIMSE URI as `sub`, so every downstream system receives a meaningful, verifiable identity—not just a client ID.
- **Credential Policies** — Governance templates that enforce TTL, allowed grant types, required trust levels, and max delegation depth. Defines each agent's operational envelope programmatically, replacing per-action consent with policy-based controls.
- **Continuous Access Evaluation (CAE)** — Revoke credentials in real time when risk signals fire via the OpenID Shared Signals Framework (SSF). Revoke the orchestrator's credential and the entire downstream chain is invalidated immediately—no waiting for token expiry.
- **Attestation Framework** — Software, platform, and hardware attestation to bootstrap or elevate trust levels before credentials are issued.
- **WIMSE Proof Tokens** — Single-use, nonce-bound tokens for service-to-service verification and replay protection.

---

## Supported Agent Flows

ZeroID covers every agentic deployment pattern — from a single autonomous agent to deep multi-agent chains spanning organizational boundaries.

| Flow | Grant Type | Human in the loop? | Description |
|------|-----------|-------------------|-------------|
| **Fully autonomous agent** | `api_key` | No | Agent acts entirely on its own. Token carries `sub` (agent WIMSE URI) and `owner` (who provisioned it). `act` is absent — no user delegated this action. |
| **Human authorizes once, agent runs autonomously** | `authorization_code` (PKCE) | At registration only | A human authenticates via OAuth and authorizes the agent once. Token carries `sub` (agent WIMSE URI), `owner` (provisioner), and `act.sub` (the authorizing user's ID). Agent runs autonomously from that point. |
| **Agent acting on behalf of a user** | `jwt_bearer` (RFC 7523) | No | Agent presents a user's JWT as proof of delegated authority. Token carries `sub` (agent WIMSE URI), `owner` (provisioner), and `act.sub` (the delegating user's ID). No user interaction at request time. |
| **Orchestrator → sub-agent delegation** | `token_exchange` (RFC 8693) | No | Orchestrator delegates a subset of its own scope to a sub-agent. Sub-agent proves its identity via a signed JWT assertion. ZeroID enforces scope intersection — sub-agent cannot receive more than the orchestrator holds. |
| **Multi-hop agent chain** | `token_exchange` chained | No | Sub-agent delegates further to a tool agent (depth 2), and so on. `delegation_depth` increments at each hop. `CredentialPolicy.max_delegation_depth` caps how far the chain can go. The full `act` claim chain is preserved at every level. |
| **Service-to-service (no user context)** | `client_credentials` | No | Agent authenticates as itself with no user association. Used for background jobs, scheduled tasks, and internal services where no human delegation chain exists. |
| **Long-running / async agent** | `refresh_token` | No | Agent refreshes its access token without re-authenticating. Used for agents executing multi-day workflows where the original access token would otherwise expire. |

**Revocation works across all flows.** A single `revoke` call on any token in a chain invalidates it and everything downstream, in real time.

---

## Quick Start

**Install the SDK:**

```bash
pip install highflame        # Python
npm install @highflame/zeroid   # Node / TypeScript
```

**Run ZeroID locally** (Docker — 30 seconds):

```bash
docker compose up -d
curl http://localhost:8899/health   # {"status":"ok"}
```

Or use `https://auth.highflame.ai` (hosted — [sign up free →](https://studio.highflame.ai/sign-up)).

**From source:**

```bash
make setup-keys           # generate ECDSA P-256 signing keys
docker compose up -d postgres
make run
```

---

## 5-Minute Tutorial

Examples use `http://localhost:8899`. Swap in `https://auth.highflame.ai` for hosted.

### 1. Connect

Point the client at your ZeroID instance. No credentials needed here — ZeroID's management API (`/api/v1/*`) is protected at the network layer by your infrastructure (API gateway, mTLS, allowlist). The token endpoints (`/oauth2/*`) are public.

```python
from highflame.zeroid import ZeroIDClient

client = ZeroIDClient(base_url="http://localhost:8899")
```

```typescript
import { ZeroIDClient } from "@highflame/zeroid";

const client = new ZeroIDClient({ baseUrl: "http://localhost:8899" });
```

### 2. Register an Agent

Before an agent can do anything, it needs an identity. Registration answers: *who is this agent, what role does it play, who created it, and how much should it be trusted?*

This call does two things atomically: it creates a persistent identity record (with a WIMSE/SPIFFE URI as a globally unique identifier) and issues a long-lived **API key** (`zid_sk_...`) that the agent will use to authenticate itself. Think of the API key as the agent's "password" — it proves ownership of the identity, but it never leaves your infrastructure and is only shown once.

```python
agent = client.agents.register(
    name="Task Orchestrator",
    external_id="orchestrator-1",   # your internal ID for this agent
    sub_type="orchestrator",        # role: orchestrator | autonomous | tool_agent | ...
    trust_level="first_party",      # how much to trust it: unverified | verified_third_party | first_party
    created_by="dev@company.com",   # stored as owner claim in every token this agent issues
)

print(agent.identity.wimse_uri)
# spiffe://auth.highflame.ai/acme/prod/agent/orchestrator-1
# ↑ stable, globally unique identity URI — carried in every token this agent issues

print(agent.api_key)
# zid_sk_...  ← save this securely, shown once
```

```typescript
const agent = await client.agents.register({
  name: "Task Orchestrator",
  external_id: "orchestrator-1",
  sub_type: "orchestrator",
  trust_level: "first_party",
  created_by: "dev@company.com",
});
// agent.identity.wimse_uri → "spiffe://..."  (persistent identity)
// agent.api_key            → "zid_sk_..."    (save securely, shown once)
```

### 3. Get an Access Token

The API key proves the agent's identity to ZeroID, but it's not what gets presented to downstream services. Instead, the agent exchanges its API key for a **short-lived JWT access token** (default: 1 hour). This is the token the agent attaches to every API call it makes.

Why this two-step design? The API key is long-lived and never leaves your system — it only ever talks to ZeroID. The JWT is short-lived, scoped to specific permissions, and safe to pass across service boundaries. If a JWT leaks, it expires. The API key stays secret.

```python
token = client.tokens.issue(
    grant_type="api_key",     # agent authenticates using its API key
    api_key=agent.api_key,    # proves ownership of the registered identity
    scope="data:read data:write",  # request only the permissions this task needs
)

print(token.access_token)  # eyJ...  ← present this to downstream APIs
print(token.expires_in)    # 3600 seconds (1 hour)

# The JWT carries full context — any service can verify these claims:
#   sub:              spiffe://auth.highflame.ai/acme/prod/agent/orchestrator-1
#   owner:            dev@company.com      ← who provisioned this agent
#   scope:            data:read data:write
#   delegation_depth: 0
#   act:              (absent)             ← no user delegated this action; fully autonomous
```

```typescript
const token = await client.tokens.issue({
  grant_type: "api_key",
  api_key: agent.api_key,
  scope: "data:read data:write",
});
// token.access_token → short-lived JWT to present to downstream services
// token.expires_in   → 3600
```

### 4. Delegate to a Sub-Agent

When an orchestrator needs a specialized agent to handle part of a task, it delegates a **subset of its own permissions** — it cannot grant more than it has. The sub-agent gets its own token with its own identity, but the full chain of who authorized what is preserved cryptographically.

This is the key difference from sharing credentials: the sub-agent has its own registered identity and its own keypair. It proves it holds that keypair by signing a short-lived JWT assertion (`actor_token`). ZeroID verifies both tokens and issues a delegated token that carries both identities.

```python
# Register the sub-agent — it has its own identity, separate from the orchestrator
sub_agent = client.agents.register(
    name="Data Fetcher",
    external_id="data-fetcher",
    sub_type="tool_agent",       # narrower role than the orchestrator
    trust_level="first_party",
)

# The sub-agent proves it holds its private key by signing a JWT assertion.
# This is what makes delegation secure — you can't impersonate an agent without its private key.
# zeroid CLI (coming soon): zeroid token assert --agent data-fetcher --key private.pem
actor_token = build_jwt_assertion(
    iss=sub_agent.identity.wimse_uri,
    sub=sub_agent.identity.wimse_uri,
    aud="https://auth.highflame.ai",
    private_key_pem=sub_agent_private_key,
)

# The orchestrator delegates data:read to the sub-agent.
# ZeroID enforces scope intersection: the sub-agent can only receive scopes
# the orchestrator already holds. Requesting more than that is silently capped.
delegated = client.tokens.issue(
    grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token=token.access_token,  # orchestrator's current token
    actor_token=actor_token,           # sub-agent's proof of identity
    scope="data:read",                 # subset of orchestrator's data:read data:write
)

# The delegated token carries the full chain:
#   sub:              spiffe://.../agent/data-fetcher   ← who is acting
#   owner:            ops@company.com                   ← who provisioned this agent
#   act.sub:          spiffe://.../agent/orchestrator-1 ← which agent delegated (RFC 8693)
#   scope:            data:read                         ← capped by intersection
#   delegation_depth: 1
#
# If a human user initiated the chain (e.g., via authorization_code), act.sub would be
# their user ID (e.g., bob@example.com) rather than an agent WIMSE URI.
```

### 5. Introspect — Verify the Full Chain

Any service that receives a ZeroID token can verify the full chain by calling introspect. This is how an MCP server, API gateway, or downstream tool answers: *"Is this token valid, who does it belong to, and on whose authority does it act?"*

```python
info = client.tokens.introspect(delegated.access_token)

print(info.active)   # True — token is valid and not revoked
print(info.sub)      # spiffe://auth.highflame.ai/acme/prod/agent/data-fetcher
# Full chain is readable from the token:
#   owner            → ops@company.com               (who provisioned this agent)
#   act.sub          → spiffe://.../orchestrator-1    (which agent delegated, or user ID if human-initiated)
#   delegation_depth → 1
#   trust_level      → first_party
```

```typescript
const info = await client.tokens.introspect(delegated.access_token);
// info.active → true/false
// info.sub    → agent's WIMSE URI
```

### 6. Revoke

Revocation is immediate and cascades. Revoke any token in the chain and everything downstream of it becomes invalid — no need to wait for expiry.

```python
# Revoke a specific token
client.tokens.revoke(delegated.access_token)
# → delegated token now returns active: false on introspect

# Revoke the orchestrator's token and the entire downstream chain collapses.
# This is how you respond to a compromise: one call, full containment.
client.tokens.revoke(token.access_token)
```

<details>
<summary>Using curl instead</summary>

```bash
# Register
curl -X POST http://localhost:8899/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Task Orchestrator","external_id":"orchestrator-1","sub_type":"orchestrator","trust_level":"first_party","created_by":"dev@company.com"}'

# Token
curl -X POST http://localhost:8899/oauth2/token \
  -d grant_type=api_key -d api_key=zid_sk_... -d "scope=data:read data:write"

# Delegate
curl -X POST http://localhost:8899/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=<orchestrator_token> \
  -d actor_token=<sub_agent_jwt_assertion> \
  -d scope=data:read

# Introspect
curl -X POST http://localhost:8899/oauth2/token/introspect -d token=eyJ...

# Revoke
curl -X POST http://localhost:8899/oauth2/token/revoke -d token=eyJ...
```

Full interactive API docs: `GET http://localhost:8899/docs`
</details>

---

## Real-World Patterns

### High-velocity agent with policy-based controls

A marketing optimization agent receives one instruction: *"Reallocate budget to maximize click-through rate."* It translates this into hundreds of API calls in seconds. Per-action consent is impossible at this velocity.

Define the agent's operational envelope upfront with a `CredentialPolicy`:

```python
policy = client.credential_policies.create(
    name="budget-optimizer-policy",
    allowed_scopes=["campaigns:read", "campaigns:write", "budget:reallocate"],
    max_ttl_seconds=3600,
    required_trust_level="first_party",
    max_delegation_depth=0,    # this agent cannot delegate further
)

agent = client.agents.register(
    name="Budget Optimizer",
    external_id="budget-optimizer-v1",
    sub_type="autonomous",
    trust_level="first_party",
    created_by="marketing-lead@company.com",
)
```

The agent operates autonomously within those bounds. The policy enforces least privilege at the authorization layer—no per-action approvals required.

### Human authorizes once, agent runs autonomously

```python
# Developer registers a coding agent once
agent = client.agents.register(
    name="Code Agent",
    external_id="code-agent-prod",
    sub_type="code_agent",
    trust_level="first_party",
    created_by="dev@company.com",   # ← becomes owner claim in every token this agent issues
)

# Agent operates fully autonomously from here.
# Every token carries:  sub = agent WIMSE URI,  owner = dev@company.com,  act = absent
# act is absent because no user delegated this specific action — the agent is acting on its own.
token = client.tokens.issue(grant_type="api_key", api_key=agent.api_key, scope="repo:write")
info  = client.tokens.introspect(token.access_token)
# info.sub          → spiffe://.../agent/code-agent-prod
# info.extra["owner"] → dev@company.com
# info.extra["act"]   → None  (fully autonomous — no user delegation)
```

### Autonomous agent chain (no human in the loop)

```python
# Cap delegation depth on the monitoring agent's policy — chain can go no deeper than 2
policy = client.credential_policies.create(
    name="sec-monitor-policy",
    max_delegation_depth=2,
    allowed_scopes=["alerts:read", "logs:read", "remediation:write"],
)

# When the monitoring agent detects an anomaly, it delegates to an investigator...
# The investigator delegates to a remediator (depth 2 — can't delegate further).
# Revoke the monitoring agent and the entire chain collapses immediately:
client.tokens.revoke(monitoring_agent_token)
```

Every token in the chain carries the full `act` claim, traceable back to the org policy.

### MCP tool boundary

```python
# In your MCP server — verify ZeroID token before executing any tool
def verify_agent_token(bearer_token: str) -> bool:
    info = client.tokens.introspect(bearer_token)
    if not info.active:
        return False
    if info.extra.get("delegation_depth", 0) > MAX_ALLOWED_DEPTH:
        return False
    if info.extra.get("trust_level") not in ("verified_third_party", "first_party"):
        return False
    return True
```

Anonymous agents, revoked credentials, and agents that exceeded their delegation depth are all rejected before any tool executes.

---

## Architecture

```mermaid
graph TD
    subgraph ZEROID ["ZeroID"]
        direction TB
        IR[Identity Registry] --> CS[Credential Service<br/><i>ES256 signing · Policy enforcement · Audit</i>]
        OG[OAuth2 Grants<br/><i>client_credentials · jwt_bearer · api_key<br/>authorization_code · refresh_token</i>] --> CS
        DL[Delegation Engine<br/><i>RFC 8693 token_exchange</i>] --> CS

        CS --> AT[Attestation]
        CS --> CAE[CAE Signals<br/><i>Real-time revocation</i>]
        CS --> WPT[WIMSE Proof Tokens<br/><i>Single-use, nonce-bound</i>]

        AT --> DB[(PostgreSQL)]
        CAE --> DB
        WPT --> DB
        CS --> DB
    end

    Agent([AI Agent]) -- "api_key / jwt_bearer" --> OG
    Orchestrator([Orchestrator]) -- "token_exchange" --> DL
    SDK([SDK / CLI]) -- "authorization_code" --> OG
    Downstream([MCP Server / Tool]) -- "introspect / verify" --> WPT

    style ZEROID fill:#1a1a2e,stroke:#e94560,stroke-width:3px,color:#fff
    style CS fill:#2d6a4f,color:#fff
    style DB fill:#264653,color:#fff
    style Agent fill:#e76f51,color:#fff
    style Orchestrator fill:#e76f51,color:#fff
    style SDK fill:#e9c46a,color:#000
    style Downstream fill:#457b9d,color:#fff
```

**Token characteristics:**

| Flow | Algorithm | Default TTL | Subject |
|------|-----------|-------------|---------|
| Agent (`api_key` / `jwt_bearer`) | ES256 | 1 hour | WIMSE URI |
| Delegated (`token_exchange`) | ES256 | 1 hour | Sub-agent WIMSE URI + `act` claim |
| SDK / CLI (`authorization_code`) | RS256 | 90 days | User ID |

---

## Configuration

```yaml
server:
  port: "8899"

database:
  url: "postgres://zeroid:zeroid@localhost:5432/zeroid?sslmode=disable"

keys:
  ecdsa_private_key_path: "keys/private.pem"
  ecdsa_public_key_path:  "keys/public.pem"
  # Optional: RSA keys for RS256 tokens (SDK/CLI)
  # rsa_private_key_path: "keys/rsa_private.pem"
  # rsa_public_key_path:  "keys/rsa_public.pem"

token:
  issuer:      "https://auth.highflame.ai"
  default_ttl: 3600

wimse_domain: "auth.highflame.ai"
```

Environment variables override YAML (prefix `ZEROID_`):

```bash
ZEROID_DATABASE_URL=postgres://...
ZEROID_TOKEN_ISSUER=https://auth.example.com
ZEROID_WIMSE_DOMAIN=example.com
ZEROID_ECDSA_PRIVATE_KEY_PATH=keys/private.pem
ZEROID_ECDSA_PUBLIC_KEY_PATH=keys/public.pem
```

---

## Embedding as a Go Library

```go
import zeroid "github.com/highflame-ai/zeroid"

cfg, _ := zeroid.LoadConfig("")
srv, _ := zeroid.NewServer(cfg)

// Protect admin routes with custom auth
srv.AdminAuth(func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("X-Admin-Key") != "secret" {
            http.Error(w, "unauthorized", 401)
            return
        }
        next.ServeHTTP(w, r)
    })
})

// Enrich JWT claims at issuance
srv.OnClaimsIssue(func(claims map[string]any, id *domain.Identity, gt domain.GrantType) {
    claims["gateway_id"] = "gw-123"
})

log.Fatal(srv.Start())
```

---

## API Reference

### Public (no auth required)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| GET | `/.well-known/jwks.json` | JWKS public keys |
| GET | `/.well-known/oauth-authorization-server` | OAuth2 server metadata |
| POST | `/oauth2/token` | Issue token (6 grant types) |
| POST | `/oauth2/token/introspect` | Token introspection (RFC 7662) |
| POST | `/oauth2/token/revoke` | Token revocation (RFC 7009) |

### Admin (`/api/v1/*` — protect at network layer)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/agents/register` | Register agent (identity + credential, atomic) |
| GET | `/api/v1/agents/registry` | List agents |
| GET | `/api/v1/agents/registry/{id}` | Get agent |
| PATCH | `/api/v1/agents/registry/{id}` | Update agent |
| DELETE | `/api/v1/agents/registry/{id}` | Deactivate agent |
| POST | `/api/v1/identities` | Register identity (manual) |
| GET | `/api/v1/identities/{id}` | Get identity |
| PATCH | `/api/v1/identities/{id}` | Update identity |
| DELETE | `/api/v1/identities/{id}` | Deactivate identity |
| GET | `/api/v1/identities` | List identities |
| POST | `/api/v1/oauth/clients` | Register OAuth2 client |
| POST | `/api/v1/api-keys` | Create API key |
| POST | `/api/v1/credential-policies` | Create credential policy |
| GET | `/api/v1/credential-policies/{id}` | Get credential policy |
| PATCH | `/api/v1/credential-policies/{id}` | Update credential policy |
| POST | `/api/v1/credentials/{id}/revoke` | Revoke credential |
| POST | `/api/v1/attestations` | Submit attestation |
| POST | `/api/v1/signals/ingest` | Ingest CAE signal |
| GET | `/api/v1/signals/stream` | SSE signal stream |
| POST | `/api/v1/proofs/generate` | Generate WIMSE proof token |
| POST | `/api/v1/proofs/verify` | Verify WIMSE proof token |

Full interactive docs at `GET /docs` when running.

---

## Standards

ZeroID implements the complete stack the for production agent identity systems. No proprietary protocols.  
References: [OpenID Agentic AI](https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf)

| Standard | RFC / Spec | Used For |
|----------|-----------|----------|
| OAuth 2.1 | RFC 6749 + BCP | Foundational auth framework |
| JWT Profile for OAuth 2.0 | RFC 7523 | Agent JWT assertions (`jwt_bearer`) |
| OAuth 2.0 Token Exchange | RFC 8693 | Agent-to-agent delegation, `act` claim |
| Token Introspection | RFC 7662 | Credential status verification |
| Token Revocation | RFC 7009 | Credential revocation |
| PKCE | RFC 7636 | Authorization code flow |
| JSON Web Tokens | RFC 7519 | Token format |
| JSON Web Key Sets | RFC 7517 | Public key distribution |
| WIMSE / SPIFFE | IETF Draft | Agent workload identity URIs |
| Shared Signals Framework (SSF) | OpenID SSF | Real-time revocation event propagation |
| CAEP | OpenID CAEP | Continuous access evaluation signals |

---

## Roadmap

- SDKs ([Python](https://github.com/highflame-ai/highflame-sdk/tree/main/python), [TypeScript](https://github.com/highflame-ai/highflame-sdk/tree/main/javascript), [RUST](https://github.com/highflame-ai/highflame-sdk/tree/main/rust))
- CIBA (Client-Initiated Backchannel Authentication) for async human-in-the-loop approvals — agents pause long-running workflows and request out-of-band user authorization without blocking
- Human-in-the-loop approval workflow (`/api/v1/approvals`)
- Ecosystem integrations (langgraph, crewai...)
- MCP server middleware
- `zeroid` CLI 

---

## Community

**Discord**: [Join the ZeroID community](https://discord.gg/zeroid) — the fastest way to get help, share what you're building, and shape the roadmap.

**ZeroID Working Group**: We are forming a working group of practitioners building agent infrastructure at scale. If you are deploying agents in production and have opinions on how identity should work, [reach out](mailto:zeroid@highflame.ai).

**GitHub Discussions**: Use [Discussions](https://github.com/highflame-ai/zeroid/discussions) for design questions, RFC proposals, and integration patterns.

**Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues are labeled [`good-first-issue`](https://github.com/highflame-ai/zeroid/issues?q=label%3Agood-first-issue).

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

*ZeroID is open source infrastructure from [Highflame](https://highflame.ai) — the Agent Control Platform for enterprise AI.*
