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

When an AI agent takes an action, commits code, calls an API, modifies a record etc., the question every security and compliance team asks is:

> *"Which agent did this, acting on whose authority, with what permissions?"*

Existing auth systems were built for humans. Service accounts don't capture delegation chains. OAuth/OIDC tokens don't model agent-to-agent trust. There is no standard answer to that question today.

We attempt to answer this question with: **ZeroID**

## What Is ZeroID

ZeroID is identity infrastructure for autonomous agents—a system that issues credentials, delegates trust between agents, and revokes access in real time. Built on OAuth 2.1 and WIMSE/SPIFFE, it answers the question of who an agent is and on whose authority it acts.

In practice: each agent receives a cryptographically verifiable identity with a defined scope and lifecycle. When one agent delegates to another, the full chain is captured: who authorized it, what scope was granted, and how deep the delegation goes. Tokens carry operational context; every action is attributable.

**The mental model:**

```
Root authority (human, policy, or orchestrator agent) authorizes Agent A
        ↓
Agent A gets a scoped credential
        ↓
Agent A delegates a subset of its scope to Agent B (RFC 8693)
        ↓
Agent B's token carries: its own identity + delegation chain + original authorizer
        ↓
Any system Agent B calls can verify the full chain cryptographically
```

The root can be a human, org policy, or another agent—so fully autonomous workflows work without anyone in the loop.

## Why Not OAuth/OIDC or Service Accounts?

|  | Service Accounts | OAuth/OIDC | ZeroID |
|---|---|---|---|
| Per-agent identity | ❌ Shared | ✅ | ✅ |
| Agent-to-agent delegation | ❌ | ❌ | ✅ RFC 8693 |
| Delegation depth enforcement | ❌ | ❌ | ✅ |
| Human-to-agent chain | ❌ | Partial | ✅ |
| Real-time revocation | ❌ | ❌ | ✅ CAE signals |
| Built for autonomous workflows | ❌ | ❌ | ✅ |

OAuth/OIDC was designed for a human authenticating to a service. ZeroID is designed for agents that act autonomously across multi-step workflows, delegate to sub-agents dynamically, and need to be governed, not just authenticated.

## Features

- **Agent Identity Registry** — Register agents, MCP servers, services, and applications. Classify by role (`orchestrator`, `autonomous`, `tool_agent`), assign trust levels, and manage full lifecycle.
- **OAuth 2.1 Token Issuance** — Full OAuth 2.1 support: `client_credentials`, `jwt_bearer` (RFC 7523), `token_exchange` (RFC 8693) for delegation, `api_key`, `authorization_code` (PKCE), `refresh_token`.
- **Agent-to-Agent Delegation** — RFC 8693 token exchange with automatic scope intersection, delegation depth tracking, and cascade revocation when an upstream credential is revoked.
- **WIMSE/SPIFFE URIs** — Stable, globally unique identity URIs: `spiffe://{domain}/{account}/{project}/{type}/{id}` for every agent.
- **Credential Policies** — Governance templates that enforce TTL, allowed grant types, required trust levels, and max delegation depth.
- **Continuous Access Evaluation (CAE)** — Revoke credentials in real time when risk signals fire (compromise, policy change, or custom events).
- **Attestation Framework** — Software, platform, and hardware attestation to bootstrap or elevate trust levels before credentials are issued.
- **WIMSE Proof Tokens** — Single-use, nonce-bound tokens for service-to-service verification and replay protection.

---

## Quick Start

### Docker (30 seconds)

```bash
docker compose up -d
```

ZeroID starts on `http://localhost:8899` with Postgres provisioned automatically.

```bash
curl http://localhost:8899/health
# {"status":"ok"}
```

### From Source

```bash
make setup-keys           # generate ECDSA P-256 signing keys
docker compose up -d postgres
make run
```

---

## 5-Minute Tutorial 
Use base URL http://localhost:8899 if running locally or https://auth.highflame.ai for [SaaS](https://studio.highflame.ai/sign-up)

### 1. Register an Agent (atomic: identity + credential in one call)

```bash
curl -X POST http://auth.highflame.ai/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "name":           "Task Orchestrator",
    "external_id":    "orchestrator-1",
    "sub_type":       "orchestrator",
    "trust_level":    "first_party",
    "allowed_scopes": ["data:read", "data:write"],
    "created_by":     "user@company.com"
  }'

# Returns:
# {
#   "identity": { "id": "...", "wimse_uri": "spiffe://auth.highflame.ai/acme/prod/agent/orchestrator-1" },
#   "credential": "zid_sk_..."    ← save this, shown once
# }
```

### 2. Get an Access Token

```bash
curl -X POST http://auth.highflame.ai/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "api_key",
    "api_key":    "zid_sk_...",
    "scope":      "data:read data:write"
  }'

# Returns:
# {
#   "access_token": "eyJ...",
#   "token_type":   "Bearer",
#   "expires_in":   3600
# }
#
# Token claims include:
#   sub:              spiffe://auth.highflame.ai/acme/prod/agent/orchestrator-1
#   zeroid_user_id:   user@company.com    ← human authorization propagated
#   scope:            data:read data:write
#   delegation_depth: 0
```

### 3. Delegate to a Sub-Agent (RFC 8693 token exchange)

Delegation requires the sub-agent to have its own registered identity and keypair. The orchestrator presents its active token (`subject_token`); the sub-agent proves its identity via a self-signed JWT assertion (`actor_token`).

```bash
# 3a. Generate a P-256 keypair for the sub-agent
openssl ecparam -name prime256v1 -genkey -noout -out sub_agent_private.pem
openssl ec -in sub_agent_private.pem -pubout -out sub_agent_public.pem

# 3b. Register the sub-agent with its public key
curl -X POST http://auth.highflame.ai/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d "{
    \"name\":           \"Data Fetcher\",
    \"external_id\":    \"data-fetcher\",
    \"sub_type\":       \"tool_agent\",
    \"trust_level\":    \"first_party\",
    \"allowed_scopes\": [\"data:read\"],
    \"public_key_pem\":  \"$(cat sub_agent_public.pem | tr '\n' '|' | sed 's/|/\\n/g')\"
  }"

# 3c. Sub-agent generates a self-signed JWT assertion (actor_token)
# The assertion proves the sub-agent holds the private key.
# iss and sub must equal the sub-agent's WIMSE URI.
# aud must equal the ZeroID token issuer.
#
# Using the zeroid CLI (coming soon):
#   zeroid token assert --agent data-fetcher --key sub_agent_private.pem
#
# Or manually — sign this payload with sub_agent_private.pem (ES256):
# {
#   "iss": "spiffe://auth.highflame.ai/acme/prod/agent/data-fetcher",
#   "sub": "spiffe://auth.highflame.ai/acme/prod/agent/data-fetcher",
#   "aud": "https://auth.highflame.ai",
#   "exp": <now + 60>,
#   "jti": "<unique-id>"
# }

# 3d. Exchange tokens — orchestrator delegates data:read to sub-agent
curl -X POST http://auth.highflame.ai/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<orchestrator_access_token>",
    "actor_token":   "<sub_agent_jwt_assertion>",
    "scope":         "data:read"
  }'

# Returns token with:
#   sub:              spiffe://auth.highflame.ai/acme/prod/agent/data-fetcher
#   act.sub:          spiffe://auth.highflame.ai/acme/prod/agent/orchestrator-1
#   scope:            data:read    ← intersection of all three scope sets
#   delegation_depth: 1
#   zeroid_user_id:   user@company.com    ← propagated from orchestrator
```

### 4. Introspect — Verify the Full Chain

```bash
curl -X POST http://auth.highflame.ai/oauth2/token/introspect \
  -H "Content-Type: application/json" \
  -d '{"token": "<delegated_jwt>"}'

# {
#   "active":           true,
#   "sub":              "spiffe://auth.highflame.ai/acme/prod/agent/data-fetcher",
#   "act":              {"sub": "spiffe://auth.highflame.ai/acme/prod/agent/orchestrator-1"},
#   "scope":            "data:read",
#   "delegation_depth": 1,
#   "trust_level":      "first_party",
#   "zeroid_user_id":   "user@company.com",
#   "exp":              1742240400
# }
```

### 5. Revoke

```bash
curl -X POST http://auth.highflame.ai/oauth2/token/revoke \
  -H "Content-Type: application/json" \
  -d '{"token": "<jwt>"}'
# 200 OK — always succeeds per RFC 7009
# Token immediately fails introspection with active: false
```

---

## Real-World Patterns

Common deployment patterns and how ZeroID handles them:

### Autonomous agent chain (no human in the loop)

A security monitoring agent detects an anomaly and delegates to an investigation agent, which delegates to a remediation agent. `CredentialPolicy` caps `delegation_depth` at 2 — the remediation agent cannot delegate further. Every token and audit log entry carries the full chain, traceable back to the org policy that authorized it.

### Human authorizes once, agent runs autonomously

A developer registers a coding agent with `created_by="dev@company.com"`. The agent gets its own credential and operates autonomously — the developer is out of the auth flow after registration. Every token carries `zeroid_user_id: dev@company.com`, so PR metadata, audit logs, and introspection all surface the human who authorized the chain.

### MCP tool boundary

An MCP server requires a ZeroID token before executing any tool. It verifies the calling agent's identity, scope, and delegation depth at the boundary — before any action runs.

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

| Standard | RFC | Used For |
|----------|-----|----------|
| OAuth 2.0 Client Credentials | 6749 §4.4 | Machine-to-machine auth |
| JWT Profile for OAuth 2.0 | 7523 | Agent JWT assertions |
| OAuth 2.0 Token Exchange | 8693 | Agent-to-agent delegation |
| Token Introspection | 7662 | Credential status |
| Token Revocation | 7009 | Revocation |
| PKCE | 7636 | Authorization code flow |
| JSON Web Tokens | 7519 | Token format |
| JSON Web Key Sets | 7517 | Public key distribution |
| WIMSE/SPIFFE | IETF Draft | Agent identity URIs |
| CAEP | OpenID CAEP | Real-time revocation signals |

---

## Roadmap

- [ ] Python SDK (`pip install highflame`)
- [ ] TypeScript SDK (`npm install @highflame/zeroid`)
- [ ] Human-in-the-loop approval workflow (`/api/v1/approvals`)
- [ ] LangGraph integration
- [ ] CrewAI integration
- [ ] MCP server middleware
- [ ] `zeroid` CLI for local development

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
