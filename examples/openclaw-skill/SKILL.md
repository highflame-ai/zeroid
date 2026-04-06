---
name: zeroid
description: Identity infrastructure for AI agents — register identities, issue tokens, delegate to sub-agents, revoke credentials, manage policies
version: 1.0.0
metadata:
  openclaw:
    requires:
      env:
        - ZEROID_API_KEY
        - ZEROID_BASE_URL
      bins:
        - curl
    primaryEnv: ZEROID_API_KEY
    emoji: 🔐
    homepage: https://github.com/highflame-ai/zeroid
---

# ZeroID — Identity Infrastructure for AI Agents

ZeroID is open-source identity infrastructure for autonomous AI agents. It assigns agents SPIFFE-based identities (WIMSE URIs), issues OAuth 2.1 tokens, supports delegation chains via RFC 8693 token exchange, and manages credential policies. All operations use the REST API at `$ZEROID_BASE_URL`.

## Authentication

All `/api/v1/*` endpoints require an API key passed via the `Authorization` header:

```
Authorization: Bearer $ZEROID_API_KEY
```

The `/oauth2/*` and `/health` endpoints are public (no auth required).

---

## 1. Register an Agent

Create an agent identity with a WIMSE/SPIFFE URI and receive an API key. This is the recommended way to onboard agents — it atomically creates the identity record and issues a long-lived API key (`zid_sk_...`).

```bash
curl -s -X POST "$ZEROID_BASE_URL/api/v1/agents/register" \
  -H "Authorization: Bearer $ZEROID_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Task Orchestrator",
    "external_id": "orchestrator-1",
    "sub_type": "orchestrator",
    "trust_level": "first_party",
    "created_by": "dev@company.com"
  }'
```

**Response (201 Created):**

```json
{
  "identity": {
    "id": "uuid",
    "external_id": "orchestrator-1",
    "wimse_uri": "spiffe://auth.highflame.ai/acme/prod/agent/orchestrator-1"
  },
  "api_key": "zid_sk_..."
}
```

The `sub_type` field classifies the agent role: `orchestrator`, `autonomous`, `tool_agent`, `code_agent`, etc. The `trust_level` controls what grants and scopes the agent can access: `unverified`, `verified_third_party`, `first_party`.

To register a bare identity without an API key (for manual credential management):

```bash
curl -s -X POST "$ZEROID_BASE_URL/api/v1/identities" \
  -H "Authorization: Bearer $ZEROID_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "external_id": "data-fetcher-1",
    "trust_level": "unverified",
    "owner_user_id": "user-ops",
    "allowed_scopes": ["data:read", "data:write"]
  }'
```

---

## 2. Issue Credentials

Exchange OAuth2 client credentials for a short-lived JWT access token. First register an OAuth2 client, then use `client_credentials` grant.

**Register an OAuth2 client:**

```bash
curl -s -X POST "$ZEROID_BASE_URL/api/v1/oauth/clients" \
  -H "Authorization: Bearer $ZEROID_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-agent-client",
    "name": "my-agent-client",
    "confidential": true,
    "grant_types": ["client_credentials"],
    "scopes": ["data:read", "data:write"]
  }'
```

**Response (201 Created):**

```json
{
  "client": {
    "client_id": "my-agent-client"
  },
  "client_secret": "..."
}
```

**Issue a token via client_credentials:**

```bash
curl -s -X POST "$ZEROID_BASE_URL/oauth2/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "my-agent-client",
    "client_secret": "<client_secret>",
    "scope": "data:read"
  }'
```

**Response (200 OK):**

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "data:read"
}
```

ZeroID also supports `api_key`, `jwt_bearer` (RFC 7523), `authorization_code` (PKCE), and `refresh_token` grant types via the same `/oauth2/token` endpoint.

---

## 3. Delegate to Sub-Agent

Use RFC 8693 token exchange to delegate a subset of the orchestrator's permissions to a sub-agent. Scope is automatically attenuated — the sub-agent can only receive scopes the parent already holds.

```bash
curl -s -X POST "$ZEROID_BASE_URL/oauth2/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<orchestrator_access_token>",
    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "actor_token": "<sub_agent_jwt_assertion>",
    "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "scope": "data:read"
  }'
```

**Response (200 OK):**

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "expires_in": 3600,
  "scope": "data:read"
}
```

The delegated token carries the full chain: `sub` is the sub-agent's WIMSE URI, `act.sub` is the delegating agent's WIMSE URI, and `delegation_depth` increments at each hop. The `actor_token` is a self-signed ES256 JWT assertion proving the sub-agent holds its private key.

Multi-hop delegation is supported — a sub-agent can delegate further to a tool agent. `CredentialPolicy.max_delegation_depth` caps how deep the chain can go.

---

## 4. Revoke Credentials

Revoke a credential immediately. Revocation cascades — revoking an orchestrator's credential invalidates all downstream delegated tokens in the chain.

```bash
curl -s -X POST "$ZEROID_BASE_URL/api/v1/credentials/{credential_id}/revoke" \
  -H "Authorization: Bearer $ZEROID_API_KEY" \
  -H "Content-Type: application/json"
```

**Response (200 OK):**

```json
{
  "revoked": true,
  "id": "uuid"
}
```

You can also revoke a token directly via the OAuth2 revocation endpoint (RFC 7009):

```bash
curl -s -X POST "$ZEROID_BASE_URL/oauth2/token/revoke" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<access_token>"
  }'
```

To deactivate an entire agent (revokes all its tokens):

```bash
curl -s -X DELETE "$ZEROID_BASE_URL/api/v1/agents/registry/{agent_id}" \
  -H "Authorization: Bearer $ZEROID_API_KEY"
```

---

## 5. Credential Policies

Create governance templates that enforce TTL limits, allowed grant types, required trust levels, and maximum delegation depth. Policies are assigned to API keys and enforced at token issuance time.

```bash
curl -s -X POST "$ZEROID_BASE_URL/api/v1/credential-policies" \
  -H "Authorization: Bearer $ZEROID_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "restricted-agent-policy",
    "description": "Policy for restricted tool agents",
    "max_ttl_seconds": 1800,
    "allowed_grant_types": ["api_key", "client_credentials"],
    "allowed_scopes": ["data:read", "tools:read"],
    "required_trust_level": "first_party",
    "max_delegation_depth": 1
  }'
```

**Response (201 Created):**

```json
{
  "id": "uuid",
  "name": "restricted-agent-policy",
  "max_ttl_seconds": 1800,
  "allowed_grant_types": ["api_key", "client_credentials"],
  "allowed_scopes": ["data:read", "tools:read"],
  "required_trust_level": "first_party",
  "max_delegation_depth": 1,
  "is_active": true
}
```

**Get a policy:**

```bash
curl -s "$ZEROID_BASE_URL/api/v1/credential-policies/{policy_id}" \
  -H "Authorization: Bearer $ZEROID_API_KEY"
```

**Update a policy:**

```bash
curl -s -X PATCH "$ZEROID_BASE_URL/api/v1/credential-policies/{policy_id}" \
  -H "Authorization: Bearer $ZEROID_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "max_delegation_depth": 3
  }'
```

---

## 6. Health Check

Verify the ZeroID server is running and healthy. No authentication required.

```bash
curl -s "$ZEROID_BASE_URL/health"
```

**Response (200 OK):**

```json
{
  "status": "healthy",
  "service": "zeroid",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

Readiness check (includes database connectivity):

```bash
curl -s "$ZEROID_BASE_URL/ready"
```

---

## Additional Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/agents/registry` | List all registered agents |
| GET | `/api/v1/agents/registry/{id}` | Get agent details |
| PATCH | `/api/v1/agents/registry/{id}` | Update agent metadata |
| GET | `/api/v1/identities/{id}` | Get identity by ID |
| GET | `/api/v1/identities` | List identities |
| POST | `/oauth2/token/introspect` | Introspect a token (RFC 7662) |
| GET | `/oauth2/token/verify` | Forward-auth endpoint for reverse proxies |
| GET | `/.well-known/jwks.json` | JWKS public keys for local verification |
| GET | `/.well-known/oauth-authorization-server` | OAuth2 server metadata |
| POST | `/api/v1/attestations` | Submit attestation evidence |
| POST | `/api/v1/proofs/generate` | Generate WIMSE proof token |
| POST | `/api/v1/proofs/verify` | Verify WIMSE proof token |
| POST | `/api/v1/signals/ingest` | Ingest CAE signal for continuous access evaluation |

## Resources

- [ZeroID GitHub](https://github.com/highflame-ai/zeroid)
- [Quickstart Notebook](https://github.com/highflame-ai/zeroid/blob/main/examples/zeroid_quickstart.ipynb)
- [Interactive API docs](https://auth.highflame.ai/docs) (or `GET /docs` when running locally)
