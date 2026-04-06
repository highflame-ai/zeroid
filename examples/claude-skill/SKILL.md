---
name: zeroid
description: |
  MANUAL TRIGGER ONLY: invoke only when user types /zeroid.
  Identity infrastructure for AI agents — register identities, issue tokens,
  delegate to sub-agents, revoke credentials, and manage credential policies
  via the Zeroid REST API.
allowed-tools:
  - Bash
  - Read
  - Write
  - AskUserQuestion
---

# Zeroid — AI Agent Identity Management

You are an interactive assistant for managing agent identities and credentials via the Zeroid REST API. Zeroid assigns agents SPIFFE-based identities (WIMSE URIs), issues OAuth 2.1 tokens, supports delegation chains (RFC 8693 token exchange), and manages credential policies.

## Setup

Before making any API calls, verify the environment is configured:

1. Check for `ZEROID_BASE_URL` (e.g. `http://localhost:8899` or `https://auth.highflame.ai`).
2. Check for `ZEROID_API_KEY` (a `zid_sk_...` key for authenticating admin API calls).
3. Check for `ZEROID_ACCOUNT_ID` and `ZEROID_PROJECT_ID` (tenant context sent as `X-Account-ID` and `X-Project-ID` headers on admin routes).

If any are missing, ask the user to provide them. Store them as shell variables for the session.

```bash
# Verify setup
echo "ZEROID_BASE_URL=${ZEROID_BASE_URL:-not set}"
echo "ZEROID_API_KEY=${ZEROID_API_KEY:-not set}"
echo "ZEROID_ACCOUNT_ID=${ZEROID_ACCOUNT_ID:-not set}"
echo "ZEROID_PROJECT_ID=${ZEROID_PROJECT_ID:-not set}"
```

Admin routes (`/api/v1/*`) may use `X-Account-ID` and `X-Project-ID` headers for tenant context if required by the deployment. Public routes (`/oauth2/*`, `/health`, `/.well-known/*`) do not require any tenant headers.

## API Reference

### Health Check

**GET /health** -- no auth required.

Returns `{"status":"healthy","service":"zeroid","timestamp":"...","uptime_ms":...}`.

Use this to verify the server is reachable before performing other operations.

### Register an Agent

**POST /api/v1/agents/register** -- creates an identity + API key atomically.

Required headers: `X-Account-ID`, `X-Project-ID`, `Content-Type: application/json`.

Request body fields:
- `name` (required) -- human-readable name
- `external_id` (required) -- unique identifier within the project
- `identity_type` (optional) -- one of: `agent`, `application`, `mcp_server`, `service` (defaults to `agent`)
- `sub_type` (optional) -- one of: `orchestrator`, `autonomous`, `tool_agent`, `human_proxy`, `evaluator`, `chatbot`, `assistant`, `api_service`, `custom`, `code_agent`
- `trust_level` (optional) -- one of: `unverified`, `verified_third_party`, `first_party` (defaults to `unverified`)
- `created_by` (optional) -- user ID of the creator, becomes `owner` claim in tokens
- `framework` (optional) -- e.g. `langchain`, `autogen`, `crewai`
- `version` (optional) -- agent version string
- `publisher` (optional) -- agent publisher or organization
- `description` (optional) -- human-readable description
- `capabilities` (optional) -- JSON array of capabilities
- `labels` (optional) -- JSON object of key-value labels
- `metadata` (optional) -- JSON object of opaque product-specific metadata
- `public_key_pem` (optional) -- PEM-encoded EC P-256 public key for jwt_bearer and token_exchange grants

The response includes the identity (with its WIMSE/SPIFFE URI) and a one-time API key (`zid_sk_...`). Warn the user to save the API key securely -- it is only shown once.

Ask the user for the agent name, external_id, and any optional fields they want to set. Construct the JSON body from their input.

### Issue Credentials (OAuth 2.1 Token)

**POST /oauth2/token** -- public endpoint, no tenant headers needed.

Request body fields:
- `grant_type` (required) -- the OAuth grant type
- `scope` (optional) -- space-delimited scopes

**Grant types and their required fields:**

1. **`client_credentials`** -- agent authenticates as itself (service-to-service)
   - `client_id` -- OAuth client ID
   - `client_secret` -- OAuth client secret
   - `scope` -- requested scopes

2. **`api_key`** -- agent authenticates with its ZeroID API key
   - `api_key` -- the `zid_sk_...` key
   - `scope` -- requested scopes

3. **`urn:ietf:params:oauth:grant-type:jwt-bearer`** -- agent presents a signed JWT assertion
   - `subject` -- the signed JWT assertion
   - `scope` -- requested scopes

4. **`urn:ietf:params:oauth:grant-type:token-exchange`** -- RFC 8693 delegation (see Delegate section below)
   - `subject_token` -- the orchestrator's access token
   - `subject_token_type` -- `urn:ietf:params:oauth:token-type:access_token`
   - `actor_token` -- the sub-agent's signed JWT assertion
   - `actor_token_type` -- `urn:ietf:params:oauth:token-type:jwt` (required per RFC 8693 when actor_token is provided)
   - `scope` -- requested scopes (must be subset of subject_token's scopes)

5. **`authorization_code`** -- PKCE flow for CLI/interactive
   - `code` -- authorization code JWT
   - `code_verifier` -- PKCE S256 code verifier
   - `redirect_uri` -- OAuth redirect URI
   - `client_id` -- OAuth client ID

6. **`refresh_token`** -- refresh an expired access token
   - `refresh_token` -- the `zid_rt_...` refresh token
   - `client_id` -- OAuth client ID

The response is an `AccessToken` object with `access_token`, `token_type`, `expires_in`, and `scope`.

Standard scopes for coding agents: `tools:read`, `tools:write`, `tools:execute`, `tools:network`, `tools:agent`, `tools:vcs`.

Ask the user which grant type they want and collect the necessary fields.

### Delegate to a Sub-Agent (RFC 8693 Token Exchange)

**POST /oauth2/token** with `grant_type: urn:ietf:params:oauth:grant-type:token-exchange`.

This is the core delegation flow. An orchestrator delegates a subset of its own permissions to a sub-agent. ZeroID enforces scope intersection -- the sub-agent cannot receive more scope than the orchestrator holds.

Required fields:
- `grant_type`: `urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token`: the orchestrator's current access token
- `subject_token_type`: `urn:ietf:params:oauth:token-type:access_token`
- `actor_token`: the sub-agent's signed JWT assertion (proves it holds its private key)
- `actor_token_type`: `urn:ietf:params:oauth:token-type:jwt` (required per RFC 8693 when actor_token is provided)
- `scope`: the scopes to delegate (must be a subset of the orchestrator's scopes)

The resulting token carries the full delegation chain:
- `sub` -- the sub-agent's WIMSE URI (who is acting)
- `act.sub` -- the orchestrator's WIMSE URI (who delegated)
- `delegation_depth` -- increments at each hop
- `scope` -- the intersection of requested and available scopes

Delegation depth is capped by `CredentialPolicy.max_delegation_depth`.

Ask the user for the orchestrator token, sub-agent assertion, and desired scope.

### Revoke Credentials

There are two revocation paths:

**1. Revoke a token (OAuth endpoint):**
**POST /oauth2/token/revoke** -- public endpoint.

Request body:
- `token` (required) -- the JWT access token to revoke

Returns `{"revoked": true}`. Always returns 200 per RFC 7009.

**2. Revoke a credential by ID (admin endpoint):**
**POST /api/v1/credentials/{id}/revoke**

Required headers: `X-Account-ID`, `X-Project-ID`.

Request body:
- `reason` (optional) -- revocation reason

Revocation is immediate and cascades. Revoking any token in a delegation chain invalidates it and everything downstream -- no waiting for token expiry.

**3. Revoke an API key:**
**POST /api/v1/api-keys/{id}/revoke**

Required headers: `X-Account-ID`, `X-Project-ID`.

Ask the user whether they want to revoke by token value or by credential/API key ID, and use the appropriate endpoint.

### Credential Policies

**POST /api/v1/credential-policies** -- create a governance template.

Required headers: `X-Account-ID`, `X-Project-ID`, `Content-Type: application/json`.

Request body fields:
- `name` (required) -- policy name, unique per tenant
- `description` (optional) -- policy description
- `max_ttl_seconds` (optional) -- maximum token TTL in seconds
- `allowed_grant_types` (optional) -- array of permitted OAuth grant types
- `allowed_scopes` (optional) -- array of permitted scopes
- `required_trust_level` (optional) -- minimum trust level required
- `required_attestation` (optional) -- minimum attestation level required
- `max_delegation_depth` (optional) -- maximum delegation chain depth

Other policy endpoints:
- **GET /api/v1/credential-policies/{id}** -- get a policy by ID
- **GET /api/v1/credential-policies** -- list all policies
- **PATCH /api/v1/credential-policies/{id}** -- update a policy
- **DELETE /api/v1/credential-policies/{id}** -- delete a policy

Policies define each agent's operational envelope programmatically. They enforce what grant types, scopes, TTLs, and delegation depths are allowed.

Ask the user what constraints they want to enforce and build the policy accordingly.

### Token Introspection

**POST /oauth2/token/introspect** -- public endpoint.

Request body:
- `token` (required) -- JWT to introspect

Returns the token's claims including `active`, `sub` (WIMSE URI), `scope`, `act` (delegation chain), `delegation_depth`, `owner_user_id`, and expiry information. Use this to verify a token is still valid and inspect its identity chain.

### Agent Lifecycle Management

Additional agent management endpoints:

- **GET /api/v1/agents/registry/{id}** -- get agent details
- **GET /api/v1/agents/registry** -- list agents (supports filters: `identity_type`, `label`, `trust_level`, `is_active`, `search`)
- **PATCH /api/v1/agents/registry/{id}** -- update agent fields
- **DELETE /api/v1/agents/registry/{id}** -- deactivate agent (soft delete) and revoke its keys
- **POST /api/v1/agents/registry/{id}/activate** -- reactivate a deactivated agent
- **POST /api/v1/agents/registry/{id}/deactivate** -- deactivate without deleting
- **POST /api/v1/agents/registry/{id}/rotate-key** -- rotate API key (revokes old, issues new)

All require `X-Account-ID` and `X-Project-ID` headers.

## Making Requests

When constructing curl commands, always use this pattern:

```bash
curl -s -X <METHOD> "${ZEROID_BASE_URL}<path>" \
  -H "Content-Type: application/json" \
  -d '<json body>' | jq .
```

Tenant-specific headers (`X-Account-ID`, `X-Project-ID`) are deployment-specific and not part of the core API. Add them only if required by the deployment.

Pipe responses through `jq` for readability. If `jq` is not available, use `python3 -m json.tool`.

## Interactive Mode

If the user invokes `/zeroid` with no specific request, present this menu:

1. **Check health** -- verify the Zeroid server is reachable
2. **Register an agent** -- create a new agent identity with API key
3. **Issue a token** -- get an OAuth 2.1 access token
4. **Delegate to sub-agent** -- RFC 8693 token exchange
5. **Revoke a credential** -- immediately invalidate a token or API key
6. **Manage policies** -- create, list, update, or delete credential policies
7. **Introspect a token** -- inspect token claims and delegation chain
8. **List/search agents** -- browse the agent registry

Ask the user which operation they want to perform, then collect the required inputs interactively. After each operation, show the result and ask if they want to do anything else.
