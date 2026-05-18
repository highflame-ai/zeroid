# zeroid — ZeroID CLI

Command-line interface for [ZeroID](https://zeroid.io) — agent identity for AI systems.

```bash
npm install -g @highflame/zeroid
# or without installing:
npx @highflame/zeroid <command>
```

The package also installs `zid` as a short alias for `zeroid`.

---

## Quick start

```bash
# First-time init needs tenant context for the target account/project
export ZID_ACCOUNT_ID=acct_123
export ZID_PROJECT_ID=proj_456
export ZID_BASE_URL=https://api.zeroid.io   # or http://localhost:8899 for local dev

# Register your first agent — writes .env.zeroid and saves a local profile
zeroid init --name "github-mcp-server" --type mcp_server --owner "dev@company.com"

# Verify a token your server received
zeroid token verify eyJhbGc...

# Decode any JWT to inspect its claims (no network call)
zeroid token decode eyJhbGc...
```

---

## Authentication

Most `zeroid` commands authenticate using an API key tied to an agent identity. The bootstrap exception is `zeroid init`, which only needs tenant context for the target account/project.

There are two ways to provide configuration:

**Environment variables** (recommended for CI/CD):
```bash
export ZID_ACCOUNT_ID=acct_123
export ZID_PROJECT_ID=proj_456
export ZID_BASE_URL=https://api.zeroid.io   # optional, default shown
export ZID_API_KEY=zid_sk_...               # required for token issue and authenticated agent flows
```

**Local profile** (set automatically by `zeroid init`, stored in `~/.config/zeroid/config.json`):
```bash
zeroid config use-profile prod     # switch active profile
zeroid config list-profiles        # list all profiles
```

Environment variables take precedence over the config file. Most commands also accept `--profile <name>` to select a non-default profile explicitly.

---

## Commands

### `zeroid init`

Register a new agent, write its API key to `.env.zeroid`, and save a local profile.

```bash
zeroid init --name "github-mcp-server" --type mcp_server --owner "dev@company.com"
zeroid init --name "code-reviewer" --type agent --sub-type code_agent --framework langchain --owner "dev@company.com"
zeroid init --name "my-agent" --save-profile staging --owner "dev@company.com"
```

| Flag | Description | Default |
|---|---|---|
| `--name <name>` | Human-readable agent name | required |
| `--owner <owner_id>` | User ID recorded as the agent owner | required |
| `--id <external_id>` | External ID (your own identifier) | same as `--name` |
| `--type <type>` | `agent` \| `application` \| `mcp_server` \| `service` | `agent` |
| `--sub-type <sub_type>` | `orchestrator` \| `tool_agent` \| `code_agent` \| `autonomous` \| ... | — |
| `--framework <name>` | Framework name, e.g. `langchain`, `mcp` | — |
| `--description <text>` | Short description | — |
| `--save-profile <name>` | Profile name to save credentials under | `default` |
| `--profile <name>` | Profile to use for the parent account/project | active profile |
| `--json` | Output raw JSON | — |

On first use, provide tenant context via `ZID_ACCOUNT_ID` and `ZID_PROJECT_ID`, or point `--profile` at an existing saved profile.

After running, the API key is written to `.env.zeroid` in the current directory. Add it to `.gitignore`.

---

### `zeroid token issue`

Issue a short-lived access token for the authenticated agent.

```bash
zeroid token issue
zeroid token issue --scope "repo:read"
zeroid token issue --scope "repo:read pr:write" --json
```

| Flag | Description | Default |
|---|---|---|
| `--scope <scopes>` | Space-separated scopes to request | all allowed scopes |
| `--profile <name>` | Profile to use | active profile |
| `--json` | Output raw JSON | — |

**Output:**
```
✓  Token issued
  access_token: eyJhbGc...
  token_type:   Bearer
  expires_in:   900s
```

---

### `zeroid token decode`

Decode a JWT and display its claims. No network call, no signature check — useful for inspecting any token.

```bash
zeroid token decode eyJhbGc...
pbpaste | zeroid token decode          # read from stdin
zeroid token decode eyJhbGc... --json  # raw JSON output
```

Reads from stdin if no argument is given, so it works in pipelines:
```bash
zeroid token issue --json | jq -r '.access_token' | zeroid token decode
```

| Flag | Description |
|---|---|
| `--json` | Output `{ header, payload }` as raw JSON |

**Output (human-readable):**
```
Header
  alg:  ES256
  kid:  key-2025-01

Payload
  sub:              wimse:agent:acct_123/proj_456/github-mcp-server
  iss:              https://api.zeroid.io
  identity_type:    agent
  trust_level:      first_party
  grant_type:       api_key
  iat:              2026-03-29T10:00:00.000Z (5m ago)
  exp:              2026-03-29T10:15:00.000Z (in 10m)
  scopes:           repo:read pr:write
```

Expired tokens are shown with the `exp` line in red.

---

### `zeroid token verify`

Verify a JWT against the live JWKS endpoint. Confirms the signature is valid and the token has not expired.

```bash
zeroid token verify eyJhbGc...
zeroid token verify eyJhbGc... --json
```

| Flag | Description |
|---|---|
| `--profile <name>` | Profile to use (determines the JWKS base URL) |
| `--json` | Output verified identity claims as raw JSON |

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Valid |
| `1` | Invalid (bad signature, malformed, network error) |
| `2` | Expired |

Shell scripts can branch on exit codes:
```bash
if zeroid token verify "$TOKEN"; then
  echo "token ok"
elif [ $? -eq 2 ]; then
  echo "token expired"
fi
```

---

### `zeroid token revoke`

Revoke a token immediately.

```bash
zeroid token revoke eyJhbGc...
```

| Flag | Description |
|---|---|
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON response |

---

### `zeroid ciba init`

Initiate an OpenID CIBA backchannel authentication request. The CLI sends tenant context in the request body because `/oauth2/bc-authorize` is a public OAuth endpoint.

```bash
zeroid ciba init \
  --client-id my-ciba-client \
  --login-hint user@example.com \
  --scope "openid profile" \
  --binding-message "Approve login on Production?" \
  --requested-expiry 600
```

For ping or push clients, include the per-request bearer token:

```bash
zeroid ciba init \
  --client-id my-ciba-client \
  --login-hint user@example.com \
  --client-notification-token opaque-token
```

| Flag | Description | Default |
|---|---|---|
| `--client-id <id>` | OAuth client initiating the request | required |
| `--login-hint <hint>` | User identifier for the out-of-band prompt | required |
| `--scope <scopes>` | Space-separated scopes to request | — |
| `--binding-message <text>` | Context shown to the approving user | — |
| `--requested-expiry <seconds>` | Requested auth request lifetime | server default |
| `--client-notification-token <token>` | Required for ping/push delivery clients | — |
| `--profile <name>` | Profile to use for tenant/base URL | active profile |
| `--json` | Output raw JSON | — |

**Output:**
```
✓  CIBA request initiated
  auth_req_id: ari_...
  expires_in:  300s
  interval:    5s
```

---

### `zeroid ciba approve <auth_req_id>`

Admin-side helper to approve a pending CIBA request in local demos and test environments.

```bash
zeroid ciba approve ari_... \
  --subject-id user@example.com \
  --subject-email user@example.com \
  --subject-name "Alice User"

# Highflame AuthN-style deployments with admin routes mounted at the base URL:
ZID_INTERNAL_SERVICE=highflame-admin \
ZID_INTERNAL_SERVICE_SECRET=... \
zeroid ciba approve ari_... --subject-id user@example.com --admin-prefix ""
```

| Flag | Description |
|---|---|
| `--subject-id <id>` | Approved end-user identifier; becomes the token `sub` |
| `--subject-email <email>` | Approved user's email |
| `--subject-name <name>` | Approved user's display name |
| `--admin-base-url <url>` | Admin API base URL; defaults to `ZID_ADMIN_BASE_URL` or the profile base URL |
| `--admin-prefix <path>` | Admin route prefix before `/oauth2/bc-authorize`; defaults to `ZID_ADMIN_PREFIX` or `/api/v1` |
| `--internal-service <name>` | Adds `X-Internal-Service`; defaults to `ZID_INTERNAL_SERVICE` |
| `--internal-service-secret <secret>` | Adds `X-Internal-Service-Secret`; defaults to `ZID_INTERNAL_SERVICE_SECRET` |
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON |

Use `--admin-prefix ""` for deployers such as Highflame AuthN that mount ZeroID admin routes directly under the configured base URL. Standalone ZeroID keeps the default `/api/v1` prefix.

---

### `zeroid ciba deny <auth_req_id>`

Admin-side helper to deny a pending CIBA request.

```bash
zeroid ciba deny ari_... --reason "user rejected"

ZID_INTERNAL_SERVICE=highflame-admin \
ZID_INTERNAL_SERVICE_SECRET=... \
zeroid ciba deny ari_... --reason "user rejected" --admin-prefix ""
```

| Flag | Description |
|---|---|
| `--reason <text>` | Operator note sent when supported by the server |
| `--admin-base-url <url>` | Admin API base URL; defaults to `ZID_ADMIN_BASE_URL` or the profile base URL |
| `--admin-prefix <path>` | Admin route prefix before `/oauth2/bc-authorize`; defaults to `ZID_ADMIN_PREFIX` or `/api/v1` |
| `--internal-service <name>` | Adds `X-Internal-Service`; defaults to `ZID_INTERNAL_SERVICE` |
| `--internal-service-secret <secret>` | Adds `X-Internal-Service-Secret`; defaults to `ZID_INTERNAL_SERVICE_SECRET` |
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON |

---

### `zeroid ciba poll <auth_req_id>`

Poll `/oauth2/token` with the CIBA grant type until the user approves or denies.

```bash
zeroid ciba poll ari_... --client-id my-ciba-client
zeroid ciba poll ari_... --client-id my-ciba-client --watch --interval 5
zeroid ciba poll ari_... --client-id my-ciba-client --json
```

| Flag | Description | Default |
|---|---|---|
| `--client-id <id>` | OAuth client that initiated the request | required |
| `--watch` | Keep polling through `authorization_pending` / `slow_down` | off |
| `--interval <seconds>` | Polling interval for `--watch` | `5` |
| `--profile <name>` | Profile to use for base URL | active profile |
| `--json` | Output raw JSON | — |

On success, the command prints the access token. Without `--watch`, OAuth polling errors such as `authorization_pending`, `slow_down`, `access_denied`, and `expired_token` are printed and return exit code `1`.

---

### `zeroid ciba listen`

Run a local HTTPS callback capture endpoint for CIBA ping and push testing. The command creates a self-signed localhost certificate in `~/.config/zeroid/ciba-cert/` on first run.

```bash
zeroid ciba listen --port 8888
```

Use `https://localhost:8888/cb` as the OAuth client's `client_notification_endpoint` while developing locally. Localhost callbacks require the ZeroID server to allow private notification endpoints in its backchannel configuration.

| Flag | Description | Default |
|---|---|---|
| `--port <port>` | HTTPS port to listen on | `8888` |
| `--host <host>` | Host to bind | `localhost` |
| `--json` | Output newline-delimited JSON events | off |

---

### `zeroid agents list`

List all registered agents for the current tenant.

```bash
zeroid agents list
zeroid agents list --type mcp_server
zeroid agents list --json | jq '.[].wimse_uri'
```

| Flag | Description | Default |
|---|---|---|
| `--type <type>` | Filter by identity type | all types |
| `--limit <n>` | Max results | `50` |
| `--profile <name>` | Profile to use | active profile |
| `--json` | Output raw JSON array | — |

**Output:**
```
┌──────────────────────┬────────────┬─────────────┬────────┬──────────┐
│ NAME                 │ TYPE       │ TRUST        │ STATUS │ CREATED  │
├──────────────────────┼────────────┼─────────────┼────────┼──────────┤
│ github-mcp-server    │ mcp_server │ first_party  │ active │ 2h ago   │
│ code-reviewer        │ agent      │ first_party  │ active │ 5m ago   │
└──────────────────────┴────────────┴─────────────┴────────┴──────────┘

2 agent(s)
```

---

### `zeroid agents get <id>`

Get a single agent by its identity ID.

```bash
zeroid agents get agt_abc123
zeroid agents get agt_abc123 --json
```

| Flag | Description |
|---|---|
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON |

---

### `zeroid agents rotate-key <id>`

Revoke the agent's current API key and issue a new one.

```bash
zeroid agents rotate-key agt_abc123
```

The new API key is printed once. If the selected saved profile belongs to the
rotated agent, `zeroid` updates that profile automatically. If `.env.zeroid`
already exists in the current directory, it is refreshed as well.

| Flag | Description |
|---|---|
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON |

---

### `zeroid agents deactivate <id>`

Suspend an agent. Its tokens will be rejected until it is re-activated. Does not delete the agent.

```bash
zeroid agents deactivate agt_abc123
zeroid agents activate agt_abc123
```

| Flag | Description |
|---|---|
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON |

---

### `zeroid creds list`

List issued credentials (JWTs) for an agent.

```bash
zeroid creds list --agent agt_abc123
zeroid creds list --agent agt_abc123 --active   # non-revoked only
zeroid creds list --agent agt_abc123 --json
```

| Flag | Description |
|---|---|
| `--agent <id>` | Agent identity ID (required) |
| `--active` | Show only non-revoked credentials |
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON array |

**Output:**
```
┌──────────────┬────────┬──────────────────────┬─────────┬──────────┐
│ ID           │ STATUS │ SCOPES               │ EXPIRES │ ISSUED   │
├──────────────┼────────┼──────────────────────┼─────────┼──────────┤
│ cred_xyz789  │ active │ repo:read pr:write   │ 10m ago │ 25m ago  │
└──────────────┴────────┴──────────────────────┴─────────┴──────────┘

1 credential(s)
```

---

### `zeroid signal`

Ingest a Continuous Access Evaluation (CAE) signal for an agent. Signals can trigger token revocation or other policy actions depending on your ZeroID configuration.

```bash
zeroid signal \
  --agent agt_abc123 \
  --type anomalous_behavior \
  --severity high \
  --source "security-monitor" \
  --reason "unexpected outbound call to external endpoint"
```

| Flag | Description | Required |
|---|---|---|
| `--agent <id>` | Agent identity ID | yes |
| `--type <type>` | Signal type (see below) | yes |
| `--severity <level>` | `low` \| `medium` \| `high` \| `critical` | yes |
| `--source <source>` | Origin of the signal, e.g. `siem`, `monitor` | yes |
| `--reason <text>` | Human-readable reason, stored in `payload.reason` | no |
| `--profile <name>` | Profile to use | no |
| `--json` | Output raw JSON | no |

**Signal types:**

| Type | When to use |
|---|---|
| `anomalous_behavior` | Unexpected or out-of-policy actions |
| `policy_violation` | Confirmed policy breach |
| `credential_change` | Key or secret rotation outside normal flow |
| `session_revoked` | Session ended by external system |
| `ip_change` | Agent calling from unexpected network location |
| `owner_change` | Ownership of the agent transferred |
| `retirement` | Agent decommissioned |

---

### `zeroid config`

Manage CLI profiles.

```bash
zeroid config list-profiles       # list all profiles, marking the active one
zeroid config use-profile prod    # switch the active profile
```

Profiles are stored in `~/.config/zeroid/config.json`.

---

## Global flags

All commands that make API calls support:

| Flag | Description |
|---|---|
| `--profile <name>` | Use a specific named profile |
| `--json` | Output machine-readable JSON (disables table/colored output) |

---

## Development

```bash
# Install dependencies
cd cli && npm install

# Run from source (no build needed)
npm run dev -- init --name "test-agent"

# Build
npm run build

# Type check
npm run typecheck
```

Or via the root Makefile:
```bash
make cli-install
make cli-build
make cli-dev ARGS="token decode eyJhbGc..."
```
