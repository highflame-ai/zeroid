# zid — ZeroID CLI

Command-line interface for [ZeroID](https://zeroid.io) — agent identity for AI systems.

```bash
npm install -g @highflame/zid
# or without installing:
npx @highflame/zid <command>
```

---

## Quick start

```bash
# First-time init needs tenant context for the target account/project
export ZID_ACCOUNT_ID=acct_123
export ZID_PROJECT_ID=proj_456
export ZID_BASE_URL=https://api.zeroid.io   # or http://localhost:8899 for local dev

# Register your first agent — writes .env.zeroid and saves a local profile
zid init --name "github-mcp-server" --type mcp_server --owner "dev@company.com"

# Verify a token your server received
zid token verify eyJhbGc...

# Decode any JWT to inspect its claims (no network call)
zid token decode eyJhbGc...
```

---

## Authentication

Most `zid` commands authenticate using an API key tied to an agent identity. The bootstrap exception is `zid init`, which only needs tenant context for the target account/project.

There are two ways to provide configuration:

**Environment variables** (recommended for CI/CD):
```bash
export ZID_ACCOUNT_ID=acct_123
export ZID_PROJECT_ID=proj_456
export ZID_BASE_URL=https://api.zeroid.io   # optional, default shown
export ZID_API_KEY=zid_sk_...               # required for token issue and authenticated agent flows
```

**Local profile** (set automatically by `zid init`, stored in `~/.config/zid/config.json`):
```bash
zid config use-profile prod     # switch active profile
zid config list-profiles        # list all profiles
```

Environment variables take precedence over the config file. Most commands also accept `--profile <name>` to select a non-default profile explicitly.

---

## Commands

### `zid init`

Register a new agent, write its API key to `.env.zeroid`, and save a local profile.

```bash
zid init --name "github-mcp-server" --type mcp_server --owner "dev@company.com"
zid init --name "code-reviewer" --type agent --sub-type code_agent --framework langchain --owner "dev@company.com"
zid init --name "my-agent" --save-profile staging --owner "dev@company.com"
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

### `zid token issue`

Issue a short-lived access token for the authenticated agent.

```bash
zid token issue
zid token issue --scope "repo:read"
zid token issue --scope "repo:read pr:write" --json
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

### `zid token decode`

Decode a JWT and display its claims. No network call, no signature check — useful for inspecting any token.

```bash
zid token decode eyJhbGc...
pbpaste | zid token decode          # read from stdin
zid token decode eyJhbGc... --json  # raw JSON output
```

Reads from stdin if no argument is given, so it works in pipelines:
```bash
zid token issue --json | jq -r '.access_token' | zid token decode
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

### `zid token verify`

Verify a JWT against the live JWKS endpoint. Confirms the signature is valid and the token has not expired.

```bash
zid token verify eyJhbGc...
zid token verify eyJhbGc... --json
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
if zid token verify "$TOKEN"; then
  echo "token ok"
elif [ $? -eq 2 ]; then
  echo "token expired"
fi
```

---

### `zid token revoke`

Revoke a token immediately.

```bash
zid token revoke eyJhbGc...
```

| Flag | Description |
|---|---|
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON response |

---

### `zid agents list`

List all registered agents for the current tenant.

```bash
zid agents list
zid agents list --type mcp_server
zid agents list --json | jq '.[].wimse_uri'
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

### `zid agents get <id>`

Get a single agent by its identity ID.

```bash
zid agents get agt_abc123
zid agents get agt_abc123 --json
```

| Flag | Description |
|---|---|
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON |

---

### `zid agents rotate-key <id>`

Revoke the agent's current API key and issue a new one.

```bash
zid agents rotate-key agt_abc123
```

The new API key is printed once and not stored — save it immediately.

| Flag | Description |
|---|---|
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON |

---

### `zid agents deactivate <id>`

Suspend an agent. Its tokens will be rejected until it is re-activated. Does not delete the agent.

```bash
zid agents deactivate agt_abc123
zid agents activate agt_abc123
```

| Flag | Description |
|---|---|
| `--profile <name>` | Profile to use |
| `--json` | Output raw JSON |

---

### `zid creds list`

List issued credentials (JWTs) for an agent.

```bash
zid creds list --agent agt_abc123
zid creds list --agent agt_abc123 --active   # non-revoked only
zid creds list --agent agt_abc123 --json
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

### `zid signal`

Ingest a Continuous Access Evaluation (CAE) signal for an agent. Signals can trigger token revocation or other policy actions depending on your ZeroID configuration.

```bash
zid signal \
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

### `zid config`

Manage CLI profiles.

```bash
zid config list-profiles       # list all profiles, marking the active one
zid config use-profile prod    # switch the active profile
```

Profiles are stored in `~/.config/zid/config.json`.

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
