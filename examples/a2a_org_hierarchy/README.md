# ZeroID Cascade Revocation — 32-Agent A2A Demo

32 agents across a 3-tier enterprise hierarchy, communicating via real HTTP
with ZeroID delegation tokens. One `zeroid signal` command fires a CAE signal
against a specialist agent, and Grafana shows its entire sub-tree flip red
within seconds — while the other 28 agents stay green and keep running.

---

## Hierarchy

```
Tier 1 — Orchestrators (2)
│
├── orch-business  [all scopes]
│   ├── spec-finance  [finance:read/write  payroll:write  reports:read]
│   │   ├── tool-invoice-processor
│   │   ├── tool-budget-tracker
│   │   └── tool-payroll-agent
│   ├── spec-hr  [hr:read/write  recruiting:write]
│   │   ├── tool-recruiter
│   │   ├── tool-performance-tracker
│   │   └── tool-onboarding-agent
│   ├── spec-legal  [legal:read/write  contracts:write]  ← REVOCATION TARGET
│   │   ├── tool-contract-reviewer
│   │   ├── tool-compliance-checker
│   │   └── tool-ip-tracker
│   └── spec-sales  [sales:read/write  crm:read/write]
│       ├── tool-crm-syncer
│       └── tool-lead-scorer
│
└── orch-platform  [all scopes]
    ├── spec-engineering  [code:read/write  deploy:read/write]
    │   ├── tool-code-reviewer
    │   ├── tool-dependency-scanner
    │   └── tool-test-runner
    ├── spec-security  [security:read/write  audit:read/write]
    │   ├── tool-siem-collector
    │   ├── tool-threat-intel
    │   └── tool-audit-logger
    ├── spec-data  [data:read/write]
    │   ├── tool-pipeline-runner
    │   ├── tool-schema-validator
    │   └── tool-reporting-agent
    └── spec-operations  [ops:read/write  deploy:read/write  infra:write]
        ├── tool-deploy-agent
        └── tool-infra-monitor
```

---

## What's real, what's stubbed

| Component | Real |
|-----------|------|
| ZeroID token issuance (RFC 8693 token exchange) | ✓ |
| Inter-agent HTTP calls with `Authorization: Bearer <token>` | ✓ |
| Token introspection on every inbound request | ✓ |
| CAE signal via `zeroid signal` CLI | ✓ |
| Cascade revocation via `parent_jti` chain walk | ✓ |
| Per-agent Prometheus metrics (`zeroid_token_active`) | ✓ |
| Grafana real-time dashboard | ✓ |
| LLM inference | stubbed (fixture JSON) |

---

## Prerequisites

```bash
# 1. Build and install the zid CLI (from repo root)
make cli-build
cd cli && npm link
cd ..

# 2. Generate keys the zeroid container needs (from repo root)
make setup-keys
```

Docker and Docker Compose (v2) are the only other dependencies.

Add the `cascade-demo` profile to `~/.config/zid/config.json` so the signal
command targets the right tenant:

```json
"cascade-demo": {
  "base_url": "http://localhost:8899",
  "account_id": "default",
  "project_id": "default"
}
```

---

## Run the demo

```bash
cd examples/a2a_org_hierarchy
docker compose up --build
```

Startup sequence:
1. `postgres` and `zeroid` boot and become healthy (~15 s).
2. `provisioner` registers all 32 agents, builds the delegation chain, and
   writes `/shared/manifest.json`. It prints the `spec-legal` identity ID and
   the exact revocation command to its logs.
3. All 32 agent containers start, read their tokens from the manifest, and
   begin sending stub tasks to their children every 5 s.

```bash
# Monitor startup
docker compose logs -f provisioner

# Once provisioner exits 0, check agent health
docker compose ps
```

---

## Trigger cascade revocation

Look up the `spec-legal` identity ID, then fire the signal:

```bash
zid signal \
  --profile cascade-demo \
  --agent "$(zid agents list --profile cascade-demo --json | jq -r '.[] | select(.external_id == "spec-legal") | .id')" \
  --type anomalous_behavior \
  --severity high \
  --source security-monitor \
  --reason 'compromised agent detected'
```


ZeroID server walks the `parent_jti` tree and revokes `spec-legal` plus its
three tool agents atomically. Each agent detects the change within 2 seconds
via its self-introspection loop.

---

## Watch the cascade

Open Grafana at **http://localhost:3100** (login: admin / admin).

Navigate to **ZeroID Demo → ZeroID Cascade Revocation**.

- **Agent Token Status** grid: all 32 tiles start green.
- Fire the signal. Within ~2 s: `spec-legal`, `tool-contract-reviewer`,
  `tool-compliance-checker`, and `tool-ip-tracker` flip red.
- The other 28 agents stay green.
- The **Token Active State Over Time** panel records the exact moment each
  agent's token went inactive.
- The **Revocation Timestamp** table shows the Unix timestamp of first
  detected revocation per agent.

Also watch the agent logs for delegation failures:

```bash
docker compose logs -f spec-legal
# → [spec-legal] TOKEN REVOKED at 1748234567.123 (cascade from ZeroID signal)
# → [spec-legal] → tool-contract-reviewer:8080: 401 UNAUTHORIZED (token revoked)
```

---

## Reset after revocation

After firing a signal, the revoked agents stay revoked because their tokens are
invalid in ZeroID. To restore all 32 agents to green (without wiping the
database), delete the manifest and re-run the provisioner — it re-issues fresh
tokens for every identity:

```bash
# Stop agents, clear the manifest, reissue all tokens, restart
docker compose down
docker volume rm a2a_org_hierarchy_shared-data
docker compose up -d
```

The ZeroID identities and API keys are preserved in postgres; only the
delegation tokens are reissued. Use this after every revocation demo run.

To fully wipe everything (identities, keys, tokens, database):

```bash
docker compose down -v
docker compose up --build
```

## Clean up

```bash
docker compose down -v
```

---

## How the delegation chain is built

The `provisioner` calls ZeroID once per agent at startup:

```
orch-business  [all scopes]             depth=0   api_key grant
  → spec-finance  [finance:*]           depth=1   RFC 8693 token exchange
    → tool-invoice-processor            depth=2   RFC 8693 token exchange
    → tool-budget-tracker               depth=2
    → tool-payroll-agent                depth=2
  → spec-legal  [legal:*]              depth=1
    → tool-contract-reviewer            depth=2
    → tool-compliance-checker           depth=2
    → tool-ip-tracker                   depth=2
  ...
```

Scope attenuation is enforced cryptographically at issuance: a tool agent
can never hold more scope than its specialist, and a specialist can never hold
more than its orchestrator.

When `spec-legal`'s credential is revoked via CAE signal, ZeroID traverses the
`parent_jti` graph and invalidates all three downstream credentials
simultaneously. The next introspection call from any of the three tool agents
returns `{"active": false}`.
