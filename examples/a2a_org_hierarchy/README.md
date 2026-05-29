# ZeroID — Cascading Revocation at Scale

When a compromised agent sits inside a delegation chain, revoking its credential
is the easy part. The hard part is every credential that was derived from it —
specialists that delegated to that agent, tool agents that received tokens through
it, any further sub-delegations downstream. In a real enterprise deployment those
downstream agents may number in the dozens or hundreds, spread across services you
don't directly control.

Without a system that tracks delegation provenance, your options are:
- Wait for TTL expiry across the entire tree (minutes to hours of unauthorized
  access per hop)
- Nuke all tokens for the tenant (taking down every unaffected agent too)
- Manually walk the topology and revoke hop-by-hop (which requires knowing it)

ZeroID solves this with a mission tree. Every token issued by RFC 8693 token
exchange inherits a `mission_id` — a stable, opaque identifier shared across every
credential in the delegation tree. When a CAE signal fires against any node, ZeroID
performs one indexed UPDATE on the mission tree and atomically invalidates every
credential bearing that `mission_id` — no graph traversal required, no knowledge of
the topology required from the caller. Unaffected branches have different
`mission_id` values and are untouched.

This demo makes that concrete at 32 agents.

---

## The Scenario

A 3-tier enterprise hierarchy: two orchestrators each managing four specialist
agents, each specialist managing two to three tool agents. All 32 agents
communicate over real HTTP, authenticate every inbound request via token
introspection, and hold delegation tokens issued through RFC 8693 token exchange
chains.

`spec-legal` (the Legal specialist under the Business orchestrator) is flagged as
anomalous. One `zid signal` command fires a CAE signal against it. Within two
seconds, ZeroID has atomically revoked the entire mission tree rooted at
`spec-legal` — itself plus its three tool agents. The other 28 agents — including
those in other branches under the same orchestrator — have different `mission_id`
values and stay green. Grafana shows the exact moment each token goes inactive.

```
orch-business  [all scopes]
├── spec-finance  [finance:read/write  payroll:write  reports:read]
│   ├── tool-invoice-processor
│   ├── tool-budget-tracker
│   └── tool-payroll-agent
├── spec-hr  [hr:read/write  recruiting:write]
│   ├── tool-recruiter
│   ├── tool-performance-tracker
│   └── tool-onboarding-agent
├── spec-legal  [legal:read/write  contracts:write]  ← REVOCATION TARGET
│   ├── tool-contract-reviewer
│   ├── tool-compliance-checker
│   └── tool-ip-tracker
└── spec-sales  [sales:read/write  crm:read/write]
    ├── tool-crm-syncer
    └── tool-lead-scorer

orch-platform  [all scopes]
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

| Component | Status |
|-----------|--------|
| ZeroID token issuance (RFC 8693 token exchange) | real |
| Inter-agent HTTP calls with `Authorization: Bearer <token>` | real |
| Token introspection on every inbound request | real |
| CAE signal via `zid signal` CLI | real |
| Atomic mission tree revocation via `mission_id` | real |
| Per-agent Prometheus metrics (`zeroid_token_active`) | real |
| Grafana real-time dashboard | real |
| LLM inference | stubbed (fixture JSON) |

---

## How the mission tree is built

At startup the provisioner calls ZeroID once per agent, building the mission tree
depth-first via RFC 8693 token exchange:

```
orch-business  [all scopes]        depth=0   api_key grant        (root — mission_id anchor)
  spec-finance  [finance:*]        depth=1   RFC 8693 exchange     (inherits mission_id)
    tool-invoice-processor         depth=2   RFC 8693 exchange     (inherits mission_id)
    tool-budget-tracker            depth=2
    tool-payroll-agent             depth=2
  spec-legal  [legal:*]           depth=1                         (separate mission_id)
    tool-contract-reviewer         depth=2
    tool-compliance-checker        depth=2
    tool-ip-tracker                depth=2
  ...
```

Scope attenuation is cryptographically enforced at issuance — a tool agent can
never hold more scope than the specialist that delegated to it. Every token in the
tree shares the same `mission_id`, so revoking any node atomically invalidates the
entire sub-tree in one indexed UPDATE — no edge traversal, no topology knowledge
required.

---

## Prerequisites

```bash
# From the repo root:

# 1. Build and install the zid CLI
make cli-build
cd cli && npm link && cd ..

# 2. Generate the keys the zeroid container needs
make setup-keys
```

Docker and Docker Compose v2 are the only other dependencies.

---

## Run the demo

```bash
cd examples/a2a_org_hierarchy
docker compose up --build
```

Startup sequence (~30 s total):
1. `postgres` and `zeroid` boot and become healthy.
2. `provisioner` registers all 32 agents, builds the delegation chain, and writes
   `/shared/manifest.json`.
3. All 32 agent containers start, read their tokens from the manifest, and begin
   sending stub tasks to their children every 5 s.

```bash
# Watch provisioner complete
docker compose logs -f provisioner

# Confirm all 32 agents healthy
docker compose ps
```

Open Grafana at **http://localhost:3100** (login: admin / admin) and navigate to
**ZeroID Demo → ZeroID Cascade Revocation**. All 32 tiles start green.

---

## Trigger cascade revocation

```bash
export ZID_BASE_URL=http://localhost:8899
export ZID_ACCOUNT_ID=default
export ZID_PROJECT_ID=default

zid signal \
  --agent "$(zid agents list --json | jq -r '.[] | select(.external_id == "spec-legal") | .id')" \
  --type anomalous_behavior \
  --severity high \
  --source security-monitor \
  --reason 'compromised agent detected'
```

ZeroID performs one indexed UPDATE on the mission tree and atomically invalidates
`spec-legal` plus its three tool agents. Within ~2 s, those four tiles flip red on
Grafana. The other 28 agents have different `mission_id` values and remain green.

```bash
# Watch the revocation propagate through agent logs
docker compose logs -f spec-legal
# [spec-legal] TOKEN REVOKED — cascade from CAE signal
# [spec-legal] → tool-contract-reviewer: 401 UNAUTHORIZED (token revoked)
```

---

## Reset after revocation

Revoked tokens stay invalid until re-issued. To restore all 32 agents to green
without wiping the database — re-issue fresh delegation tokens for every identity:

```bash
docker compose down
docker volume rm a2a_org_hierarchy_shared-data
docker compose up -d
```

ZeroID identities and API keys are preserved in postgres; only the delegation
tokens are reissued.

To fully wipe everything and start from scratch:

```bash
docker compose down -v
docker compose up --build
```

---

## Clean up

```bash
docker compose down -v
```
