## Summary

Add a **mission log** — an append-only, hash-chained activity trail where agents report what they actually did, scoped to a delegation chain. This bridges the gap between what ZeroID knows an agent was *authorized* to do (tokens, scopes, delegation chains) and what it *actually did* (actions, outcomes, resources accessed).

Inspired by the mission log concept in [draft-hardt-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-aauth-protocol/) and [Karl McGuinness's analysis](https://notes.karlmcguinness.com/notes/aauth-now-has-a-mission-layer/) of its governance gaps. This proposal adapts the concept to ZeroID's existing architecture without requiring the full AAuth mission lifecycle.

## Background

### What AAuth's mission log is

An ordered record of all agent↔Person Server interactions within a mission:

| Entry type | Who creates it | When |
|---|---|---|
| Token requests | PS records automatically | Agent calls `token_endpoint` |
| Permission requests | PS records automatically | Agent calls `permission_endpoint` |
| Audit records | **Agent reports** | Agent calls `audit_endpoint` |
| Interaction requests | PS records automatically | Agent requests human interaction |
| Clarification exchanges | PS records automatically | During mission approval dialogue |

The key design choice: the agent is a **first-class contributor** to its own audit trail. This has no analogue in OAuth or in ZeroID today.

The AAuth spec intentionally leaves the log under-specified — no entry schema, no read API, no integrity mechanism. McGuinness's critique specifically calls out the lack of tamper-evidence and the minimal lifecycle.

### What ZeroID already has

| AAuth concept | ZeroID equivalent | Gap |
|---|---|---|
| Token request log | `issued_credentials` — every token with grant_type, delegation_depth, parent_jti | Exists |
| Security event log | `cae_signals` — signal_type, severity, payload, identity_id | Exists |
| Mission scope | `act` chain + 3-way scope intersection on token_exchange | Exists |
| PS evaluation | `OnClaimsIssue` hook | Plumbing exists |
| Agent-reported actions | **Nothing** | **Gap** |
| Hash-chained integrity | **Nothing** | **Gap** |

## Design

### Mission = delegation chain

No new "mission" concept needed. A mission is the tree of tokens rooted at an orchestrator's initial credential. The **root JTI** (the orchestrator's original token JTI) is the natural mission identifier — ZeroID already tracks these via `parent_jti` links.

### Endpoint

```
POST /oauth2/mission/log
Authorization: Bearer <agent-token>
```
```json
{
  "action":   "tool:execute",
  "resource": "github.com/api/repos/org/repo/pulls",
  "outcome":  "success",
  "detail":   {"tool": "create_pull_request", "pr_number": 42}
}
```

The server:
1. Extracts the agent's JTI and root JTI (walks `parent_jti` chain or reads a `root_jti` claim) from the bearer token
2. Appends an entry with the next sequence number
3. Computes `entry_hash = SHA-256(prev_hash || entry_type || action || resource || outcome || detail || sequence || timestamp)`
4. Returns the entry with its hash

### Schema

```sql
CREATE TABLE mission_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    root_jti    VARCHAR(255) NOT NULL,   -- mission = root of delegation chain
    agent_jti   VARCHAR(255) NOT NULL,   -- which credential reported this
    identity_id UUID REFERENCES identities(id) ON DELETE SET NULL,
    account_id  VARCHAR(255) NOT NULL,
    project_id  VARCHAR(255) NOT NULL,

    entry_type  VARCHAR(50)  NOT NULL,   -- action, decision, error
    action      VARCHAR(255),
    resource    TEXT,
    outcome     VARCHAR(50),
    detail      JSONB,

    sequence    BIGINT       NOT NULL,   -- ordering within mission
    prev_hash   VARCHAR(64),             -- SHA-256 of previous entry
    entry_hash  VARCHAR(64)  NOT NULL,   -- SHA-256 of this entry

    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mission_log_root_jti_seq ON mission_log (root_jti, sequence);
CREATE INDEX idx_mission_log_identity ON mission_log (identity_id);
CREATE INDEX idx_mission_log_tenant ON mission_log (account_id, project_id);
```

### Read endpoint

```
GET /oauth2/mission/log?root_jti=<jti>
Authorization: Bearer <agent-token>
```

Returns the ordered log for a delegation chain. Optionally filterable by `identity_id`, `entry_type`, `action`.

## What this enables

### 1. Audit that answers "why" not just "what"

Today: agent B got a token with `data:read` scope delegated from agent A.
With mission log: agent B used that token to read 3 files, create a PR, and post a Slack message — and whether each action succeeded.

### 2. Policy decisions informed by history

The `OnClaimsIssue` hook (or a new `OnTokenExchange` hook) could receive the mission log as context. Example: "This sub-agent is requesting `deploy:write` scope, and the mission log shows 47 file reads and 0 test runs — deny until tests pass."

### 3. CAEP integration for trajectory drift

A monitoring layer reads the mission log, detects trajectory drift (many individually-authorized actions that collectively diverge from intent), and pushes a `policy_violation` CAEP signal back into ZeroID to revoke the chain. This closes the gap McGuinness identified — runtime alignment monitoring that feeds back into the auth layer.

### 4. Tamper-evident compliance

The hash chain means any modification to a log entry invalidates all subsequent hashes. For EU AI Act traceability or SOC2 audit: cryptographic proof the log is intact, not just "here's what we logged."

## What this does NOT require

- No new token type or claim (root_jti is derivable from existing delegation chain)
- No changes to existing grant types
- No mission description or clarification channel (can come later)
- No changes to forward-auth proxy or JWKS endpoints
- Agents that don't report are unaffected — the log is opt-in

## Scope

Minimal implementation: one migration, one domain model, one repo, one handler endpoint (POST + GET), and a hash function. Composes with existing infrastructure rather than replacing any of it.

## References

- [draft-hardt-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-aauth-protocol/) — Mission and mission log concept (Sections 7.1–7.6)
- [McGuinness: AAuth Now Has a Mission Layer](https://notes.karlmcguinness.com/notes/aauth-now-has-a-mission-layer/) — Critique of text-first vs authority-model-first, lifecycle gaps, cross-domain enforcement
- [Aembit / CSA Survey](https://aembit.io/blog/introducing-the-identity-and-access-gaps-in-the-age-of-autonomous-ai-survey-report/) — 68% of teams can't distinguish agent vs human actions
- [draft-nyantakyi-vaip-agent-identity](https://datatracker.ietf.org/doc/draft-nyantakyi-vaip-agent-identity/) — SHA-256 hash-chained audit trail for agent identity (VAIP)
