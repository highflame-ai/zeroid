# Confused Deputy — LangGraph + ZeroID

This example demonstrates how ZeroID prevents the **Confused Deputy** problem in a LangGraph multi-agent workflow via indirect prompt injection.

## The Attack

A two-agent pipeline: an **Email Agent** reads the HR inbox, a **Payroll Agent** acts on the Email Agent's output using privileged HR system credentials.

An attacker sends a message to the HR inbox with a `PAYROLL_COMMAND` embedded inside it. Because the Payroll Agent trusts its peer's output, it executes the injected command — rerouting an employee's direct deposit to the attacker's bank account — without realizing the instruction came from untrusted email.

```
Email Agent reads poisoned inbox message → passes output to Payroll Agent
Payroll Agent sees PAYROLL_COMMAND → uses its HR API key → 💀 direct deposit rerouted
```

This is **Business Email Compromise (BEC) at AI speed.** Attackers already do this manually — they email HR posing as an employee requesting a bank account change. An AI agent that reads email and has write access to payroll systems makes this instantaneous and requires no human social engineering.

**Root cause:** Both agents share one credential. There is no identity boundary, no scope enforcement, and nothing to distinguish the Email Agent's reasoning from injected instructions.

## The Fix

ZeroID maps to two patterns:

| Pattern | What it does here |
|---|---|
| **Pattern 3** — Orchestrator delegates to sub-agent | A 3-hop RFC 8693 delegation chain enforces scope at every step. The Payroll Agent can never act beyond the scope it was given for a specific context. |
| **Pattern 5** — Tool boundary enforces identity | `payroll_tool` calls `client.tokens.verify()` before acting. If the token lacks `payroll:write`, the action is rejected — cryptographically, not by trust. |

## The 3-Hop Delegation Chain

This is the critical point. The fix is not just that the Email Agent lacks `payroll:write` — it is that **the Payroll Agent itself is constrained** when processing untrusted content.

```
[depth=0] Payroll Agent   — email:read  payroll:read  payroll:write
               ↓  RFC 8693: delegates email:read only
[depth=1] Email Agent     — email:read
               ↓  RFC 8693: delegates email:read back to Payroll Agent
[depth=2] Payroll Agent   — email:read   ← operating under Email Agent's scope
```

When the Payroll Agent processes the Email Agent's output, it does so using the **depth=2 context token** — not its original full-privilege token. That context token was minted by exchanging the Email Agent's token, so it carries only what the Email Agent was permitted to delegate.

**The full payroll token never enters the graph.** It is used only during setup to mint the delegated tokens. By the time `payroll_agent` runs, the only credential in its state is `payroll_context_token` (depth=2, `email:read` only).

This means even if the Payroll Agent is fully tricked by the injection and tries to call `payroll_tool`, it cannot succeed — it is literally operating with a credential that excludes `payroll:write`. ZeroID enforces this at the token level, not at the application level.

The rejection message shows the full chain embedded in the token:

```
[Payroll] REJECTED — missing payroll:write
          Delegation chain:
          payroll-agent [email:read payroll:read payroll:write] (depth=0)
          → email-agent [email:read] (depth=1)
          → payroll-agent [email:read] (depth=2)  ← BLOCKED: missing payroll:write
```

This chain is **cryptographically verifiable** — every downstream system can read it from the token's `act` claim without trusting any intermediary.

## Files

- `without_zeroid.py` — the vulnerable pipeline; attack succeeds
- `with_zeroid.py` — fixed with ZeroID; attack is rejected at the tool boundary

## Run

```bash
# Start ZeroID
make setup-keys && docker compose up -d   # from repo root

# Install deps
pip install highflame langgraph 'PyJWT[cryptography]'

# See the attack
python without_zeroid.py

# See the fix
export ZEROID_BASE_URL=http://localhost:8899
export ZEROID_ADMIN_API_KEY=zid_sk_...
python with_zeroid.py
```
