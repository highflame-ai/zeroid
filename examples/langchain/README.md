# Scope-Aware Tools: LangChain + ZeroID

This example demonstrates a simple but important idea for agent developers: the same LangChain agent should not always see the same tools.

## The Problem

LangChain tools are often attached to an agent statically. That works for demos, but it gets risky in production: a support agent that should only inspect account state in one context might still be able to call a refund, write, or admin tool in another context unless you add authorization logic everywhere.

## The Solution

ZeroID turns the bearer token into a live capability boundary:

* **Planning-time control:** middleware filters the tool list from the token's scopes, so the model only sees the tools it is allowed to use.
* **Execution-time control:** each tool still calls `session.require_scope(...)`, so sensitive actions stay protected even if the model or app logic makes a mistake.
* **Revocation:** the next tool call re-checks the token, so access disappears as soon as the token is revoked.

## What The Notebook Shows

The notebook runs the **same support agent** against the **same user prompt** three times:

* **Read-only token:** the agent can inspect docs and customer state, but it cannot see the refund tool.
* **Refund-enabled token:** the agent now sees the refund tool and can execute it.
* **Revoked token:** the token becomes inactive, the tool list drops to zero, and the request is denied.

There is no external model dependency in this example. The notebook uses a tiny deterministic LangChain chat model so the ZeroID behavior is easy to see and easy to reproduce locally.

## Why This Matters

For an AI agent developer, this is the practical value of ZeroID:

* Reuse the same agent across low-risk and high-risk contexts without cloning the whole agent graph.
* Keep least privilege at the tool boundary instead of relying on prompts alone.
* Remove access immediately when risk changes, without waiting for token expiry.

## Quickstart

**1. Start ZeroID locally (from the repository root):**
```bash
make setup-keys && docker compose up -d
```

**2. Install notebook dependencies:**
```bash
pip install highflame langchain notebook
```

**3. Open the notebook:**
```bash
jupyter notebook examples/langchain/scope_aware_tools.ipynb
```

By default the notebook talks to `http://localhost:8899`. Set `ZEROID_BASE_URL` if your ZeroID server is running somewhere else. If your deployment protects admin routes, also set `ZEROID_ADMIN_API_KEY`.
