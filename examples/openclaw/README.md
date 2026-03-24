# ZeroID + OpenClaw: Cryptographic Identity & Automated Governance

Enterprises want to deploy AI agents, but security teams are rightly blocking them. The current landscape relies on shared service accounts, long-lived API keys, and untrackable sub-agent delegation—making audit logs meaningless and least-privilege impossible.

**ZeroID** is an open-source identity infrastructure that gives agents cryptographic identities, enforces least-privilege delegation, and enables instant credential revocation across entire agent chains.

### See it in Action
We show the main OpenClaw agent with full permissions delegate a restricted, write-only scope to a sub-agent, followed by a cascading revocation that instantly terminates access for the entire agent chain.

[ZeroID + OpenClaw Demo](https://youtu.be/msboKc9XqRc)

---

### Key Features

* **Verifiable Agent Identities:** Instead of relying on shared service accounts, ZeroID assigns a globally unique, verifiable identity URI (e.g., `spiffe://zeroid.dev/Highflame/OpenClaw/agent/main`) to every agent. Downstream systems know exactly who is calling.
* **Scope-Constrained Delegation:** When an orchestrator spawns a sub-agent, it delegates specific permissions. ZeroID enforces this at the cryptographic level: a sub-agent can only receive a scope that is less than or equal to what the parent holds. The resulting token embeds the full delegation chain and scope provenance.
* **Instant Cascading Revocation:** ZeroID tracks the delegation tree internally. If you revoke an orchestrator's credential, every downstream sub-agent is instantly revoked. It also supports Continuous Access Evaluation for real-time anomaly response.
* **Zero-Rewrite Integration:** No framework rewrites required. ZeroID uses a sidecar for registration and a reverse proxy (Nginx, Caddy, Traefik) to validate tokens and forward identity headers.

### Built on Industry Standards
The OpenID Foundation, NIST, and WIMSE all identify agent identity as a critical unsolved problem. ZeroID implements these requirements via **OAuth 2.1**, **WIMSE/SPIFFE**, and **RFC 8693**.

---

**Get Involved:** Star the repo to follow our progress!

