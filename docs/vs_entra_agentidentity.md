# ZeroID vs. Microsoft Entra Agent ID

Microsoft announced [Entra Agent ID](https://learn.microsoft.com/en-us/entra/identity/) in 2024 as a first-class identity type for AI agents inside the Microsoft ecosystem. ZeroID solves a different — and larger — problem: cryptographically verifiable delegation chains for agents across any stack. This doc is a side-by-side comparison for teams deciding between them (or planning to use both).

## What each solves

**Entra Agent ID** gives AI agents a first-class identity distinct from service principals and user accounts, inside Azure / Microsoft 365. It primarily answers *"what is this agent, and what M365 resources can it touch?"*

**ZeroID** answers *"who authorized this agent, with what scope, through what chain of sub-agents?"* — across any ecosystem, any platform, any LLM provider.

The two are complementary. They aim at different questions and occupy different layers of the stack.

---

## Feature comparison

| Capability | Entra Agent ID | ZeroID |
| --- | --- | --- |
| First-class agent identity | ✅ | ✅ |
| Agent registry / inventory | ✅ (Agent Registry) | ✅ |
| Owner / sponsor accountability | ✅ (Owner + Sponsor roles) | ✅ (`created_by` / `owner_user_id`) |
| Globally unique identity URI | ✅ (tenant-scoped Object ID) | ✅ WIMSE / SPIFFE (`spiffe://...`) |
| Agent-to-agent delegation | ❌ | ✅ RFC 8693 with `act` claim |
| Scope attenuation per hop | ❌ | ✅ enforced at each exchange |
| Delegation depth enforcement | ❌ | ✅ `max_delegation_depth` per policy |
| Cascade revocation down chains | ❌ | ✅ CAE + SSF signals |
| Real-time token verification | ✅ (via Entra security products) | ✅ JWKS + RFC 7662 introspection |
| Open standards | ❌ (proprietary Graph API) | ✅ OAuth 2.1, RFC 8693, RFC 7662, WIMSE |
| Cross-platform / any agent framework | ❌ (Microsoft ecosystem) | ✅ |
| Self-hostable / open source | ❌ | ✅ Apache 2.0 |
| SDK coverage | PowerShell / Graph API | Python, TypeScript, Rust |
| M365 / Azure resource access | ✅ (licenses, groups, mailbox) | ❌ (not in scope) |
| Conditional Access / Defender integration | ✅ deep integration | ❌ |

---

## Architectural differences

### Entra's Blueprint model

Credentials live on the *Blueprint* — a template — rather than on the Agent Identity itself. Creating an agent involves a multi-stage token exchange: the Blueprint authenticates, receives a bootstrap token (T1), and T1 then impersonates the Agent Identity. Clever for centralized credential management inside Azure, but the exchange is opaque, proprietary, and not portable outside Microsoft's control plane.

### ZeroID's delegation model

Every agent has its own identity and its own credential (API key, JWT-bearer assertion, or derived task token). When an agent delegates to a sub-agent, it uses RFC 8693 token exchange — the resulting token carries the `act` claim explicitly and verifiably at every hop. Any downstream system can read the full delegation chain from the token itself, without calling back to a central authority.

The practical difference: ZeroID tokens are **self-describing**. Hand any token to any service, that service can verify the signature, walk the `act` chain, and know the full provenance of the action. Entra tokens require round-tripping to Microsoft Graph to get the equivalent information, and only if you're inside the Microsoft tenant.

---

## The gap: multi-agent delegation

Entra Agent ID doesn't address multi-agent delegation at all. If a Copilot Studio orchestrator spawns a sub-agent, there's no standardized mechanism for the sub-agent's token to carry *"I was authorized by this orchestrator, which was authorized by this user, with this scope."* Once the agent chain spans more than one hop — or crosses out of Azure — provenance breaks.

That multi-hop provenance is the problem [the OpenID Foundation's agentic identity work](https://openid.net/foundation-white-papers/) (and the [CoSAI Agentic IAM paper](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agentic-identity-and-access-control.md)) flag as the central unsolved piece of agentic IAM. ZeroID's RFC 8693 implementation is specifically designed to solve it.

---

## Choosing between them

**Use Entra Agent ID if:**

- You're building entirely within Azure / Microsoft 365.
- Your agents need direct access to M365 resources (licenses, groups, mailbox, Teams, SharePoint) and you want Defender / Purview / Conditional Access coverage out of the box.
- You don't need multi-hop delegation — your agents are single-purpose and talk only to Microsoft-hosted services.

**Use ZeroID if:**

- You're building multi-agent systems across any stack (LangGraph, CrewAI, AutoGen, custom, or mixed).
- You need verifiable delegation chains where every hop is reconstructable from the token alone.
- You want open standards and portability — OAuth 2.1, RFC 8693, WIMSE / SPIFFE — with no lock-in to a single cloud vendor.
- You need self-hosting for data-residency, air-gap, or regulatory reasons.

**Use both if:**

- You have agents inside Azure that access M365 resources, *and* agents outside Azure (or agents that delegate to external systems). Register the agent in both: Entra for M365 resource access, ZeroID for delegation chains and cross-platform audit. The two are orthogonal — an agent can carry both an Entra identity and a ZeroID credential without conflict, because they're asserting different facts.

For the mechanics of how the ZeroID identity composes with an Entra-held user identity (or any other upstream IdP), see [docs/identity-model.md](./identity-model.md).

---

## References

- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange, the delegation primitive ZeroID uses.
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) — OAuth 2.0 Token Introspection.
- [WIMSE / SPIFFE](https://spiffe.io/) — Workload identity URI format.
- [Microsoft Entra Agent ID docs](https://learn.microsoft.com/en-us/entra/identity/) — Official Entra documentation.
- [CoSAI Agentic IAM](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agentic-identity-and-access-control.md) — Vendor-neutral framing of the agentic IAM problem.
- [ZeroID Identity Model](./identity-model.md) — How user / client / agent / resource identities compose across trust domains.
