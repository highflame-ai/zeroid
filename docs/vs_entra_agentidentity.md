 What They're Solving

  Entra Agent Identity: Gives AI agents a first-class identity within the Microsoft ecosystem — distinct from
  service principals and user accounts. Primarily solves "what is this agent?" inside Azure/M365.

  ZeroID: Solves "who authorized this agent, with what scope, through what chain of agents?" — across any
  ecosystem, any platform.

  They're complementary but aimed at different problems.

  ---
  Feature-by-Feature

  ┌────────────────────────────────┬────────────────────────────────┬─────────────────────────────────┐
  │                                │      Entra Agent Identity      │             ZeroID              │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ First-class agent identity     │ ✅                             │ ✅                              │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Agent registry / inventory     │ ✅ (Agent Registry)            │ ✅                              │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Owner/sponsor accountability   │ ✅ (Owner + Sponsor roles)     │ ✅ (created_by / owner_user_id) │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Agent-to-agent delegation      │ ❌                             │ ✅ RFC 8693 + act claim         │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Scope attenuation per hop      │ ❌                             │ ✅ enforced at each exchange    │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Delegation depth enforcement   │ ❌                             │ ✅ max_delegation_depth         │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Cascade revocation down chains │ ❌                             │ ✅ CAE + SSF signals            │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Globally unique identity URI   │ ✅ (tenant-scoped Object ID)   │ ✅ WIMSE/SPIFFE (spiffe://...)  │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Open standards                 │ ❌ (proprietary Graph API)     │ ✅ OAuth 2.1, RFC 8693, WIMSE   │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Cross-platform / any agent     │ ❌ (Microsoft ecosystem only)  │ ✅                              │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Self-hostable / open source    │ ❌                             │ ✅ Apache 2.0                   │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ SDK                            │ PowerShell/Graph API only      │ Python, TypeScript, Rust        │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ M365 / Azure resource access   │ ✅ (licenses, groups, mailbox) │ ❌ (not in scope)               │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Conditional Access / Defender  │ ✅ deep integration            │ ❌                              │
  ├────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
  │ Real-time token verification   │ ✅ via Entra security products │ ✅ JWKS + introspection         │
  └────────────────────────────────┴────────────────────────────────┴─────────────────────────────────┘

  ---
  Key Architectural Differences

  Entra's Blueprint model: Credentials live on the Blueprint (a template), not the Agent Identity itself.
  Creating an agent involves a multi-stage token exchange: Blueprint authenticates → gets T1 → T1 impersonates
  the Agent Identity. This is clever for centralized credential management but is opaque and proprietary.

  ZeroID's delegation model: Each agent has its own API key and identity. When it delegates, it uses RFC 8693
  token exchange — the resulting token carries the act chain explicitly and verifiably at every hop. Any
  downstream system can read the full delegation chain from the token without calling back to a central
  authority.

  ---
  The Critical Gap in Entra

  Entra Agent Identity doesn't address multi-agent delegation at all. If a Copilot Studio orchestrator spawns a
  sub-agent, there's no standard mechanism for the sub-agent's token to carry "I was authorized by this
  orchestrator, which was authorized by this user, with this scope." That's exactly what ZeroID's RFC 8693
  implementation does.

  Entra solves identity registration and SSO within Microsoft. ZeroID solves identity provenance and delegation
  across autonomous agent chains — which is the harder problem the OpenID Foundation whitepaper you cite actually
   identifies as the unsolved one.

  ---
  Practical Takeaway

  If you're building entirely within Azure/M365, Entra Agent Identity gives you Defender, Purview, Conditional
  Access, and M365 app access out of the box — things ZeroID doesn't touch. If you're building multi-agent
  systems across any stack (LangGraph, CrewAI, custom), need verifiable delegation chains, or want open standards
   and portability, ZeroID covers ground Entra fundamentally doesn't.
