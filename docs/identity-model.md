# ZeroID Identity Model: User, Client, Agent, Resource

Anyone adopting ZeroID for agentic systems hits the same question within the first week: **which identity does the token represent?** The human user who started the session? The software installation (Cursor, Claude Code) that issued the call? The autonomous agent actually doing the work? The resource being called? They all show up in a real request, and at first glance they look like competing answers.

They're not competing. They're **different roles in a single request**, and a well-designed token carries all of them at once as a delegation chain. This doc names those roles, shows how they compose, and walks through the three common trust-federation patterns that emerge when MCP servers have their own authorization stories.

> **The cryptographic caveat up front.** A JWT is signed by exactly one private key, so "one token with Okta + ZeroID + GitHub all inside" is not literally possible — no issuer can forge another's signature. What IS possible is attestation via federation: ZeroID verifies the upstream IdP's ID token and re-asserts the user claims under its own signature (preserving `user_id_iss` to record which IdP authenticated), producing a single JWT authoritative within ZeroID's trust domain. Crossing into a different trust domain (e.g., GitHub) requires a separate token minted by that domain's authority. See [How ZeroID composes claims from upstream IdPs](#how-zeroid-composes-claims-from-upstream-idps) for the direct-federation mechanics and [Three federation patterns](#three-federation-patterns-for-remote-mcp-servers) for the outbound side.

---

## The four identities, named precisely

| Identity | What it represents | How it's proven | Typical claim |
| --- | --- | --- | --- |
| **Human user** | The person behind the keyboard authorizing the work | Interactive OIDC (browser + PKCE, SSO, hardware key) | `user_id` |
| **MCP client** | The software installation / product (Claude Desktop, Cursor install, CI runner) | OAuth 2.1 client credentials, dynamic client registration, or device code flow | `azp` / `client_id` |
| **Agent** | The autonomous software acting right now (a specific Claude Code session, a sub-agent, a headless job) | ZeroID `jwt_bearer` assertion or `api_key` grant, bound to a registered identity | `sub` (WIMSE URI) |
| **Resource** | The MCP server / tool / API being called | Not an identity it proves — it's an audience the token is *scoped for* | `aud` |

There's also a fifth role — the **gateway** — that isn't an identity per se, it's a token broker. Its job is to exchange one token shape for another when the identity domain on either side doesn't trust the other directly.

## They compose in a single token, not in separate ones

RFC 8693 (Token Exchange) already designed this. A single JWT carries all four roles via standard claims:

```json
{
  "iss":       "https://auth.example.com",
  "sub":         "spiffe://example.com/acct/proj/agent/claude-code-session-abc",
  "aud":         "mcp.github-tools.internal",
  "user_id":     "alice@example.com",
  "trusted_by":  "gateway-prod-us-west",
  "azp":         "cursor-macos-v1.2.3",
  "scopes":      ["mcp:github:create_issue", "mcp:github:list_repos"],
  "iat":         1735600000,
  "exp":         1735603600,
  "jti":         "cred-xyz-789",
  "act": {
    "sub":       "spiffe://example.com/acct/proj/agent/claude-code-orchestrator",
    "act": {
      "sub":     "spiffe://example.com/acct/proj/user-session/alice-session-xyz"
    }
  }
}
```

Reading this token top-down tells you the whole story of the request:

- **Who is this token for?** `aud` → the GitHub MCP server.
- **What is the active actor?** `sub` → a specific Claude Code session (agent identity).
- **On whose behalf?** `user_id` → alice, the human user.
- **Who vouched for the user?** `trusted_by` → the gateway service that performed the OIDC verification against the upstream IdP (see [How ZeroID composes claims from upstream IdPs](#how-zeroid-composes-claims-from-upstream-idps) for why ZeroID trusts this claim).
- **Via what software?** `azp` → Cursor 1.2.3, the MCP client installation.
- **Who delegated?** `act.sub` → the orchestrator session that spawned this agent.
- **And before them?** `act.act.sub` → Alice's original login session, where the whole chain started.

No identity is lost. Every hop is accountable. Every field has a standardized home.

## Where each identity gets established

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Alice's laptop                              │
│                                                                      │
│   [Alice] ──browser OIDC login─► Okta (or Entra / Auth0 / Google)   │
│                                    │                                 │
│                                    │ issues Okta ID token:           │
│                                    │   sub=alice, iss=okta           │
│                                    │                                 │
│                                    ▼                                 │
│   [Cursor]  ◄────── Okta ID token ─────                             │
│      │                                                               │
│      │ Preferred: ZeroID verifies Okta directly (tracked in #88).    │
│      │ Today:     trusted-service broker verifies, ZeroID trusts it. │
│      │                                                               │
│      ▼                                                               │
│   ZeroID — mints a session token carrying whichever provenance the   │
│            chosen path supports (user_id_iss for direct;             │
│            trusted_by for broker).                                   │
│                                                                      │
│   On agent spawn, Cursor calls token_exchange:                       │
│      subject_token = <session token>                                 │
│      actor_token   = <agent's signed JWT assertion>                  │
│   → ZeroID issues task token:                                        │
│              sub = spiffe://...agent/claude-code-session-abc         │
│              user_id = alice@example.com   (propagated)              │
│              user_id_iss or trusted_by    (propagated)               │
│              azp = cursor-macos-v1.2.3                               │
│              act.sub = claude-code-orchestrator                      │
│              scopes narrowed to task requirements                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                │  agent task token on every MCP call
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Gateway (token broker)                          │
│                                                                      │
│   • Validates token (JWKS / introspection)                           │
│   • Decides: does the remote MCP server accept ZeroID tokens?        │
│                                                                      │
│   Case A (federated):  forward token as-is.                          │
│   Case B (isolated):   RFC 8693 token_exchange at the MCP server's   │
│                        own auth endpoint, attaching Alice's          │
│                        per-server refresh token from the vault.     │
│                        Issue a server-specific token, narrowed to    │
│                        the MCP server's audience, carrying the same  │
│                        delegation chain via `act`.                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Remote MCP server                                │
│                                                                      │
│   SEP-1763 validation interceptor (e.g., zeroid-auth)                │
│   • JWKS verify, aud check                                           │
│   • Populate interceptorState.principal = { agent, user_id, act }   │
│                                                                      │
│   SEP-1763 scope interceptor                                         │
│   • Enforce mcp:github:create_issue against principal.claims.scopes  │
│                                                                      │
│   SEP-1763 audit interceptor                                         │
│   • Emit event with full chain to SIEM                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

Each layer writes exactly the fields it's responsible for, and each downstream layer reads what the ones above provided. No layer re-parses anything.

## How ZeroID composes claims from upstream IdPs

You won't store human users in ZeroID. Okta / Entra ID / Auth0 / Google Workspace own that directory; ZeroID's job is agent identity. When Alice logs in to Cursor, her identity is first minted by the IdP as an OIDC ID token — signed by the IdP. A few milliseconds later, that identity needs to land as a `user_id` claim inside a ZeroID-signed token that the agent will use for the rest of its session.

Two patterns get it there. They produce substantively different tokens and are not equivalent.

### Direct IdP federation (spec-aligned preferred path)

**Status: tracked in [#88](https://github.com/highflame-ai/zeroid/issues/88); preferred default once shipped.**

ZeroID verifies the IdP's ID token itself, using the IdP's published JWKS. Authentication context — which IdP did the authenticating, when, at what assurance level — is preserved end-to-end as first-class claims the consumer can read.

```
1. Alice → Cursor → Okta
   Interactive OIDC login (browser, PKCE, SSO, MFA).
   Okta issues: ID token signed by Okta.
       { sub: alice@ex.com, email, groups, aud: cursor, iss: okta }

2. Cursor → ZeroID
   POST /oauth2/token
     grant_type           = urn:ietf:params:oauth:grant-type:token-exchange
     subject_token        = <Okta ID token>
     subject_token_type   = urn:ietf:params:oauth:token-type:id_token
     account_id, project_id

3. ZeroID resolves Okta from its configured external_issuers allowlist,
   fetches Okta's JWKS, verifies signature / iss / aud / exp / nbf / iat,
   extracts user claims per the configured claim-mapping rules, then
   mints a new token:

       {
         iss:          ZeroID,
         sub:          <cursor client identity>,
         user_id:      alice@ex.com,                      ← from Okta's sub/email
         user_id_iss:  https://auth.example.okta.com,     ← real upstream issuer
         auth_time:    1735600000,                         ← when Okta authenticated
         scopes:       [...]
       }
       Signed by ZeroID.
```

**Why this is the preferred default.** It's what the standards actually ask for:

- **RFC 8693** defines `subject_token_type = id_token` precisely for this case — the receiver verifies the ID token.
- **OIDC Core** expects `iss` (and its propagation) to trace to the IdP that did the authenticating.
- **RFC 9068 (JWT Access Token Profile)** specifies `acr` / `amr` / `auth_time` as authentication-context claims that only make sense if you know where auth happened.
- **NIST SP 800-63C §4.1** requires assertions to name the IdP that authenticated the subject, not an intermediate aggregator.
- **CoSAI Agentic IAM**'s "prove control on demand" principle collapses without IdP-level provenance.

Any regulator, auditor, or consumer that asks *"which IdP authenticated this user?"* gets an answer directly from `user_id_iss`. The broker pattern below can't.

### Trusted-service broker (currently-available fallback)

**Status: implemented today via `ExternalPrincipalExchange`.** Lossier on provenance than the direct path. Use when an operational constraint below applies; otherwise wait for #88.

A deployer-controlled service verifies the IdP's token, extracts claims, and calls ZeroID with pre-validated user context. ZeroID validates the *caller* — not the original IdP token — via its `TrustedServiceValidator` hook.

```
1. Alice → Cursor → Okta  (same as above)

2. Cursor → Trusted service (gateway / admin tier / identity broker)
   The trusted service verifies Okta's signature, extracts user claims,
   resolves tenant context.

3. Trusted service → ZeroID
   POST /oauth2/token
     grant_type           = urn:ietf:params:oauth:grant-type:token-exchange
     subject_token        = <Okta JWT>
     subject_token_type   = urn:ietf:params:oauth:token-type:jwt
     user_id              = alice@ex.com      ← extracted by trusted service
     account_id, project_id

4. ZeroID validates the CALLER via TrustedServiceValidator.
   Does NOT re-verify Okta's signature — that happened in step 2.
   Mints a new token:

       {
         iss:              ZeroID,
         sub:              <cursor client identity>,
         user_id:          alice@ex.com,
         trusted_by:       gateway-prod-us-west,   ← which service vouched
         token_exchange:   "external_principal",
         scopes:           [...]
       }
       Signed by ZeroID.
```

**What's lost.** `trusted_by` is **service-granular, not IdP-granular**. The consumer can see *which service vouched* but not *which IdP authenticated*. For regulators, audit trails, or downstream policy engines that need per-IdP provenance (common in finance and healthcare), this is information that's just gone. If Alice authenticates via corporate Entra on her laptop and personal Google on her phone and both route through the same gateway, the ZeroID tokens look identical at the provenance layer. They shouldn't.

### When the broker is actually right

Three narrow cases where the broker's simplifications are operationally justified:

1. **You already run a dedicated identity-broker tier.** The gateway is doing OIDC verification for many downstream services (not just ZeroID), with its own policy, audit, and compliance boundary. Adding direct federation to ZeroID duplicates work and creates two places where IdP trust config lives. Pick one.

2. **Complex per-deployment claim mapping.** Your claim rules involve cross-referencing an internal HR directory, normalizing identifiers across merged orgs, or applying time-of-day policy. Keeping that logic in a dedicated broker is cleaner than extending ZeroID's config.

3. **Air-gapped or egress-restricted ZeroID.** ZeroID runs in an environment that can't reach external IdP JWKS endpoints. A broker in the DMZ does the IdP round-trip; ZeroID trusts what it gets.

If none of these apply, use direct federation.

### Provenance comparison

| Question a consumer might ask | Direct federation (#88) | Broker (today) |
|---|---|---|
| Which IdP authenticated this user? | `user_id_iss` | Not preserved |
| When did that authentication happen? | `auth_time` | Not preserved |
| At what assurance level? | `acr` / `amr` | Not preserved |
| Which service vouched? | N/A (direct) | `trusted_by` |
| Is the token ZeroID-signed? | ✅ | ✅ |
| Can I reason about the trust chain from the token alone? | Yes | No — need to know what `trusted_by` maps to |

### Wiring the trusted-service validator

If you use the broker path today, the `TrustedServiceValidator` hook is deployer-supplied. Typical implementations:

- **mTLS at the ingress** — validator checks the presented client certificate against an internal CA.
- **Service JWT** — the trusted service presents its own ZeroID-issued service token; validator verifies it inline.
- **Network policy** — validator reads a trusted header populated by a locked-down ingress controller.

See `internal/service/oauth.go:ExternalPrincipalExchange` for the code path and `SetTrustedServiceValidator` on `Server` for wiring.

### Optional: preserving the upstream token for high-assurance paths

Independent of which federation pattern you use, for operations that need *direct cryptographic proof-of-authentication* (the Okta signature, not ZeroID's attestation of it), the deployer can configure Cursor to carry the Okta access token in a secondary header (`X-User-Assertion: <okta jwt>`) on specific requests. The MCP server's interceptor chain then verifies both: the ZeroID token for agent identity + delegation, the Okta token for direct user proof. This is uncommon — most deployments accept transitive trust via federation — but it's the answer when regulatory or contractual requirements demand it.

## Three federation patterns for remote MCP servers

The architecturally interesting question is which MCP servers accept which identities. Three patterns cover almost every real deployment:

### Pattern 1 — Fully federated (if you control the MCP server)

The MCP server trusts ZeroID directly as its authorization server. The agent's ZeroID token is the token the server verifies. No token exchange needed.

- **When:** internal MCP servers you deploy inside the same trust boundary as ZeroID.
- **Setup:** MCP server runs `zeroid-auth` interceptor (or equivalent), configured with ZeroID's issuer and JWKS URL.
- **Tradeoff:** simplest; doesn't work for third-party MCP servers you don't control.

### Pattern 2 — MCP server has its own OAuth (common for third-party MCPs)

GitHub, Slack, Atlassian, etc. run their own authorization servers and don't know your ZeroID exists. They want either a user OAuth token (OIDC flow, user logs in once) or a client credentials token (the gateway is a registered OAuth client). The agent's identity is invisible to these MCP servers — only Alice (user) or the gateway (client) shows through.

- **When:** calling external MCP servers operated by third parties.
- **Setup:** the gateway holds Alice's refresh token for each server in a credential vault. On every MCP call initiated by Alice, the gateway attaches a fresh access token minted by that server's auth system.

**Two tokens in flight, not one.** This pattern is where the single-JWT composition story visibly breaks. At the gateway boundary the Authorization header gets swapped:

```
Agent → Gateway:   Authorization: Bearer <ZeroID task token>
                                         (iss=ZeroID, user_id=alice, sub=<agent>,
                                          act.sub=<orchestrator>, scopes=[...])

Gateway:           [validate ZeroID token]
                   [lookup alice's github refresh token in vault]
                   [mint fresh GitHub access token via refresh flow]

Gateway → GitHub:  Authorization: Bearer <GitHub access token>
                                         (iss=github.com, sub=<alice's github id>)
```

The two tokens are signed by different issuers, live in separate trust domains, and are never cryptographically combined. GitHub verifies only the GitHub-issued token; ZeroID's token never leaves the gateway's memory.

**What gets lost.** GitHub's audit log can reconstruct only: "user alice invoked `create_issue` at 14:37." It cannot see:

- Which agent acted for Alice (was it Claude Code? Cursor-native? a scheduled batch job?)
- Which orchestrator session delegated the authority
- The delegation depth or the `act.sub` chain
- The task context (`task_id`, `allowed_tools`, `workspace`)

Those dimensions live in ZeroID's audit stream, not GitHub's. An SRE investigating "why did Alice file 400 spammy issues last night?" can answer *that it was Alice* from GitHub's logs and *which agent it was* only by correlating to ZeroID's logs via timestamp + user. There's no cryptographic linkage — only log-level correlation — and only operations teams with access to both log systems can reconstruct the full picture.

**Mitigations.** Three options, best to worst:

1. **Prefer Pattern 3** for any third-party MCP that implements Token Exchange (see below). Preserves the chain cryptographically.
2. **Correlation IDs**. Gateway injects a `X-Request-ID` / `traceparent` into the outbound GitHub request; the same ID is logged on the ZeroID side. Best-effort link, readable by a human joining two log streams.
3. **Accept the loss** for low-stakes third-party integrations. For high-stakes ones (finance, healthcare, prod-write) either pick a federated MCP server or hold the agent back from that tool.

### Pattern 3 — Delegated via RFC 8693 (the right answer when available)

The remote MCP server implements Token Exchange. The gateway presents:
- `subject_token` = the agent's ZeroID task token (the full chain).
- `actor_token` = the gateway's own credential (proving it's trusted to request the exchange).

The MCP server's auth issues a server-specific token, narrowed to that server's audience, preserving the `act` chain from the original.

- **When:** both sides implement RFC 8693 and have federated trust (maybe via OAuth Federation / OpenID Federation — see limitations below).
- **Setup:** one-time out-of-band trust config between ZeroID and the remote MCP server's auth (issuer allowlist, JWKS exchange). Runtime flow is automatic.
- **Tradeoff:** best long-term answer; depends on the remote side implementing RFC 8693 — adoption is still thin.

The gateway is what reconciles the difference between patterns. The validation interceptor at the MCP server boundary is agnostic about which upstream model you picked — it just validates whichever token the MCP server trusts.

## Reading identities in your code

With the `pkg/authjwt` client library, each role is accessible as a typed claim on the verified identity:

```go
import "github.com/highflame-ai/zeroid/pkg/authjwt"

claims, err := verifier.Verify(ctx, tokenString)
if err != nil { return err }

userID    := claims.UID              // "alice@example.com"
clientID  := claims.AuthorizedParty  // "cursor-macos-v1.2.3"
agentURI  := claims.Subject          // "spiffe://.../agent/claude-code-session-abc"
audience  := claims.Audience         // ["mcp.github-tools.internal"]
scopes    := claims.Scopes           // ["mcp:github:create_issue", ...]

// Delegation chain (RFC 8693 act):
if agent := claims.Agent(); agent != nil {
    delegator := agent.DelegatedBy   // act.sub, the immediate delegator
    depth     := agent.DelegationDepth
}
```

The TypeScript and Python SDKs expose the same structure. The interceptor packages in `examples/` populate `interceptorState.principal.claims` with this shape, so downstream interceptors (scope, rate-limit, audit) read one standard map instead of digging into vendor-specific fields.

## What ZeroID does vs. what the deployer does

| Concern | ZeroID | Deployer |
| --- | --- | --- |
| Issue agent tokens, mint JWTs, sign with ES256/RS256 | ✅ | |
| Run the OIDC user-login flow for human sessions | ✅ (PKCE + device-code) | |
| Preserve delegation chains via RFC 8693 `act` | ✅ | |
| Intersect scopes across delegation hops | ✅ | |
| Emit CAE signals for cascade revocation | ✅ | |
| Hold third-party OAuth refresh tokens (Pattern 2 credential vault) | ❌ | ✅ at the gateway |
| Decide federation policy with external issuers (Pattern 3 trust config) | ❌ | ✅ |
| Validate tokens at the MCP server boundary | ❌ | ✅ via interceptor / authjwt / forward-auth |

ZeroID is the identity source of truth for agents. It does not own your user directory, your third-party OAuth relationships, or your MCP server auth policies. Those are deployer responsibilities that ZeroID is designed to compose with.

## References

- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — Token Exchange. The `act` claim and delegation chain semantics.
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) — Token Introspection. The revocation side-channel.
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JWT. Claim registry (`sub`, `aud`, `iss`, `iat`, `exp`, `jti`).
- [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) — OAuth 2.0 Authorization Server Metadata. The `.well-known` discovery path the gateway uses in Pattern 3.
- [SPIFFE Workload API](https://spiffe.io/) / WIMSE — the URI format for agent `sub` values.
- [CoSAI Agentic IAM](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agentic-identity-and-access-control.md) — architectural framing that matches this doc's pattern.
- [SEP-1763](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1763) — MCP Interceptors proposal where `interceptorState.principal` lives.

## Worked examples in this repo

- [`examples/openclaw/`](../examples/openclaw/) — sidecar that registers agents and swaps provider API keys for ZeroID short-lived tokens. Demonstrates Pattern 1 end-to-end with nginx forward-auth.
- [`examples/langgraph/confused_deputy.py`](../examples/langgraph/) — why per-hop enforcement (not just gateway-edge) matters, and how the `act` chain defeats confused-deputy attacks.
- [`examples/langchain/scope_aware_tools.ipynb`](../examples/langchain/) — scope intersection through the lens of tool-level authorization.
