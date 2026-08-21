# Client ID Metadata Documents (CIMD) — Reference

ZeroID implements **Client ID Metadata Documents** ([`draft-ietf-oauth-client-id-metadata-document`](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/), adopted by the OAuth WG in October 2025) — the client-onboarding model the [MCP Authorization specification (2025-11-25)](https://modelcontextprotocol.io/) names as its preferred default.

CIMD lets an OAuth client complete an `authorization_code` + PKCE flow against ZeroID **with zero pre-registration**: no admin console, no RFC 7591 dynamic-registration call, no shared secret. The client uses a stable `https://` URL as its `client_id`; ZeroID fetches the JSON metadata document published at that URL, validates it, and treats it as an ephemeral public PKCE client for the duration of the flow.

For where CIMD sits relative to ZeroID's other onboarding paths, see the [DCR reference](dpop-and-dcr.md#choosing-between-agent-identity-registration-and-oauth-dcr).

---

## What it solves

Open agent ecosystems (MCP is the motivating example) break both classic onboarding models:

- **Pre-registration** — a human registers the client with every authorization server it will ever talk to. Unworkable when an agent connects to hundreds of servers it discovers at runtime.
- **Dynamic Client Registration** ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)) — automates registration but grows an unbounded row per (client × server), needs a write endpoint exposed, and *transmits* a claimed identity without *verifying* it (anyone can `POST` `"client_name": "Claude Desktop"`).

CIMD flips the trust model from "central authority database" to **"domain ownership, verified through TLS + DNS."** The client self-publishes its metadata at a URL it controls; the `redirect_uris` array in that document is the primary anti-impersonation control. An attacker who copies a legitimate client's `client_id` still cannot receive its authorization codes, because the attacker's callback host won't appear in the legitimate document's `redirect_uris`.

---

## Wire shape

### 1. The client publishes a metadata document

At a stable HTTPS URL it controls, e.g. `https://app.example.com/oauth/client.json`:

```json
{
  "client_id":    "https://app.example.com/oauth/client.json",
  "client_name":  "Example MCP Client",
  "client_uri":   "https://app.example.com",
  "redirect_uris": [
    "http://127.0.0.1:3000/callback",
    "http://localhost:3000/callback"
  ],
  "grant_types":    ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "notebook:read notebook:write"
}
```

### 2. The client starts the flow with its URL as `client_id`

`GET` or `POST /oauth2/authorize` (unchanged from the [normal PKCE flow](../README.md#real-world-patterns) — the only difference is the `client_id` value).

A browser-based client uses the RFC 6749 §4.1.1 redirect:

```http
GET /oauth2/authorize?client_id=https%3A%2F%2Fapp.example.com%2Foauth%2Fclient.json
    &redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback
    &response_type=code
    &code_challenge=<S256 challenge>
    &code_challenge_method=S256
    &state=<opaque> HTTP/1.1
Cookie: <your session cookie>
```

`state` is **optional** here. PKCE is mandatory on this endpoint and carries the
CSRF binding that `state` was originally needed for, so OAuth 2.1 leaves `state`
to carry application state only. ZeroID round-trips it verbatim when present and
does not require it. It is shown because most clients have somewhere to return
the user to.

**Serving the browser leg *directly* at `/oauth2/authorize` needs a GET-capable
`PrincipalResolver`, which ZeroID does not ship.** A browser cannot set a custom
header on a top-level navigation, and the resolver-facing `Form` accessor is
bound to the POST body, so a resolver that reads `req.Form(...)` sees nothing on
a GET.

Direct access is not the only shape, though. There are two ways to connect the
browser leg, and the second — which needs no GET-capable resolver at all — is
usually the better one:

1. **Register a cookie-reading resolver** (`req.Cookie(...)`) and own the login
   and consent screens behind it. This makes `/oauth2/authorize` itself the
   browser-facing endpoint, which brings the CSRF obligations described below —
   `SameSite=Lax` still sends the cookie on a cross-site top-level navigation,
   and CIMD accepts an attacker-published `client_id` with its own
   `redirect_uri`.

   ZeroID will send the user to that login screen for you: return
   `ErrPrincipalInteractionRequired` from the resolver when there is no session
   and register the surface with `Server.SetInteractiveLoginURL`. See the
   resolver bullet below for what that does and does not do — in particular
   **it is refused for a CIMD client unless `cimd.allowed_domains` is set**, so
   on an open-mode deployment a CIMD authorization request only succeeds for a
   user who already has a session. If you want browser-driven CIMD clients to
   complete this route — the MCP case — you have to name the hosts that may
   publish.
2. **Front the browser leg above ZeroID and hand off over POST.** Your own
   surface owns the redirect, authenticates the human however you already do,
   and then POSTs to `/oauth2/authorize` with a credential a form-based resolver
   reads — an RFC 7523 assertion signed by that surface, say, verified against
   its published JWKS. The browser never reaches this endpoint, so no GET-capable
   resolver is needed.

   What route 2 does **not** remove is authorization-request CSRF — it moves it
   to your surface. An attacker can still navigate a victim's browser to that
   surface with an attacker-published `client_id`; if it authenticates from a
   `SameSite=Lax` session cookie and mints the assertion without further
   interaction, the same code is issued for the victim, one hop earlier. The
   CSRF-protected interaction — an explicit consent gesture behind an
   anti-forgery token — has to happen at the fronting surface before the
   assertion is minted. What the route removes is the exposure at
   `/oauth2/authorize` itself, which is no longer reachable by navigation.

Highflame's own deployment takes route 2 — Studio authenticates the user, mints
an assertion, and POSTs; AuthN's assertion resolver verifies it and ZeroID mints
the code. (For MCP clients specifically that routing is in flight: today Studio
mints their codes locally with its own CIMD check, and highflame-studio#1392
brings them back through this path.) Route 1 exists for deployers with no such
surface. Either way ZeroID stays the engine: it validates the CIMD document,
enforces the `redirect_uri` allow-list, and issues the code.

**ZeroID cannot detect this for you.** Its AS metadata omits the
`authorization_code` grant when *no* resolver is registered, but it cannot
introspect what a registered resolver reads — so a deployment whose resolvers are
all form-based *and* has no fronting surface advertises the grant and then 401s
every browser redirect. If that is you, call
`Server.SetAuthorizationCodeAvailable(func() bool { return false })` until one of
the two routes above exists; otherwise the metadata promises a flow the
endpoint cannot finish, which is exactly the failure this is meant to prevent.
(A route-2 deployment is fine as-is: its form-based resolver *is* the browser
leg's back end, fed by the surface.)

A `false` answer turns the flow **off**, not merely unadvertised:
`/oauth2/authorize` answers 503 on both GET and POST. Reach for it if you run a
cookie-based resolver and are not yet ready for the CSRF obligations below — a
cookie resolver is safe while POST is the only route, because `SameSite=Lax`
withholds the cookie on a cross-site POST, and becomes reachable by cross-site
top-level navigation once GET is mounted.

**Errors are not redirected to an *unvetted* CIMD client.** RFC 6749 §4.1.2.1 says report most
`/oauth2/authorize` failures by redirecting to the client's registered
`redirect_uri`, and ZeroID does — for clients somebody registered. A CIMD client's
`redirect_uris` come from a document it published itself, so with `allowed_domains`
empty the destination is attacker-*chosen*, and honouring the rule would make the
endpoint an unauthenticated redirector: the failure being reported is "you have no
credential", so no credential is needed to trigger it, and the first hop carries
your origin. CIMD clients therefore get the §5.2 JSON body instead, and the
interactive-login redirect is refused for them too — an unvetted client does not
get to borrow your login surface's credibility.

The cost is real and worth naming: a browser-driven CIMD client cannot learn its
error from the callback and has to read the JSON body. Setting
`cimd.allowed_domains` restores the redirect, because vetting which hosts may
publish restores the assumption §4.1.2.1 is built on. The gate is provenance, not
CIMD.

**That hatch only works on a single-tenant deployment.** `allowed_domains` is one
deployment-wide set — `domainAllowed` takes no tenant — so on a multi-tenant AS it
cannot express one customer's policy, and setting it accepts one customer's
publishers on behalf of all of them. There it is effectively all-or-nothing, which
in practice means CIMD clients do not get error redirects. Tracked in zeroid#286;
the tenant is not even known at the point CIMD resolves, so this is a design
question rather than a missing config field.

Three things a deployer must handle:

* **The resolver starts the interaction; it does not render it.**
  `PrincipalResolver` returns `(*Principal, error)` and has no `ResponseWriter`,
  so it cannot render a consent screen — but it can ask for one. Return
  `ErrPrincipalInteractionRequired` and ZeroID redirects the user agent to the
  surface you registered with `Server.SetInteractiveLoginURL`, appending
  `return_to` so the flow resumes at `/oauth2/authorize` once you have
  authenticated them. Your resolver then only has to recognise the session that
  established.

  `return_to` is rebuilt from the parameters ZeroID validated, never copied from
  the inbound URL, so nothing extraneous a caller appended — including a
  credential in the wrong channel — is forwarded to your login surface.

  Only GET is redirected: a POST caller has no user agent. With no target
  configured the sentinel degrades to `access_denied`, because a resolver cannot
  conjure a surface the deployment does not have — and it is refused for an
  *unvetted* CIMD client, per the provenance rule above. Setting
  `cimd.allowed_domains` lifts that refusal along with the error-redirect one:
  they are the same check.

  Use `Server.Use` middleware instead if you want to own the whole interaction
  including the 302.

  `Server.Use` chains, so registering the consent gate alongside whatever else
  you already use it for is safe: middleware runs in registration order, first
  registered outermost. (It used to *replace*, silently dropping everything but
  the last registration — if you are reading older notes that say to compose
  manually at the call site, that is no longer necessary. Fixed in zeroid#276.)
* **CSRF.** A cookie-authenticated `GET` is reachable by top-level navigation
  from any site (`SameSite=Lax` still sends the cookie), and CIMD accepts any
  attacker-published `client_id` + its own `redirect_uri`. Require an explicit
  user interaction — a consent screen with a CSRF token — before issuing a code.
  This is the same reason a real AS never mints on the bare redirect.
* **Consent content.** CIMD's premise is that the AS shows the user something
  about a client it has never seen, and marks it unverified. ZeroID does not
  hand you that metadata today: `client_name` / `client_uri` / `logo_uri` are
  parsed into the internal document type but dropped when it is synthesized
  into a client (`domain.OAuthClient` has no such fields), and the document
  type is unexported. Your consent surface must fetch and validate the CIMD
  document itself — applying the same rules ZeroID does, in particular the
  draft §4 self-reference check that the document's own `client_id` equals the
  URL it was fetched from, without which the screen can be made to display
  someone else's branding.

A CLI client can post the same parameters as a form instead:

```http
POST /oauth2/authorize HTTP/1.1
Content-Type: application/x-www-form-urlencoded

client_id=https%3A%2F%2Fapp.example.com%2Foauth%2Fclient.json
&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback
&response_type=code
&code_challenge=<S256 challenge>
&code_challenge_method=S256
&state=<opaque>
&api_key=zid_sk_...
```

**Credentials never travel in the query string.** On `GET`, the principal must
arrive in a header (`X-API-Key`, or `Authorization: Bearer zid_sk_…`) or a
cookie — a URL ends up in access logs, browser history, and `Referer`. The
protocol parameters above are fine there; the credential is not.

ZeroID detects the `client_id` is a CIMD URL, fetches + validates the document, checks the `redirect_uri` against the document's `redirect_uris`, mints the auth code, and 302s back to the callback with `?code=…&state=…`.

### 3. The client exchanges the code

`POST /oauth2/token` with `grant_type=authorization_code`, the same CIMD URL as `client_id`, the `code_verifier`, and the `redirect_uri`. No `client_secret` — CIMD clients are public; PKCE is the proof of possession. ZeroID re-resolves the document (served from cache) and issues the token.

### 4. Refresh, introspect, revoke

When the document's `grant_types` includes `refresh_token`, the exchange also returns a rotating refresh token. On `grant_type=refresh_token` ZeroID re-resolves the document before rotating — which gives CIMD its lifecycle story: **a client that unpublishes its metadata document can no longer rotate** (the presented token is not consumed on resolution failure, so a transient outage doesn't brick the session). The introspection and revocation endpoints likewise accept a CIMD `client_id` as a public-client identification (RFC 7662/7009 §2.1), so stock OAuth libraries that attach `client_id` to those calls work unmodified.

---

## How ZeroID resolves + validates a document

Implemented in [`internal/service/cimd.go`](../internal/service/cimd.go); wired into the auth-code flow at `OAuthService.IssueAuthCode` (`/oauth2/authorize`) and `OAuthService.authorizationCode` (`/oauth2/token`).

1. **Detect — registry first.** The client registry is always consulted first; CIMD resolution only runs when the registry misses **and** the `client_id` is an absolute `https://` URL with a host and a non-root path (`IsCIMDClientID`). Registry-first keeps any pre-existing registry client whose `client_id` happens to be a URL working unchanged, and gives deployers a pinning mechanism: registering a client under a CIMD URL overrides the document. Anything not CIMD-shaped behaves exactly as before — CIMD is purely additive.
2. **Validate the URL** against draft-02 §3: `https` scheme, non-empty host, path present, **no fragment** (MUST NOT), **no userinfo** (MUST NOT), **no `.` or `..` path segments** (MUST NOT), and ≤ 255 characters (the `client_id` is persisted into `VARCHAR(255)` columns downstream).

   Two of these carry their own weight beyond conformance. Userinfo is the phishing shape — `https://legit.example.com@evil.example/client.json` resolves to `evil.example` while *reading* as `legit.example.com` on a consent screen or in an audit log. Dot segments would give one document many spellings, splitting the resolution cache and handing one client several identities the §4 self-reference check cannot distinguish.

   ZeroID also rejects a **query string**, where the draft says only SHOULD NOT. That is deliberate and stricter than required: the `client_id` a client presents must stay byte-identical to the URL the document was fetched from, which is exactly what the self-reference check compares.
3. **Domain policy.** If `cimd.allowed_domains` is configured, the host must be in it (exact, case-insensitive). Empty allowlist ⇒ any public HTTPS host — which is the **default**, and ZeroID warns at startup when CIMD is enabled without one. Note what this control can and cannot do: it constrains *which hosts may publish*, at domain granularity — and, since it also gates redirects (§ below), *where documents from those hosts may send a user*. **Only list hosts whose publishing you control.** On a host where anyone can serve a path — user content, a raw-file CDN, a broadly writable bucket — allow-listing hands that party a vetted-client status the redirect gate then honours. It does not establish that the party presenting a `client_id` controls that document — CIMD has no proof of possession, so any client may present any published URL, and for a native client whose document lists a loopback `redirect_uri` the code is delivered to the presenter's own listener. Treat the allowlist as ecosystem scoping, not client authentication.
4. **Fetch (SSRF-guarded, no redirects).** `GET` via the same DNS-rebinding-safe client the OIDC attestation verifier and CIBA dispatch use ([`attestation.NewSSRFGuardedHTTPClient`](../internal/attestation/oidc.go)): the host is resolved once, every answer is checked against the private/loopback/link-local/multicast/CGN/reserved blocklist, and the connection is pinned to the validated IP. TLS still verifies against the original hostname. Response is size-capped (5 KiB default) and timeout-bounded (5 s). **HTTP redirects are not followed** — the `client_id` is a canonical location; a 3xx is a resolution failure.
5. **Validate the document.**
   - **Self-reference** (draft §4): the document's `client_id` field MUST equal the URL it was fetched from. This is what stops a document from claiming someone else's identity.
   - `redirect_uris` is **required and non-empty** — CIMD's primary anti-impersonation control. Each entry must satisfy OAuth 2.1 scheme rules: `https://`, loopback `http://`, or a private-use scheme (native apps); plaintext non-loopback `http://` is rejected. The requested `redirect_uri` is matched against the list by the existing `redirectURIAllowed` logic (exact match, with RFC 8252 §7.3 port-agnostic matching for loopback callbacks).

     When `cimd.allowed_domains` is set, an `https://` entry must additionally be on the `client_id`'s own host or on that list — a **deviation**, and the reason the allowlist can be trusted as the switch that restores redirects (see below). Allow-listing the *publisher* only vets the destination if the destination is vetted too; otherwise any host where more than one party can publish a path lets an attacker name `https://evil.example/cb` and collect codes from a real sign-in. Loopback and private-use schemes are exempt: they deliver to the caller's own machine, not to a published host. In open mode this constrains nothing, because open mode refuses those redirects outright.
   - `token_endpoint_auth_method` must be `none` (omitted defaults to `none`). **Confidential CIMD clients (`private_key_jwt`) are not supported in v1.**
   - `grant_types` defaults to `["authorization_code"]`, must include `authorization_code`, and may only contain `authorization_code` / `refresh_token`.
   - `response_types`, if present, must include `code`.
6. **Synthesize + cache.** The document becomes an ephemeral `domain.OAuthClient` (`client_type: public`, `token_endpoint_auth_method: none`, `registration_source: cimd`) that is **never written to the database**. Outcomes are memoized in a bounded in-memory cache (1000 entries): successes for the configured TTL (1 h default, 24 h hard cap), shortened when the document's `Cache-Control` `max-age` asks for less (floored at 60 s so a document can't force a fetch per request) — so the `/oauth2/authorize` → `/oauth2/token` round-trip doesn't fetch twice, and a client rotating its `redirect_uris` can shrink the staleness window; failures are negative-cached (10 s for transient fetch errors, 60 s for deterministic validation failures) so replaying a dead URL can't force a fresh timeout-bounded outbound fetch per request.

### Error mapping

| Outcome | OAuth `error` | HTTP |
|---|---|---|
| `client_id` not a valid CIMD URL (bad scheme, query, fragment) | `invalid_request` | 400 |
| Document malformed / self-reference mismatch / forbidden field / oversize | `invalid_client_metadata` | 400 |
| Host not in `allowed_domains` | `invalid_client` | 401 |
| Document could not be fetched (network, non-200, SSRF block, timeout) | `invalid_client` | 401 |
| CIMD disabled but a URL `client_id` reached resolution | `invalid_client` | 401 |

Fetch-failure causes are logged server-side but never echoed to the client (they can reveal the server's DNS view / internal topology).

---

## Configuration

CIMD is **on by default**. Knobs (all optional):

```yaml
cimd:
  enabled: true                          # ZEROID_CIMD_ENABLED — set false to disable
  allowed_domains: []                    # PRODUCTION HARDENING LEVER — allowlist of client_id hosts; empty = any HTTPS host (see below)
  allow_private_metadata_endpoints: false # ZEROID_CIMD_ALLOW_PRIVATE_ENDPOINTS — test/dev only
  max_document_bytes: 5120               # ZEROID_CIMD_MAX_DOCUMENT_BYTES
  cache_ttl_seconds: 3600                # ZEROID_CIMD_CACHE_TTL_SECONDS (clamped to 24 h)
```

### Production hardening — set `allowed_domains`

> **`allowed_domains` is the primary production hardening lever for CIMD.** Set it to the exact hosts you trust.

CIMD ships **on and open**: with an empty `allowed_domains`, any request-supplied `https://` `client_id` reaching the public `/oauth2/authorize` endpoint drives ZeroID to fetch that URL. The fetch is heavily guarded (SSRF blocklist, 5 KiB / 5 s caps, no redirects, negative caching — see [Security considerations](#security-considerations)), but an empty allowlist still means ZeroID will make outbound requests to arbitrary attacker-chosen public hosts.

`allowed_domains` closes that: only `client_id` URLs whose host is in the list (exact, case-insensitive) are resolved — every other host is rejected **before any outbound fetch**. This turns CIMD from an open ecosystem into a closed one bounded to your known clients.

```yaml
cimd:
  allowed_domains:
    - client.example.com
    - apps.acme.dev
```

Guidance:
- **Enterprise / closed deployments:** set `allowed_domains` to your known client hosts. This is the recommended production posture.
- **Open agent ecosystems (public MCP):** leaving it empty is a deliberate choice — additionally rate-limit `/oauth2/authorize` at the edge (see [Fetch abuse](#security-considerations)).
- **Turning CIMD off entirely:** `enabled: false` — `https://` `client_id` values then fall through to the registry (and miss, since CIMD clients are never persisted).

`allow_private_metadata_endpoints: true` disables the SSRF blocklist so documents can be served from `localhost` / a private network in single-tenant dev/test. **Production MUST keep it `false`.**

---

## Discovery

When enabled, the OAuth 2.0 Authorization Server Metadata document (`GET /.well-known/oauth-authorization-server`) advertises:

```json
{ "client_id_metadata_document_supported": true }
```

CIMD-aware clients (MCP 2025-11-25, and any client that walks the draft's discovery) read this to learn they can present a URL `client_id` and skip registration. The field is omitted when CIMD is disabled.

---

## Specification revision and deviations

**Implemented against:** [`draft-ietf-oauth-client-id-metadata-document-02`](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/), adopted by the OAuth WG in October 2025.

This is a **draft at revision 02 and it will change.** The section exists so that when it does, the next reader can tell which behaviours were the spec, which were our choices, and which were deliberately left unbuilt — rather than reverse-engineering that from the validator.

### Where ZeroID is deliberately STRICTER than the draft

Both of these will reject a document some other implementation accepts. That is intended, but it is also the part most likely to age badly: a later revision can bless what we refuse, and then we are rejecting valid clients for a reason nobody remembers choosing. Revisit both on each draft bump.

| Rule | Draft says | ZeroID does | Why |
|---|---|---|---|
| Query string in `client_id` | SHOULD NOT | **Rejects** | The `client_id` a client presents must stay byte-identical to the URL the document was fetched from — that is exactly what the §4 self-reference check compares. Stripping or tolerating a query gives one document two spellings. |
| `client_name` | RECOMMENDED | **Required, non-empty** | It is the string a human is asked to trust on a consent screen. Absent, the prompt degrades to a raw URL — and for a URL an attacker chose, that is actively misleading. The publisher is anonymous by construction (no registration, no secret), so this label is most of what consent has to work with. |

### Deliberately not implemented

- **Confidential CIMD clients** — `token_endpoint_auth_method: private_key_jwt` with a published `jwks_uri`. ZeroID accepts no `private_key_jwt` token-endpoint auth for any client; CIMD is public-PKCE-only.
- **`software_statement`** — signed metadata is not consumed. CIMD trust here is domain-ownership based.

Both are areas the draft is more likely to move in than the core resolution rules, which is part of why they are not built on.

### The change most likely to break silently

A rename of the discovery field **`client_id_metadata_document_supported`**.

If a later draft renames it, nothing errors. The authorization server keeps advertising a key clients no longer look for, every client falls back to `registration_endpoint` and DCR, and the whole flow keeps working — via exactly the row-per-client path CIMD exists to remove.

Tests do not help here. They assert the server *emits* that field, so they stay green while no client can see it. The only guard is tracking the draft.

### What makes drift survivable

Two properties worth knowing about before a spec change forces a decision:

- **DCR is retained as a fallback.** `registration_endpoint` stays advertised alongside CIMD deliberately, so a client that cannot complete CIMD still has a path.
- **Registry-first resolution is a pinning mechanism.** A client registered under its CIMD URL overrides the document (see step 1 of resolution). So a specific client caught by a spec change can be pinned by registering it, without waiting on a ZeroID release.

### Deployment note: the cache is per process

`CIMDService` holds its resolution cache in memory, so a deployment running N replicas has N independent caches. Concurrent resolutions of the same `client_id` are coalesced **within** a process (singleflight), not across them.

Two consequences worth planning around:

- **Fan-out** is up to N fetches per document per TTL, and negative caching is likewise per replica — so replaying a dead URL costs N times as much. Bounded in practice by edge rate limiting, which is required for an open deployment anyway.
- **Staleness is non-uniform.** Two replicas can serve different versions of one document for up to the TTL, so a client that removes a `redirect_uri` may find the change effective on some replicas and not others, with no way to tell which served it.

A shared cache (Redis) would fix the fan-out and make replicas *consistently* stale — it would not make them *fresher*. Revocation latency is governed by the TTL and by the document's `Cache-Control` (ZeroID takes the shorter, floored at 60s), independent of where the cache lives. Note also that a shared cache holds `redirect_uris`, the primary anti-impersonation control, so write access to it becomes equivalent to choosing where authorization codes are delivered.

---

## Security considerations

- **Redirect-URI allow-list is the load-bearing control.** Copying a `client_id` is useless without control of a host in its `redirect_uris`. PKCE binds the code to the verifier on top of that.
- **SSRF.** The document fetch cannot be turned into a probe of internal/metadata addresses — the guard is the same audited implementation used elsewhere in ZeroID, applied at dial time against the *resolved* IP (DNS-rebinding-safe).
- **Localhost redirects.** Loopback `redirect_uris` are matched port-agnostically (RFC 8252) so native/CLI callbacks work, but any process on the user's machine can bind a loopback port. Treat localhost CIMD clients with the same caution as any native public client.
- **DNS / TLS trust.** CIMD's integrity rests on the same DNS + TLS + certificate-transparency assumptions as any HTTPS-based trust model. **`allowed_domains` is the hard boundary** — see [Production hardening](#production-hardening--set-allowed_domains).
- **No persistence, no secret.** CIMD clients are ephemeral and hold no symmetric secret at the broker — there is nothing to leak from ZeroID's side.
- **Fetch abuse.** The resolution surface is unauthenticated (`/oauth2/authorize` is public, and client resolution runs *before* the principal chain), so a request-supplied `client_id` triggers an outbound fetch. It is deliberately hard to abuse — concurrent resolutions of the same `client_id` are **coalesced into one fetch** (singleflight), plus a bounded cache (1000 entries), negative caching of failures (10 s fetch / 60 s validation), 5 KiB response cap, 5 s timeout, no redirect following, and the SSRF blocklist.

  Be precise about what each control bounds. The caps bound the cost of *one* fetch. Coalescing bounds *duplicate concurrent* work for one `client_id`. Neither bounds a caller cycling **distinct** URLs: each unique path is a fresh flight, misses the cache, walks past negative caching, and churns cache eviction. So the **primary control is `allowed_domains`**, which rejects unknown hosts before any fetch — and a deployment running fully open (empty allowlist) **must** rate-limit `/oauth2/authorize` at the edge. That is the deployer's job; no in-process control substitutes for it.

---

## Limitations / future work

- **Unimplemented draft features** — confidential CIMD clients (`private_key_jwt` + `jwks_uri`) and `software_statement`. Both are covered under [Specification revision and deviations](#deliberately-not-implemented), which is the single place that records what is and is not built against the draft; they are not repeated here so the two cannot drift apart.
- **Cross-replica cache coherence** — the resolution cache is per process, so N replicas hold N caches. See [Deployment note: the cache is per process](#deployment-note-the-cache-is-per-process) for the fan-out and staleness consequences, and why a shared cache addresses the first but not the second.

---

## Files

| Concern | File |
|---|---|
| CIMD service (detect / fetch / validate / synthesize / cache) | [`internal/service/cimd.go`](../internal/service/cimd.go) |
| Auth-code flow integration | [`internal/service/oauth.go`](../internal/service/oauth.go) (`IssueAuthCode`, `authorizationCode`, `cimdOAuthError`) |
| SSRF-guarded HTTP client (shared) | [`internal/attestation/oidc.go`](../internal/attestation/oidc.go) (`NewSSRFGuardedHTTPClient`) |
| Discovery advertisement | [`internal/handler/wellknown.go`](../internal/handler/wellknown.go) (`oauthMetadataOp`) |
| Config | [`config.go`](../config.go) (`CIMDConfig`) |
| Tests | [`internal/service/cimd_test.go`](../internal/service/cimd_test.go) |
