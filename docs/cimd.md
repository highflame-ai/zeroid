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

**The browser leg needs a GET-capable `PrincipalResolver`, which ZeroID does not
ship.** A browser cannot set a custom header on a top-level navigation, and the
resolver-facing `Form` accessor is bound to the POST body, so a resolver that
reads `req.Form(...)` sees nothing on a GET. The deployer must register one that
reads a session cookie (`req.Cookie(...)`) and own the login and consent screens
behind it.

**ZeroID cannot detect this for you.** Its AS metadata omits the
`authorization_code` grant when *no* resolver is registered, but it cannot
introspect what a registered resolver reads — so a deployment whose resolvers are
all form-based advertises the grant and then 401s every browser redirect. If that
is you, call `Server.SetAuthorizationCodeAvailable(func() bool { return false })`
until a GET-capable resolver exists; otherwise the metadata promises a flow the
endpoint cannot finish, which is exactly the failure this is meant to prevent.

Three things a deployer must handle:

* **The interaction cannot live in the resolver.** `PrincipalResolver` returns
  `(*Principal, error)` — no `ResponseWriter`, no redirect, no way to render or
  resume a consent screen. Do it in `Server.Use` middleware, which sees the raw
  request and can 302 to a consent page before the handler runs; the resolver
  then only recognises the session that flow established.

  **`Server.Use` replaces rather than chains.** A second call silently discards
  the first, despite the name. If you already use it for anything else — and
  most deployers do — compose both into one function at the call site. Adding
  the consent gate as a second `Use` call drops one of the two with no error,
  and if the loser is the consent gate, the protection below simply is not
  running. Tracked in zeroid#276.
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
2. **Validate the URL.** `https` scheme, non-empty host, path present, **no query string, no fragment** (the draft requires a canonical document location), and ≤ 255 characters (the `client_id` is persisted into `VARCHAR(255)` columns downstream).
3. **Domain policy.** If `cimd.allowed_domains` is configured, the host must be in it (exact, case-insensitive). Empty allowlist ⇒ any public HTTPS host.
4. **Fetch (SSRF-guarded, no redirects).** `GET` via the same DNS-rebinding-safe client the OIDC attestation verifier and CIBA dispatch use ([`attestation.NewSSRFGuardedHTTPClient`](../internal/attestation/oidc.go)): the host is resolved once, every answer is checked against the private/loopback/link-local/multicast/CGN/reserved blocklist, and the connection is pinned to the validated IP. TLS still verifies against the original hostname. Response is size-capped (5 KiB default) and timeout-bounded (5 s). **HTTP redirects are not followed** — the `client_id` is a canonical location; a 3xx is a resolution failure.
5. **Validate the document.**
   - **Self-reference** (draft §4): the document's `client_id` field MUST equal the URL it was fetched from. This is what stops a document from claiming someone else's identity.
   - `redirect_uris` is **required and non-empty** — CIMD's primary anti-impersonation control. Each entry must satisfy OAuth 2.1 scheme rules: `https://`, loopback `http://`, or a private-use scheme (native apps); plaintext non-loopback `http://` is rejected. The requested `redirect_uri` is matched against the list by the existing `redirectURIAllowed` logic (exact match, with RFC 8252 §7.3 port-agnostic matching for loopback callbacks).
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

## Security considerations

- **Redirect-URI allow-list is the load-bearing control.** Copying a `client_id` is useless without control of a host in its `redirect_uris`. PKCE binds the code to the verifier on top of that.
- **SSRF.** The document fetch cannot be turned into a probe of internal/metadata addresses — the guard is the same audited implementation used elsewhere in ZeroID, applied at dial time against the *resolved* IP (DNS-rebinding-safe).
- **Localhost redirects.** Loopback `redirect_uris` are matched port-agnostically (RFC 8252) so native/CLI callbacks work, but any process on the user's machine can bind a loopback port. Treat localhost CIMD clients with the same caution as any native public client.
- **DNS / TLS trust.** CIMD's integrity rests on the same DNS + TLS + certificate-transparency assumptions as any HTTPS-based trust model. **`allowed_domains` is the hard boundary** — see [Production hardening](#production-hardening--set-allowed_domains).
- **No persistence, no secret.** CIMD clients are ephemeral and hold no symmetric secret at the broker — there is nothing to leak from ZeroID's side.
- **Fetch abuse.** The resolution surface is unauthenticated (`/oauth2/authorize` is public), so a request-supplied `client_id` triggers an outbound fetch. It is deliberately hard to abuse — bounded cache (1000 entries), negative caching of failures (10 s fetch / 60 s validation), 5 KiB response cap, 5 s timeout, no redirect following, and the SSRF blocklist — but the **primary control is `allowed_domains`**, which rejects unknown hosts before any fetch. Deployers running fully open CIMD (empty allowlist) should additionally rate-limit `/oauth2/authorize` at the edge like any public endpoint.

---

## Limitations / future work

- **Confidential CIMD clients** (`token_endpoint_auth_method: private_key_jwt` with a published `jwks_uri`) are not supported — ZeroID does not yet accept `private_key_jwt` token-endpoint auth for any client. v1 is public-PKCE-only.
- **`software_statement`** (signed metadata) — not consumed; CIMD trust is domain-ownership based.

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
