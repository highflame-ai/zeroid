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

`POST /oauth2/authorize` (unchanged from the [normal PKCE flow](../README.md#real-world-patterns) — the only difference is the `client_id` value):

```http
POST /oauth2/authorize HTTP/1.1
Content-Type: application/x-www-form-urlencoded

client_id=https%3A%2F%2Fapp.example.com%2Foauth%2Fclient.json
&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback
&response_type=code
&code_challenge=<S256 challenge>
&code_challenge_method=S256
&state=<opaque>
```

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
6. **Synthesize + cache.** The document becomes an ephemeral `domain.OAuthClient` (`client_type: public`, `token_endpoint_auth_method: none`, `registration_source: cimd`) that is **never written to the database**. Outcomes are memoized in a bounded in-memory cache (1000 entries): successes for the configured TTL (1 h default, 24 h hard cap) so the `/oauth2/authorize` → `/oauth2/token` round-trip doesn't fetch twice; failures for 60 s (negative caching) so replaying a dead URL can't force a fresh timeout-bounded outbound fetch per request.

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
  allowed_domains: []                    # YAML-only allowlist of client_id hosts; empty = any HTTPS host
  allow_private_metadata_endpoints: false # ZEROID_CIMD_ALLOW_PRIVATE_ENDPOINTS — test/dev only
  max_document_bytes: 5120               # ZEROID_CIMD_MAX_DOCUMENT_BYTES
  cache_ttl_seconds: 3600                # ZEROID_CIMD_CACHE_TTL_SECONDS (clamped to 24 h)
```

To run CIMD as a **closed ecosystem**, set `allowed_domains` to the hosts you trust. To turn it off entirely, set `enabled: false` — `https://` `client_id` values then fall through to the registry (and miss, since CIMD clients are never persisted).

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
- **DNS / TLS trust.** CIMD's integrity rests on the same DNS + TLS + certificate-transparency assumptions as any HTTPS-based trust model. Use `allowed_domains` where you want a hard boundary.
- **No persistence, no secret.** CIMD clients are ephemeral and hold no symmetric secret at the broker — there is nothing to leak from ZeroID's side.
- **Fetch abuse.** The resolution surface is unauthenticated (`/oauth2/authorize` is public), so it is deliberately hard to abuse: bounded cache (1000 entries), 60 s negative caching of failures, 5 KiB response cap, 5 s timeout, no redirect following, and the SSRF blocklist. Deployers running fully open CIMD should still rate-limit `/oauth2/authorize` at the edge like any public endpoint.

---

## Limitations / future work

- **Confidential CIMD clients** (`token_endpoint_auth_method: private_key_jwt` with a published `jwks_uri`) are not supported — ZeroID does not yet accept `private_key_jwt` token-endpoint auth for any client. v1 is public-PKCE-only.
- **`Cache-Control` honouring** — the resolved-client cache uses a fixed TTL (config-driven, 24 h cap) rather than reading the document's `Cache-Control` / `max-age`. Adding max-age honouring (still capped) is a small extension.
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
