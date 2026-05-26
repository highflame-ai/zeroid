# DPoP & Dynamic Client Registration — Reference

ZeroID implements two standards that together let agents and tools onboard themselves and prove ongoing possession of their credentials:

- **DPoP** ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) — sender-constrained access tokens. Defeats bearer-token theft.
- **Dynamic Client Registration** ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)) + **Client Configuration Endpoint** ([RFC 7592](https://datatracker.ietf.org/doc/html/rfc7592)) — self-service OAuth client onboarding. Defeats hand-rolled admin shims.

This document covers both because they share design choices (intrinsic per-request auth, ZeroID-specific tenant + scope constraints) and they ship together. For the conceptual one-page overview see [the Real-World Patterns section of the README](../README.md#real-world-patterns) (Pattern 7 = DPoP, Pattern 8 = DCR).

---

## DPoP — Demonstrating Proof of Possession (RFC 9449)

### What it solves

A standard OAuth2 access token is a **bearer credential**: anyone who has the bytes can use them until expiry or revocation. For a finance-bot or a high-trust orchestrator, the window between "token stolen" and "token revoked" is wide enough to do real damage. Network mitigations (mTLS, IP allowlists) don't scale to portable workloads.

DPoP closes the gap by **binding the access token to a key the client holds in process memory**. Every request that presents the token must also present a fresh JWT signed by that key. A stolen token without the key is useless.

### Wire shape

#### 1. Requesting a DPoP-bound token

The client generates an asymmetric key (ES256 or RS256), then signs a proof JWT whose payload covers the HTTP method (`htm`), the target URI (`htu`), an issued-at timestamp (`iat`), and a fresh JWT ID (`jti`). The proof's protected header carries `typ: "dpop+jwt"` and the **public** JWK.

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

grant_type=client_credentials&client_id=...&client_secret=...&account_id=...&project_id=...&scope=payments:write
```

Response:

```json
{
  "access_token": "eyJ0eXAi...",
  "token_type":   "DPoP",
  "expires_in":   3600,
  "scope":        "payments:write"
}
```

The access token's claims include a `cnf` (confirmation) member with `jkt` = the base64url-encoded SHA-256 JWK thumbprint of the proof key (RFC 7638).

#### 2. Calling a resource server

Per RFC 9449 §7, the access token is presented with the `DPoP` (not `Bearer`) auth scheme, and a **new** proof JWT is signed for **this** call. The new proof carries an `ath` claim — `base64url(SHA-256(access_token))` — that binds the proof to this specific access token.

```http
POST /api/v1/transfer HTTP/1.1
Host: payments.example.com
Authorization: DPoP eyJ0eXAi...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7... (different jti, ath claim set)
```

The resource server calls ZeroID's `POST /oauth2/token/introspect`, sees `cnf.jkt` in the response, and validates the per-request proof against that thumbprint plus its own htm/htu.

### How ZeroID validates a proof

Implemented in [`internal/service/dpop.go`](../internal/service/dpop.go). Twelve steps, ordered for security:

1. Parse the JWS, fail on malformed input.
2. `typ` header must be `dpop+jwt`.
3. `alg` must be one of the allow-listed asymmetric algorithms (`ES256`, `RS256`). Symmetric algs are spec-forbidden.
4. `jwk` header must be present and must **not** carry private-key material (we type-assert against `jwk.ECDSAPrivateKey` / `jwk.RSAPrivateKey` / `jwk.OKPPrivateKey`).
5. Verify the JWS signature using the embedded public JWK.
6. Parse the payload (only after signature is verified).
7. `htm` matches the request method **exactly** (case-sensitive per RFC 9110 §9.1).
8. `htu` matches the request URL **after stripping query and fragment**. The URL we compare against is the **request's effective URL** — captured by `internal/middleware/RequestURLMiddleware` — not the configured `cfg.Token.BaseURL`. This makes reverse-proxied deployments work transparently when `ServerConfig.TrustForwardedHeaders = true`.
9. `iat` must fall inside the freshness window (60 s in the past + 5 s of clock-skew tolerance).
10. `jti` is consumed atomically by INSERTing into `dpop_jti` with `jti` as the primary key. A `23505` duplicate-key error → replay. **Wall-clock expiry** (`now + freshness + skew`), not iat-relative — a malicious client cannot backdate `iat` to shrink the row's replay-coverage window.
11. If an access token is being validated at a resource server (`ValidateProofForToken`), `ath` is required and must equal `base64url(SHA-256(access_token))`.
12. Compute the JWK thumbprint (SHA-256 per RFC 7638) — this is what becomes `cnf.jkt` on the issued token.

### Token-endpoint behaviour

`/oauth2/token` reads the `DPoP` header on **every** grant type. When present and valid:

- The issued JWT carries `cnf: {"jkt": "<thumbprint>"}`.
- The persisted `IssuedCredential` row records the thumbprint in `dpop_key_thumbprint`.
- The HTTP response's `token_type` field is `"DPoP"` instead of `"Bearer"`.
- Token introspection (`POST /oauth2/token/introspect`) surfaces the `cnf` claim alongside other claims.

When absent: standard Bearer behaviour. Existing callers see no change.

#### Error mapping

| Outcome | HTTP | OAuth `error` field |
|---|---|---|
| `DPoP` header missing | (n/a — DPoP is optional) | — |
| Malformed JWS / wrong typ / bad alg / private-key JWK / htm/htu/iat/jti/ath failure | 400 | `invalid_dpop_proof` |
| JTI replay detected | 400 | `invalid_dpop_proof` |
| **`dpop_jti` table unreachable** | 500 | `server_error` |

The 500 case is deliberate: a database-unreachable signal must never look like an "invalid proof" 4xx, because that would mask outages as client errors. The service returns `ErrDPoPStorageFailure` (in `internal/service/dpop.go`) and the handler maps it explicitly.

### Reverse-proxy deployments

If ZeroID sits behind nginx / an AWS ALB / a GCP LB, set:

```yaml
server:
  trust_forwarded_headers: true
```

`RequestURLMiddleware` will then read `X-Forwarded-Proto` and `X-Forwarded-Host` when reconstructing the URL the client signed. **Leave it `false` if the service terminates TLS itself** — otherwise a spoofed `X-Forwarded-Host` could move the `htu` goalpost.

### Replay store and cleanup

The `dpop_jti` table is INSERT-only at the service layer; the cleanup worker (`internal/worker/cleanup.go`) sweeps rows where `expires_at < now()` on its periodic tick. Storage parameters are tuned for high churn:

```sql
CREATE TABLE dpop_jti (
    jti        VARCHAR(512) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
) WITH (fillfactor = 90, autovacuum_vacuum_scale_factor = 0.05);
```

`autovacuum_vacuum_scale_factor = 0.05` keeps dead-tuple ratio under control (the default 0.2 is too lazy for INSERT-then-DELETE workloads).

> **Operational follow-up (not in this PR):** at >100 token/sec sustained DPoP traffic, split the `dpop_jti` cleanup into a tighter 5-minute ticker independent of the credential/auth-code sweep. The hourly cadence is fine for early adoption; the analyst flagged the cutoff for visibility.

### When the DPoP-bound token reaches a downstream resource server

ZeroID does not gate its **own** endpoints on a downstream DPoP proof — `/oauth2/token/introspect` and `/oauth2/token/revoke` accept the access token under either auth scheme. The proof check is the resource server's job, and resource servers reach for `ValidateProofForToken` (passes `accessToken` so the `ath` check fires) rather than `ValidateProof`.

### Refresh-token binding (RFC 9449 §5)

When a refresh token is issued in conjunction with a DPoP-bound access token (via the `authorization_code` grant whose `/oauth2/token` call carried a proof), the refresh token itself is bound to the same public key. Implementation:

- `refresh_tokens.dpop_key_thumbprint` (added in migration 026) records the thumbprint.
- `RotateRefreshToken` accepts the presented proof's thumbprint as a parameter; the comparison runs **inside the rotation transaction**, so a bound refresh token that's presented with a wrong key / no proof:
  - returns `invalid_dpop_proof`, **not** `invalid_grant`,
  - does **not** consume the refresh token (the transaction rolls back),
  - leaves the legitimate caller's next request with the correct key still working.
- The successor row carries the same thumbprint, so binding survives the rotation chain indefinitely.

An **unbound** refresh token (issued without DPoP) is not retroactively bound — even if a later rotation request presents a proof. That decision could change later; today it preserves the explicit user opt-in to DPoP.

### Limitations / future work

- **CIBA push mode**: the CIBA push delivery path mints a token server-side with no client proof available; those tokens come out as Bearer regardless. CIBA poll mode is fully DPoP-capable today (the poll's `/oauth2/token` call carries the proof normally).
- **Resource-server SDKs**: the in-tree SDK helpers do not yet implement client-side proof generation. Tracking issue: future work.
- **PS256 / EdDSA**: only ES256 and RS256 are advertised today via `dpop_signing_alg_values_supported`. Adding more is a one-line allow-list change.
- **Unbound → bound upgrade on rotation**: today an unbound refresh token stays unbound across rotation even if the new request carries a proof. Upgrading on first proof is a small extension once we agree it's the desired UX.

---

## Dynamic Client Registration (RFC 7591 / RFC 7592)

### What it solves

OAuth clients are normally provisioned by an admin via a console. That works when the deployer of a service is the same team that runs the AS — but agent-tooling vendors who ship MCP servers, SDKs, or installer scripts to other tenants have no way to express "register an OAuth client when you install me." The workarounds (expose the admin API publicly with a sign-up form, ask each tenant's ops team to file a ticket) are operationally and security-wise bad.

RFC 7591 defines a standard registration endpoint; RFC 7592 defines the per-client management endpoints that follow it.

### Choosing between agent identity registration and OAuth DCR

ZeroID has two registration paths; the right one depends on what you're registering.

| Use case | Endpoint | Auth shape |
|---|---|---|
| **Agent identity** participating in delegation chains (`token_exchange`, multi-hop `jwt-bearer`) | `POST /api/v1/agents/register` with `public_key_pem` | Keypair owned by the agent; public PEM uploaded to the broker at registration. Self-signed JWT assertions verify against the stored key. |
| **Confidential OAuth client** — vendor MCP server, installer bootstrap, single-hop tool — that does not participate in delegation chains | `POST /oauth2/register` (this doc) with `client_secret_basic` / `client_secret_post`, optionally inline `jwks` for jwt-bearer assertions | Client secret minted at registration; assertion-signing keys (if used) held at the broker. |

The split is deliberate. DCR-registered clients are **explicitly blocked from `token_exchange`** (enforced at the grant-type allow-list — see "What ZeroID enforces" below) because they have no `IdentityID` binding and cannot legitimately act as a delegation actor. Agents that need to participate in chains must register through the agent identity path. See the [agent registration walkthrough in the README](../README.md#1-register-an-agent) for that side of the API.

**Both paths hold public keys at the broker, not behind the agent.** `public_key_pem` (agent path) and inline `jwks` (DCR path) are the recommended shapes. `jwks_uri` (broker fetches keys from a URL the client publishes) is accepted for RFC 7591 spec compliance, but it requires every registered client to operate an internet-reachable HTTPS endpoint solely for key publication — and is not the recommended pattern for self-hosted ZeroID deployments. Broker-held keys remove an entire class of operational concerns (tunneling, NAT, certificate provisioning for client hosts) and limit internet-exposed surface area to ZeroID itself.

### Wire shape

#### 1. Mint an initial access token (one-time, per registrant)

The platform decides who's allowed to self-register and mints an **initial access token (IAT)** — an ordinary ZeroID-issued JWT whose `scopes` claim contains the reserved `client:register` scope. Tokens are minted via any standard ZeroID grant (typically `client_credentials` against a confidential bootstrap client whose `allowed_scopes` list includes `client:register`).

```bash
IAT=$(curl -s -X POST https://auth.example/oauth2/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=...' -d 'client_secret=...' \
  -d 'account_id=acme' -d 'project_id=prod' \
  -d 'scope=client:register' | jq -r .access_token)
```

#### 2. Register

```bash
curl -s -X POST https://auth.example/oauth2/register \
  -H "Authorization: Bearer $IAT" \
  -H "Content-Type: application/json" \
  -d '{
        "client_name": "Acme Notebook MCP",
        "grant_types": ["client_credentials"],
        "scope": "notebook:read notebook:write",
        "token_endpoint_auth_method": "client_secret_post",
        "software_id": "com.acme.notebook",
        "software_version": "2.4.0"
      }'
```

The response contains the new `client_id` + `client_secret` (the plaintext secret is shown once and **never** persisted in plain form) and a `registration_access_token` that authenticates subsequent management calls.

```json
{
  "client_id":                  "9f43b1c2...",
  "client_secret":              "shown-once",
  "client_id_issued_at":        1716000000,
  "client_secret_expires_at":   0,
  "client_name":                "Acme Notebook MCP",
  "grant_types":                ["client_credentials"],
  "scope":                      "notebook:read notebook:write",
  "token_endpoint_auth_method": "client_secret_post",
  "registration_access_token":  "shown-once",
  "registration_client_uri":    "https://auth.example/oauth2/register/9f43b1c2..."
}
```

#### 3. Manage (RFC 7592)

```bash
# Read current registration
curl -X GET    https://auth.example/oauth2/register/9f43b1c2 \
     -H "Authorization: Bearer <registration_access_token>"

# Replace registration (full replacement — RFC 7592 §3)
curl -X PUT    https://auth.example/oauth2/register/9f43b1c2 \
     -H "Authorization: Bearer <registration_access_token>" \
     -H "Content-Type: application/json" \
     -d '{"client_name":"Acme Notebook MCP","grant_types":["client_credentials"],"scope":"notebook:read"}'

# Delete
curl -X DELETE https://auth.example/oauth2/register/9f43b1c2 \
     -H "Authorization: Bearer <registration_access_token>"
```

GET and PUT responses re-include the public client metadata but **never** re-reveal `client_secret` or `registration_access_token`.

#### 4. Register a client that signs JWT assertions (jwt-bearer grant, inline `jwks`)

For clients that will use the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant — typically a service-account-style integration whose downstream calls are authorized by a signed JWT assertion — register an inline JWKS at registration time so the broker can verify those assertions:

```bash
# 1. Generate a P-256 keypair locally (one-time per client).
openssl ecparam -name prime256v1 -genkey -noout -out client-private.pem
openssl ec -in client-private.pem -pubout -out client-public.pem

# 2. Convert client-public.pem into JWK form (kty/crv/x/y). Any small helper
#    works — Python's `cryptography` + `python-jose`, Go's `lestrrat-go/jwx`,
#    or the `mkjwk` CLI. The shape below assumes you've already produced it.

# 3. Register, embedding the JWK inline.
curl -s -X POST https://auth.example/oauth2/register \
  -H "Authorization: Bearer $IAT" \
  -H "Content-Type: application/json" \
  -d '{
        "client_name": "Acme Notebook MCP",
        "grant_types": [
          "urn:ietf:params:oauth:grant-type:jwt-bearer",
          "client_credentials"
        ],
        "scope": "notebook:read notebook:write",
        "token_endpoint_auth_method": "client_secret_basic",
        "jwks": {
          "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": "client-key-1",
            "x":   "<base64url of public x coordinate>",
            "y":   "<base64url of public y coordinate>"
          }]
        },
        "software_id":      "com.acme.notebook",
        "software_version": "2.4.0"
      }'
```

When this client later presents a jwt-bearer grant:

```bash
curl -s -X POST https://auth.example/oauth2/token \
  -u "<client_id>:<client_secret>" \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
  -d 'assertion=<JWT signed by client-key-1>' \
  -d 'scope=notebook:read'
```

…the client authenticates **to the token endpoint** with HTTP Basic (its `client_secret`), and the `assertion` JWT is verified against the JWKS uploaded at registration. The two checks are independent: `token_endpoint_auth_method` governs how the client identifies itself to the endpoint; the `jwks` governs how its assertion signature is verified.

**Why inline `jwks` rather than `jwks_uri`**: RFC 7591 §2 accepts both. Inline `jwks` uploads the keys to the broker once at registration time, the broker stores them, and verification is local. `jwks_uri` requires the broker to fetch keys from a URL the client publishes, which means the client must run an internet-reachable HTTPS endpoint solely for key publication — workable when client and broker live in different security domains, but unnecessary friction for self-hosted ZeroID deployments. For key rotation, use an RFC 7592 `PUT` to swap the inline JWKS (single round-trip, no DNS or TLS dependency).

> **`private_key_jwt` is not currently accepted** as `token_endpoint_auth_method` for DCR-registered clients (see "What ZeroID enforces" below). DCR clients authenticate to the token endpoint with their client secret; the jwt-bearer **grant** is the path where signed assertions and JWKS come into play.

### What ZeroID enforces

Implemented in [`internal/handler/dynamic_registration.go`](../internal/handler/dynamic_registration.go) (handler) and [`internal/service/oauth_client.go`](../internal/service/oauth_client.go) (service).

#### On the IAT (RFC 7591 §3.4)

`validateInitialAccessToken` rejects unless **all** of the following hold:

- JWS signature verifies against the local JWKS (any zeroid signing key).
- `iss` equals `cfg.Token.Issuer`.
- `aud` contains `cfg.Token.Issuer` — defence against tokens minted for a different protected resource being replayed here. (Per RFC 9068 §3, ZeroID-issued access tokens default to `aud = [issuer]`, so this works out of the box.)
- `iat`/`exp` are in-window per `jwt.WithValidate(true)`.
- The `scopes` claim contains `client:register`. The accessor tries `[]string` first then falls back to `[]any` — matching `internal/middleware/AgentAuthMiddleware`'s pattern.

Tenant claims (`account_id`, `project_id`, `sub`) are extracted and surfaced into the audit log; OAuth clients themselves are global per ZeroID's design (see `domain/token.go`'s `OAuthClient` comment) so they are not stored with a tenant column.

#### On the registration body (RFC 7591 §2)

Validated by `validateDCRClientMetadata`:

- `client_name` is required.
- `grant_types` defaults to `["client_credentials"]`. The allow-list for DCR-registered clients is **`client_credentials`** and **`urn:ietf:params:oauth:grant-type:jwt-bearer`** only. Notably absent:
  - `authorization_code` — no interactive consent flow exists for self-registered clients.
  - `urn:ietf:params:oauth:grant-type:token-exchange` — DCR clients have no `IdentityID` binding and so cannot legitimately act as a delegation actor. Re-enable once that binding exists.
- `token_endpoint_auth_method` is `client_secret_post`, `client_secret_basic`, or empty (defaults to `client_secret_basic` per RFC 7591 §2). `"none"` is explicitly rejected — this server requires client authentication.
- `redirect_uris` is accepted for spec compliance but ignored.

#### On the registration_access_token

`VerifyRegistrationToken` performs a **constant-time** check: regardless of whether the client_id exists, exactly one bcrypt comparison runs (against the stored hash on a hit, against `dummyRegistrationTokenHash` on a miss). Both hashes use `dcrBcryptCost = 12` so timing is balanced.

`RegistrationSource != "dynamic"` short-circuits to "not found" before the bcrypt comparison so an admin-registered (internal) client can never be authenticated via a registration token — even if one is somehow guessed.

#### On the delete path

`DeleteByClientID` (in `internal/store/postgres/oauth_client.go`) adds `WHERE registration_source = 'dynamic'` as defence-in-depth. Even if a service-layer check is skipped or bypassed, the repository refuses to remove an internal client.

### Reserved `cnf` claim

For the DPoP/DCR cross-cut: `cnf` is now in `reservedClaims` in `internal/service/oauth.go`. The external-principal-exchange flow (which lets a trusted service inject claims via `additional_claims`) cannot smuggle a `cnf.jkt` value through; the only path that writes `cnf` is `credential.IssueCredential` when `req.DPoPKeyThumbprint` came from a validated proof.

### Database

DCR adds two columns on the existing `oauth_clients` table:

```sql
ALTER TABLE oauth_clients
    ADD COLUMN registration_source       VARCHAR(50) NOT NULL DEFAULT 'internal',
    ADD COLUMN registration_access_token VARCHAR(255);
```

Existing rows back-fill to `'internal'`; no manual migration step. The `registration_access_token` column is `nullzero`-tagged in the Go model so internal clients persist NULL (not `""`).

### Discovery

A standards-conformant client walks two documents to find the registration endpoint:

1. `/.well-known/oauth-protected-resource` (RFC 9728) — the *resource server's* metadata. Advertises `resource`, `authorization_servers` (pointers to the AS), `bearer_methods_supported: ["header"]`, `dpop_bound_access_tokens_required: false`. This is the document a 401 with `WWW-Authenticate: Bearer resource_metadata="…"` points the client at.
2. `/.well-known/oauth-authorization-server` (RFC 8414) — the *authorization server's* metadata, fetched after PRM points the client here. Advertises the actual endpoints:
   - `registration_endpoint` — set to `{baseURL}/oauth2/register` when DCR is wired (it always is in this build; the endpoint exists but every request 401s if the deployer doesn't mint `client:register`-scoped tokens).
   - `dpop_signing_alg_values_supported: ["ES256", "RS256"]`.

The two-hop PRM → AS chain is what an RFC 8414/9728-conformant client walks. Publishing both documents lets stock OAuth clients work without ZeroID-specific shimming.

### Limitations / future work

- **`software_statement`** (RFC 7591 §2.3) — signed metadata assertions — not implemented.
- **Per-client `client_secret_expires_at`** — DCR clients today have a non-expiring secret (the response field is `0` per RFC 7591 §3.2.1 conventions). Rotation is supported via the `RotateSecret` admin path on the underlying client, but no automatic expiry/rotation policy is wired.
- **Initial-access-token issuance UX** — ZeroID does not yet ship a one-call "mint me an IAT" admin endpoint. Today it's an ordinary `client_credentials` call against a confidential client whose `allowed_scopes` list includes `client:register`.

---

## Configuration knobs

```yaml
server:
  trust_forwarded_headers: false   # set true when behind a trusted edge proxy (nginx/ALB/etc.) for DPoP htu correctness
```

No DCR-specific config knobs — the feature is governed by which clients hold `client:register` scope.

## Operational signals

| Signal | What it means | Fix |
|---|---|---|
| `level=info, msg="DCR: dynamic client registered", client_id=..., registered_by_*=...` | DCR registration succeeded | informational; preserve for audit |
| `level=info, msg="DCR: initial access token rejected"` | A POST /oauth2/register call presented an IAT that failed validation | check IAT issuer / audience / freshness / scope |
| `level=info, msg="DCR: initial access token rejected — insufficient scope"` | IAT validated cryptographically but lacked `client:register` | client error; respond 403 (handler already does) |
| `level=error, msg="DPoP JTI store unavailable"` | DB write to `dpop_jti` failed for a non-23505 reason | check PG availability; ZeroID returned 500 |

## Files

| Concern | File |
|---|---|
| DPoP validator | [`internal/service/dpop.go`](../internal/service/dpop.go) |
| DPoP handler integration | [`internal/handler/oauth.go`](../internal/handler/oauth.go) (search `DPoPProof`) |
| Request-URL middleware (for DPoP htu) | [`internal/middleware/request_url.go`](../internal/middleware/request_url.go) |
| DCR handler (POST/GET/PUT/DELETE) | [`internal/handler/dynamic_registration.go`](../internal/handler/dynamic_registration.go) |
| DCR service methods | [`internal/service/oauth_client.go`](../internal/service/oauth_client.go) (search `DynamicRegisterClient`, `VerifyRegistrationToken`, `UpdateDynamicClient`, `DeleteDynamicClient`) |
| Repo guard | [`internal/store/postgres/oauth_client.go`](../internal/store/postgres/oauth_client.go) (`DeleteByClientID`) |
| Cleanup worker (sweeps `dpop_jti`) | [`internal/worker/cleanup.go`](../internal/worker/cleanup.go) |
| Discovery (well-known) | [`internal/handler/wellknown.go`](../internal/handler/wellknown.go) |
| Migrations | [`migrations/024_dynamic_client_registration.up.sql`](../migrations/024_dynamic_client_registration.up.sql), [`migrations/025_dpop.up.sql`](../migrations/025_dpop.up.sql), [`migrations/026_refresh_token_dpop_binding.up.sql`](../migrations/026_refresh_token_dpop_binding.up.sql) |
| Refresh-token rotation w/ binding | [`internal/service/refresh_token.go`](../internal/service/refresh_token.go) (`RotateRefreshToken`, `ErrDPoPBindingMismatch`) |
