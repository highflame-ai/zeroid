# Changelog

All notable changes to ZeroID are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). ZeroID uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `authorization_code` grant with PKCE (S256) support for human-authorized agent flows
- Refresh token issuance and rotation for MCP clients (single-use, family revocation on reuse)
- `POST /api/v1/oauth/clients` now accepts public PKCE clients (`client_id` without `external_id`) alongside existing M2M confidential clients
- `is_mcp` flag on `oauth_clients` table — replaces config-based prefix detection; determines short-lived (1h) vs long-lived (90-day) token TTL
- `pkg/authjwt` — standalone Go client package for JWKS-based JWT verification, usable without embedding the full server
- `GET /oauth2/token/verify` forward-auth endpoint for use with auth proxies (Nginx, Envoy, Traefik)

### Changed
- OAuth2 errors now conform to RFC 6749 §5.2 — structured `{"error": "...", "error_description": "..."}` responses with correct HTTP status codes (`400`, `401`, `403`)
- `authorization_code` flow looks up clients from the `oauth_clients` table instead of a config allowlist

### Removed
- `token.valid_client_ids`, `token.mcp_client_prefix`, and `token.mcp_static_clients` config fields — clients must be registered via `POST /api/v1/oauth/clients`

### Fixed
- `identity_inactive` error code replaced with standard `invalid_grant` per RFC 6749

---

## [1.1.3] — 2026-03-23

### Changed
- Grant type and scope labels are now generic strings rather than a fixed enum, enabling custom grant types registered via `RegisterGrantHandler`

---

## [1.1.2] — 2026-03-23

### Fixed
- Custom grant hooks now receive the correct request context when invoked via `RegisterGrantHandler`

---

## [1.1.1] — 2026-03-20

### Added
- `GET /oauth2/token/verify` — forward-auth endpoint; returns `200` with `X-Auth-*` headers on valid tokens, `401` on invalid
- `pkg/authjwt` — importable Go package for JWKS-based JWT verification; verifies ES256 and RS256 tokens against the ZeroID JWKS endpoint with a 5-minute key cache

---

## [1.1.0] — 2026-03-19

### Changed
- Internal service layer refactored for cleaner separation between OAuth grant logic and identity resolution; no public API changes

---

## [1.0.1] — 2026-03-18

### Fixed
- CI pipeline: resolved Trivy security scan false positives in Docker image build

---

## [1.0.0] — 2026-03-18

Initial public release.

### Added
- **Identity management** — register, update, suspend, and delete NHI/agent identities with external ID, trust level, and capability metadata
- **OAuth2 grants**
  - `client_credentials` (RFC 6749 §4.4) — M2M service-to-service tokens
  - `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523) — keyless agent authentication via signed JWT assertions
  - `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) — delegated sub-agent tokens with `act` claims and depth enforcement
  - API key grant — exchange long-lived API keys for short-lived JWTs
- **Token operations** — introspection (RFC 7662), revocation (RFC 7009), JWKS endpoint (RFC 7517)
- **OAuth2 client registration** — `POST /api/v1/oauth/clients` for M2M confidential clients
- **WIMSE Proof Tokens** — single-use `DPoP`-style proof tokens with DB-level replay prevention
- **CAE signals** — `POST /api/v1/signals` for continuous access evaluation; credential revocation on `critical` and `high` severity signals
- **Attestation** — register and retrieve identity attestation records
- **OpenTelemetry** — distributed tracing via OTLP exporter
- **Embedded migrations** — schema managed via `golang-migrate`, auto-applied on startup by default
- **Extensibility hooks** — `ClaimsEnricher`, `RegisterGrantHandler`, `AdminAuthMiddleware`, `TrustedServiceValidator`
- **`/.well-known/oauth-authorization-server`** metadata endpoint (RFC 8414)
- Multi-stage Docker image, `docker-compose.yml` for local development, `make setup-keys` for key generation

[Unreleased]: https://github.com/highflame-ai/zeroid/compare/v1.1.3...HEAD
[1.1.3]: https://github.com/highflame-ai/zeroid/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/highflame-ai/zeroid/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/highflame-ai/zeroid/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/highflame-ai/zeroid/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/highflame-ai/zeroid/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/highflame-ai/zeroid/releases/tag/v1.0.0
