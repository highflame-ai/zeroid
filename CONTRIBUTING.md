# Contributing to ZeroID

Thank you for your interest in contributing to ZeroID! This document provides guidelines and information for contributors.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/<you>/zeroid.git`
3. **Set up** your environment:
   ```bash
   make setup-keys    # Generate ECDSA P-256 signing keys
   docker compose up -d postgres  # Start Postgres
   make run           # Start ZeroID
   ```
4. **Create a branch** for your work: `git checkout -b feat/my-feature`

## Development

### Prerequisites

- Go 1.25+
- PostgreSQL 14+
- Docker & Docker Compose (for local dev)

### Project Structure

```
cmd/zeroid/          # Binary entry point
domain/              # Exported domain types (Identity, Credential, etc.)
internal/
  service/           # Business logic
  handler/           # HTTP handlers (Huma v2)
  store/postgres/    # Postgres repositories (Bun ORM)
  middleware/        # Auth middleware
  signing/           # JWKS + JWT signing (ES256, RS256)
  database/          # Migration runner
  telemetry/         # OpenTelemetry
  worker/            # Background workers
migrations/          # SQL migrations (embedded via go:embed)
server.go            # Server builder (library entry point)
config.go            # Configuration
hooks.go             # Extensibility (GrantHandler, PersonGrantResolver, ...)
```

### Running Tests

```bash
make test
```

Integration tests use [testcontainers](https://golang.testcontainers.org/) to spin up a real Postgres instance. No mocks for the database layer.

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- No unnecessary abstractions — three similar lines are better than a premature helper
- Error messages should be lowercase and descriptive
- Comments explain *why*, not *what*

## Making Changes

### What We Welcome

- Bug fixes with test coverage
- New attestation proof types
- Additional OAuth2 grant implementations
- Performance improvements with benchmarks
- Documentation improvements
- New storage backends (MySQL, SQLite, etc.)

### What Needs Discussion First

Open an issue before working on:

- New domain types or API endpoints
- Changes to the JWT claims structure
- Breaking changes to the public API (`domain/`, `server.go`, `config.go`, `hooks.go`)
- Major refactoring

### Commit Messages

Use clear, imperative commit messages:

```
feat: add TPM attestation verification
fix: prevent refresh token reuse after family revocation
docs: add delegation sequence diagram to README
```

Prefixes: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`

## Pull Requests

1. **One concern per PR** — don't mix features with refactoring
2. **Include tests** for new functionality
3. **Update docs** if you change public API or behavior
4. **Keep PRs small** — easier to review, faster to merge
5. **Fill out the PR template** — describe what changed and why

### PR Checklist

- [ ] `make test` passes
- [ ] `go vet ./...` clean
- [ ] New public types/functions have doc comments
- [ ] Migration files are sequential and have both `.up.sql` and `.down.sql`
- [ ] No secrets, keys, or credentials in the diff

## Standards We Follow

ZeroID implements these RFCs. Changes to grant flows or token handling must remain compliant:

| Standard | RFC |
|----------|-----|
| OAuth 2.0 Client Credentials | 6749 §4.4 |
| JWT Assertion Grant | 7523 |
| Token Exchange | 8693 |
| Token Introspection | 7662 |
| Token Revocation | 7009 |
| PKCE | 7636 |
| WIMSE/SPIFFE | SPIFFE spec |

## Reporting Issues

- **Bugs**: Include steps to reproduce, expected vs actual behavior, and ZeroID version
- **Security vulnerabilities**: Email security@zeroid.dev — do **not** open a public issue

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
