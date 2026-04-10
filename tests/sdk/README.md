# SDK Smoke Tests

End-to-end tests that verify the Python and TypeScript SDKs against a real ZeroID server. Each test run:

1. Starts a PostgreSQL container via [testcontainers](https://testcontainers.com/)
2. Generates ECDSA + RSA signing keys
3. Builds the `zeroid` binary from source (`go build`)
4. Starts the server on a random port
5. Runs the full SDK lifecycle (register, issue, verify, revoke, etc.)
6. Tears everything down

No Docker Compose, no manual setup — works identically in CI and local dev.

## Prerequisites

- **Go** (to build zeroid from source)
- **Docker** (for testcontainers)
- **OpenSSL** (for key generation)

## Python

```bash
# Install deps
pip install highflame testcontainers "PyJWT>=2.8" cryptography pytest

# Run
pytest tests/sdk/test_sdk_smoke.py -v
```

## TypeScript

```bash
# Install deps
cd tests/sdk
npm init -y
npm install --save-dev vitest @testcontainers/postgresql
npm install @highflame/sdk

# Run
npx vitest run sdk-smoke.test.ts
```

## What's tested

| Test | Python | TypeScript |
|------|--------|------------|
| Health check + JWKS discovery | `TestHealth` | `Health` |
| Agent register → get → list → deactivate → activate → rotate → delete | `TestAgentLifecycle` | `Agent lifecycle` |
| Token issue (API key) → verify → session introspect → revoke | `TestTokenLifecycle` | `Token lifecycle` |
| `require_scope` pass/fail, `require_trust`, `is_delegated` | `TestVerificationGuards` | `Verification guards` |
| 404 on nonexistent agent, inactive on invalid token | `TestErrorHandling` | `Error handling` |

## CI

These run automatically on every PR via `.github/workflows/sdk-integration.yml` as two parallel jobs.
