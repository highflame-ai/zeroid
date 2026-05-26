# Spec compliance test pattern

ZeroID implements a handful of OAuth / OIDC / identity specs (RFCs, OpenID specs, and IETF drafts) and adds others as new features land. Each spec gets a dedicated `<feature>_compliance_test.go` file in this directory whose role is **explicit conformance** to the spec's normative clauses — separate from the happy-path / feature-behaviour tests that live in `<feature>_test.go`.

## Conventions

1. **One file per spec.** Name: `<short-feature>_compliance_test.go` (e.g. `dpop_compliance_test.go`, `dcr_compliance_test.go`, `ciba_compliance_test.go`).

2. **Test name carries the citation.** `TestRFC<num>_S<section>_<assertion>` for RFCs (e.g. `TestRFC9449_S4_2_TypHeaderMustBeDpopJwt`); `TestCIBACore1_0_S<section>_<assertion>` for OpenID specs; `TestSPIFFE_S<section>_<assertion>` for SPIFFE IDs. The prefix is deliberately greppable for spec-revision sweeps.

3. **One MUST per test.** Each test asserts exactly one normative clause (`MUST`, `MUST NOT`, `SHALL`, `REQUIRED`). Don't conflate two MUSTs into one test, even when they share setup.

4. **Comment cites the paragraph.** The first non-blank line of every test body is a comment that quotes or paraphrases the RFC clause being asserted, in the form:
   ```go
   // RFC 9449 §4.2: "There is not more than one signature in the JWS Compact Serialization."
   ```

5. **Negative-space coverage.** Compliance suites are mostly negative-path: "if the client violates X, the server MUST reject with Y." Happy paths are presumed proven by the feature tests.

6. **No happy-path duplication.** If a clause is already exercised by a feature test (e.g. `TestDPoPClientCredentialsFlow` proves `cnf.jkt` is set), the compliance suite need only assert any negative-space invariant the feature test doesn't already cover.

7. **Group by section.** Tests within a file appear in RFC order (§3 before §4 before §5).

## When to add a compliance file

Add one when introducing a feature that implements a spec the project advertises as supported. The bar is "we tell users we conform to this spec" — not just RFCs but also OpenID specs (CIBA) and IETF drafts (SPIFFE / WIMSE). If a spec appears in the README's standards table, it gets a compliance suite.

## Coverage matrix

| Spec | File | Status |
|---|---|---|
| RFC 6749 (OAuth 2.0 core) | `oauth2_compliance_test.go` | Covered |
| RFC 7009 (Token Revocation) | `token_revocation_compliance_test.go` | Covered |
| RFC 7517 (JWKS) | `jwks_compliance_test.go` | Covered |
| RFC 7519 (JWT) | `jwt_compliance_test.go` | Covered |
| RFC 7523 (JWT Bearer grant) | `jwt_bearer_compliance_test.go` | Covered |
| RFC 7591 / 7592 (Dynamic Client Registration) | `dcr_compliance_test.go` | Covered |
| RFC 7636 (PKCE) | `pkce_compliance_test.go` | Covered |
| RFC 7638 (JWK Thumbprint) | exercised by `dpop_compliance_test.go` | Covered |
| RFC 7662 (Introspection) | `introspection_compliance_test.go` | Covered |
| RFC 8414 (AS Metadata) | `discovery_compliance_test.go` | Covered |
| RFC 8693 (Token Exchange) | `token_exchange_compliance_test.go` | Covered |
| RFC 9396 (Rich Authorization Requests) | `rar_compliance_test.go` | Partial — bc-authorize side only; token-side (§5/§6/§7) ships in the follow-up token-embed PR |
| RFC 9449 (DPoP) | `dpop_compliance_test.go` | Covered |
| OpenID CIBA Core 1.0 | `ciba_compliance_test.go` | Covered |
| SPIFFE ID + JWT-SVID | `spiffe_compliance_test.go` | Covered |
| OpenID SSF / CAEP | `cae_test.go` (behavioral) | Partial — see note |

### OpenID SSF / CAEP scope note

ZeroID consumes CAE-style signals via `POST /signals/ingest` and propagates them across delegation chains. The signal schema is ZeroID-local (`signal_type` is a freeform string), NOT strict OpenID SSF/CAEP (which formalize event-type URIs like `https://schemas.openid.net/secevent/caep/event-type/session-revoked`). The behavioral contract — severity-driven revocation, cascade to delegation children — is covered by `cae_test.go`'s 6 happy-path tests. Strict SSF Stream Configuration and Stream Status endpoints (per OpenID SSF §7) aren't implemented; the README's SSF / CAEP entry describes the signal-shape inspiration rather than full stream-protocol conformance. A dedicated SSF/CAEP compliance suite is deferred until those endpoints land.

## Maintenance

When a spec is revised (e.g. an erratum, a successor RFC), search by spec number / name to find every assertion and revisit. The `RFC9449` / `RFC7591` / `CIBACore1_0` / `SPIFFE` prefixes are deliberately greppable.
