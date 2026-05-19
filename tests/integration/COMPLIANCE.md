# RFC compliance test pattern

ZeroID implements a handful of OAuth / OIDC RFCs and adds others as new features land. Each RFC gets a dedicated `<feature>_compliance_test.go` file in this directory whose role is **explicit conformance** to the spec's normative clauses — separate from the happy-path / feature-behaviour tests that live in `<feature>_test.go`.

## Conventions

1. **One file per RFC.** Name: `<short-feature>_compliance_test.go` (e.g. `dpop_compliance_test.go`, `dcr_compliance_test.go`).

2. **Test name carries the citation.** `TestRFC<num>_S<section>_<assertion>` (e.g. `TestRFC9449_S4_2_TypHeaderMustBeDpopJwt`). The number is the RFC, the section is dotted-then-underscored, and the assertion is a short imperative.

3. **One MUST per test.** Each test asserts exactly one normative clause (`MUST`, `MUST NOT`, `SHALL`, `REQUIRED`). Don't conflate two MUSTs into one test, even when they share setup.

4. **Comment cites the paragraph.** The first non-blank line of every test body is a comment that quotes or paraphrases the RFC clause being asserted, in the form:
   ```go
   // RFC 9449 §4.2: "There is not more than one signature in the JWS Compact Serialization."
   ```

5. **Negative-space coverage.** Compliance suites are mostly negative-path: "if the client violates X, the server MUST reject with Y." Happy paths are presumed proven by the feature tests.

6. **No happy-path duplication.** If a clause is already exercised by a feature test (e.g. `TestDPoPClientCredentialsFlow` proves `cnf.jkt` is set), the compliance suite need only assert any negative-space invariant the feature test doesn't already cover.

7. **Group by section.** Tests within a file appear in RFC order (§3 before §4 before §5).

## When to add a compliance file

Add one when introducing a feature that implements an RFC the project advertises as supported. The bar is "we tell users we conform to this RFC" — if the feature touches a spec, it gets a compliance suite. The first three landed alongside the feature itself:

- [`dpop_compliance_test.go`](./dpop_compliance_test.go) — RFC 9449
- [`dcr_compliance_test.go`](./dcr_compliance_test.go) — RFC 7591 / RFC 7592

## Maintenance

When the RFC is revised (e.g. an erratum, a successor RFC), search by RFC number to find every assertion and revisit. The `RFC9449` / `RFC7591` prefix is deliberately greppable.
