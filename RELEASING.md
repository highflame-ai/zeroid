# Releasing ZeroID

ZeroID is published as **three Go modules** from this one repository:

| Module path | Source tree | Tag prefix |
|----|----|----|
| `github.com/highflame-ai/zeroid` (the root OAuth/OIDC server library) | `./` | `vX.Y.Z` |
| `github.com/highflame-ai/zeroid/pkg/authjwt` | `./pkg/authjwt/` | `pkg/authjwt/vX.Y.Z` |
| `github.com/highflame-ai/zeroid/pkg/dpop` (RFC 9449 DPoP primitive — also consumed by Cerberus, Shield, Firehog directly) | `./pkg/dpop/` | `pkg/dpop/vX.Y.Z` |

Every release tags all three modules at the **same `vX.Y.Z`**. This document explains why, how, and what to do when things go sideways.

---

## TL;DR — how to cut a release

```bash
gh workflow run prepare-release.yml \
  --repo highflame-ai/zeroid \
  --field version=v1.7.0
```

Then watch:

- `prepare-release.yml` (in-progress, ~30s) — bumps `zeroid/go.mod` cross-module refs, commits as `devops: prepare release v1.7.0`, pushes to main, creates the GitHub release.
- `release.yml` (fires on release-published, ~3-5m) — validates, runs tests, builds the goreleaser binaries, builds + pushes the Docker image.

**Do not use the GitHub UI's "Draft a new release" button directly.** It still works mechanically, but it skips the cross-module version bump that downstream consumers need — `release.yml`'s validate-gate will reject the release if `zeroid/go.mod` is out of sync. See [Recovery](#recovery--what-if-i-publish-directly-via-the-ui) below.

---

## Why prepare-release exists — the quirk

ZeroID's root module **imports `pkg/dpop`** in its non-test source code (the DPoP verifier wires into `/oauth2/token` for RFC 9449 DPoP-bound tokens). Concretely:

```
server.go                              → import ".../pkg/dpop"
internal/handler/routes.go             → import ".../pkg/dpop"
internal/handler/oauth.go              → import ".../pkg/dpop"
internal/store/postgres/dpop_replay.go → import ".../pkg/dpop"
```

`pkg/authjwt` is imported only from `tests/integration/`, which means it's NOT a transitive dependency of downstream consumers (Go's module resolution only follows non-test imports across module boundaries). But `pkg/dpop` IS a real load-bearing transitive dep — whenever anyone runs `go get github.com/highflame-ai/zeroid@vX.Y.Z`, Go has to resolve `pkg/dpop@vX.Y.Z` from the proxy.

**The trap:** Go's `replace` directives only apply to the *main* module being built — they do NOT propagate to downstream consumers. So writing `replace github.com/highflame-ai/zeroid/pkg/dpop => ./pkg/dpop` in `zeroid/go.mod` makes in-repo dev work, but every `go get zeroid@vX.Y.Z` from outside the repo fails because `zeroid/go.mod`'s require directive still says `pkg/dpop v0.0.0` and `v0.0.0` doesn't exist as a published tag. This is why `prepare-release.yml` exists: to keep `zeroid/go.mod`'s cross-module version refs in lockstep with the actual released tags.

**In-repo dev experience is preserved** by `go.work` at the repo root. Go automatically reads it when you `go build` from anywhere inside the tree and overrides the published version refs with the local source. No manual `replace` directives needed.

This pattern (workspace for dev + real version refs in go.mod + automated release-prep) is the standard Go-monorepo idiom — see kubernetes/staging, etcd, opentelemetry-go for the same shape.

---

## What prepare-release.yml does, step by step

For `version=v1.7.0`:

1. **Validates** the version format matches `vMAJOR.MINOR.PATCH`.
2. **Checks out** `main` at current HEAD.
3. **Tags subpackages first** at current HEAD: pushes `pkg/authjwt/v1.7.0` and `pkg/dpop/v1.7.0`.
   - Why first? Step 5's `go mod tidy` needs to resolve these new versions, which requires the tags to exist (`go list -m` would otherwise error with `unknown revision`).
   - Idempotent: skips tags that already exist (handles re-runs after a failed attempt).
4. **Bumps `zeroid/go.mod`** cross-module refs to `v1.7.0` via `go mod edit -require=...@v1.7.0`.
5. **Runs `go mod tidy`** to reconcile `go.sum` against the new version.
6. **Commits** the bump as `devops: prepare release v1.7.0` and pushes to `main`.
7. **Creates the GitHub release** pointing at that commit with auto-generated notes.

The downstream `release.yml` workflow (which fires on `release: published`) then:

1. Validates the tag format + svu semver match.
2. Validates cross-module refs match the release tag (this is the gate that catches missing bumps).
3. Sub-tags subpackages at the release commit (idempotent; skips since prepare-release already created them).
4. Runs the integration test suite.
5. Runs goreleaser + Docker build.

---

## Subtle consistency note

Because `prepare-release.yml` tags subpackages BEFORE the bump commit, the sub-tag `pkg/dpop/vX.Y.Z` points at the **pre-bump main HEAD**, while the root tag `vX.Y.Z` points at the **bump commit** (one commit later). The two commits differ only in `zeroid/go.mod` and `zeroid/go.sum` — `pkg/dpop/` source is byte-identical at both commits — so the semantic content under both tags matches. A downstream `go get github.com/highflame-ai/zeroid/pkg/dpop@vX.Y.Z` and a downstream `go get github.com/highflame-ai/zeroid@vX.Y.Z` both get a consistent view.

This is the same approach kubernetes/staging uses for its prerelease pattern. The alternative — tagging subpackages at the bump commit — would require running `go mod tidy` BEFORE the subpackage tags exist, which is what creates the chicken-and-egg.

---

## Recovery — what if I publish directly via the UI?

GitHub's "Draft a new release" button works mechanically (the tag gets created), but `release.yml`'s **validate-gate will fail** with a clear error:

```
::error::go.mod references github.com/highflame-ai/zeroid/pkg/dpop v1.6.0 but release is v1.7.0.
::error::Run prepare-release.yml with version=v1.7.0, OR manually:
::error::  go mod edit -require=github.com/highflame-ai/zeroid/pkg/dpop@v1.7.0 && go mod tidy
::error::  git commit -am 'devops: prepare release v1.7.0' && git push
::error::Then re-publish the release pointing at the new commit.
```

**Cleanest recovery:**

1. Delete the GitHub release.
2. Delete the root tag: `git push --delete origin v1.7.0`.
3. Delete any sub-tags that got created (none, if validate failed before tag-submodules ran).
4. Re-run `prepare-release.yml`.

**Manual recovery** (if you want to keep the release):

1. Locally on main: `go mod edit -require=github.com/highflame-ai/zeroid/pkg/authjwt@v1.7.0 -require=github.com/highflame-ai/zeroid/pkg/dpop@v1.7.0 && go mod tidy`.
2. `git commit -am 'devops: prepare release v1.7.0' && git push origin main`.
3. Move the v1.7.0 tag to the new commit: `git tag -f v1.7.0 && git push --force origin v1.7.0`. (Force-pushing a tag is generally bad practice, but acceptable here if the release was published seconds ago and no one has pulled it yet.)
4. Re-trigger `release.yml` via `gh workflow run release.yml` or by republishing the release.

---

## The svu gate, briefly

`release.yml`'s first gate (after the tag-format check) runs [svu](https://github.com/caarlos0/svu) to compute the expected next version from commit-prefix history. It maps:

- `feat:` → MINOR bump (e.g. v1.6.0 → v1.7.0)
- `fix:` → PATCH bump (e.g. v1.6.0 → v1.6.1)
- `feat!:` or `BREAKING CHANGE:` → MAJOR bump (e.g. v1.x.x → v2.0.0)
- `devops:`, `build(deps)`, `[Snyk]`, `Bump`, `Merge`, `Revert` — no bump (housekeeping)

The gate **fails if your release tag is below svu's recommendation** (e.g. you published `v1.6.1` but svu says `v1.7.0` because there's been a `feat:` commit since the last tag — that would silently ship a feature as a patch). The gate **allows tags at or above the recommendation**, so a maintainer can manually force a higher bump when intentional.

The `devops: prepare release vX.Y.Z` commit created by `prepare-release.yml` is correctly classified by svu as housekeeping (no version movement), so the bump commit itself doesn't perturb svu's recommendation for the release.

---

## Adding a new nested module

If you introduce a new module (e.g. `pkg/dcr/`), three things must change:

1. **`go.work`** — add `./pkg/dcr` to the `use (...)` list.
2. **`.github/workflows/release.yml`** — append `pkg/dcr` to the `SUBMODULES=(...)` array in both `tag-submodules` AND the cross-module validate-gate.
3. **`.github/workflows/prepare-release.yml`** — append `pkg/dcr` to the `SUBMODULES=(...)` array in `Tag sub-modules at current HEAD`, and add `-require=github.com/highflame-ai/zeroid/pkg/dcr@${VERSION}` to the `go mod edit` step.

After the next release, downstream consumers can `go get github.com/highflame-ai/zeroid/pkg/dcr@vX.Y.Z`.
