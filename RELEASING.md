# Releasing ZeroID

ZeroID is published as **three Go modules** from this one repository:

| Module path | Source tree | Tag prefix |
|----|----|----|
| `github.com/highflame-ai/zeroid` (the root OAuth/OIDC server library) | `./` | `vX.Y.Z` |
| `github.com/highflame-ai/zeroid/pkg/authjwt` | `./pkg/authjwt/` | `pkg/authjwt/vX.Y.Z` |
| `github.com/highflame-ai/zeroid/pkg/dpop` (RFC 9449 DPoP primitive — also consumed by Cerberus, Shield, Firehog directly) | `./pkg/dpop/` | `pkg/dpop/vX.Y.Z` |

Every release tags all three modules at the **same `vX.Y.Z`**. The release flow is a **two-step PR-based pattern** that mirrors what opentelemetry-go and etcd use. This document explains why, how, and what to do when things go sideways.

---

## TL;DR — how to cut a release

```bash
# 1. Open the release-prep PR
make prepare-release VERSION=v1.7.0

# 2. Review the PR in GitHub (it's auto-generated; should be go.mod + go.sum only).
#    Approve + merge it. Use a merge commit or squash — either works.

# 3. Create the root tag + GitHub release
make tag-release VERSION=v1.7.0
```

That's it. Three commands (one is "merge the PR"). Total wall-clock: 5-10 minutes including CI.

Both `make` targets wrap `gh workflow run` against the respective workflows; the raw form is shown under each step below for environments without `make`.

---

## What each step does

### Step 1: `make prepare-release VERSION=v1.7.0`

Triggers [`prepare-release.yml`](.github/workflows/prepare-release.yml). The workflow:

1. **Validates** the version format (`vMAJOR.MINOR.PATCH`).
2. **Tags subpackages first**: pushes `pkg/authjwt/v1.7.0` and `pkg/dpop/v1.7.0` pointing at current `main` HEAD. Idempotent (skip-if-exists). Load-bearing — step 4's `go mod tidy` needs these tags to exist so the proxy can resolve them.
3. **Branches** off `main` as `release-prep/v1.7.0`. Idempotent (reuses existing branch if a prior run created one).
4. **Bumps** `zeroid/go.mod`: `go mod edit -require=...@v1.7.0` for both subpackages, then `go mod tidy` to reconcile `go.sum`.
5. **Commits** as `devops: prepare release v1.7.0` and pushes the branch.
6. **Opens a PR** (`devops: prepare release v1.7.0`) with a checklist + recovery instructions in the body.

Raw command equivalent:

```bash
gh workflow run prepare-release.yml \
  --repo highflame-ai/zeroid \
  --field version=v1.7.0
```

### Step 2: Review + merge the PR

The PR should contain `go.mod` + `go.sum` changes ONLY. The diff is mechanical (version bumps), but human review catches:

- Wrong version specified
- Unexpected indirect deps shuffled by `go mod tidy`
- The subpackage tags actually exist on the remote (mentioned in PR body)

Merge via the UI or `gh pr merge --squash` (commit subject stays compliant either way; `devops:` prefix matches `highflame-commit-check`).

### Step 3: `make tag-release VERSION=v1.7.0`

Triggers [`tag-release.yml`](.github/workflows/tag-release.yml). The workflow:

1. **Validates** the version format.
2. **Guards**: refuses to proceed unless
   - main HEAD's `go.mod` references `pkg/{authjwt,dpop}` at the target version (i.e. the release-prep PR was actually merged), AND
   - `pkg/authjwt/v1.7.0` + `pkg/dpop/v1.7.0` already exist on the remote (created by step 1), AND
   - The release `v1.7.0` does not already exist.
3. **Creates** the GitHub release `v1.7.0` pointing at `main` HEAD with `--generate-notes`.

Raw command equivalent:

```bash
gh workflow run tag-release.yml \
  --repo highflame-ai/zeroid \
  --field version=v1.7.0
```

### What happens after step 3

The existing [`release.yml`](.github/workflows/release.yml) fires on `release: published`. In order:

1. **`highflame-validate`** → tag format + svu semver check + cross-module ref consistency check.
2. **`tag-submodules`** → tries to create `pkg/{authjwt,dpop}/v1.7.0`; they already exist from step 1, so skip-if-exists fires and the job is a no-op.
3. **`highflame-sast`** → runs the integration test suite.
4. **`highflame-goreleaser`** → builds binaries + attaches to the release.
5. **`highflame-docker`** → builds + pushes the Docker image to GHCR.

---

## Why the PR-based flow?

zeroid's root module **imports `pkg/dpop`** in its non-test source code (DPoP RFC 9449 verifier wires into `/oauth2/token` for DPoP-bound tokens). Concretely:

```
server.go                              → import ".../pkg/dpop"
internal/handler/routes.go             → import ".../pkg/dpop"
internal/handler/oauth.go              → import ".../pkg/dpop"
internal/store/postgres/dpop_replay.go → import ".../pkg/dpop"
```

`pkg/authjwt` is imported only from `tests/integration/`, which means Go's module resolution doesn't pull it transitively for downstream consumers. But `pkg/dpop` IS a real load-bearing transitive dep — every `go get github.com/highflame-ai/zeroid@vX.Y.Z` from an external consumer (authn, shield, anyone) requires Go to resolve `pkg/dpop@vX.Y.Z` from the proxy.

**The trap:** Go's `replace` directives only apply to the *main* module being built — they do NOT propagate to downstream consumers. So `replace github.com/highflame-ai/zeroid/pkg/dpop => ./pkg/dpop` in `zeroid/go.mod` works for in-repo dev but every external `go get zeroid@vX.Y.Z` fails because `go.mod`'s require directive still says `pkg/dpop v0.0.0` and `v0.0.0` doesn't exist as a published tag.

**The fix is to keep `zeroid/go.mod`'s cross-module version refs in lockstep with the actual released subpackage tags.** That's the entire purpose of `prepare-release.yml`. PR-based review of the bump (rather than direct push to main) is the industry-standard shape — see opentelemetry-go's `make prerelease`, etcd's release tooling, kubernetes's staging publishing-bot.

In-repo dev experience is preserved by `go.work` at the repo root. Go reads it automatically when you `go build` from anywhere inside the tree and overrides published version refs with local source. No manual `replace` directives needed.

---

## Subtle consistency note

Because `prepare-release.yml` tags subpackages BEFORE creating the bump commit, the sub-tags `pkg/{authjwt,dpop}/vX.Y.Z` point at the **pre-bump main HEAD** while the root tag `vX.Y.Z` points at the **merge commit** (one commit later). The two commits differ only in `zeroid/go.mod` and `zeroid/go.sum` — `pkg/dpop/` and `pkg/authjwt/` source is byte-identical at both commits — so the semantic content under both tags matches. A downstream `go get github.com/highflame-ai/zeroid/pkg/dpop@vX.Y.Z` and a downstream `go get github.com/highflame-ai/zeroid@vX.Y.Z` both get a consistent view.

This is the same approach kubernetes/staging uses for its pre-release pattern. The alternative — tagging subpackages at the merge commit — would require running `go mod tidy` BEFORE the subpackage tags exist, which is what creates the chicken-and-egg.

---

## What happens if I bypass the flow?

### GitHub UI: "Draft a new release"

If you draft a release in the UI and click Publish directly (bypassing `prepare-release.yml`), the existing `release.yml`'s cross-module validate-gate **will fail** with a clear error:

```
::error::go.mod references github.com/highflame-ai/zeroid/pkg/dpop v1.6.0 but release is v1.7.0.
::error::Run prepare-release.yml with version=v1.7.0, OR manually:
::error::  go mod edit -require=github.com/highflame-ai/zeroid/pkg/dpop@v1.7.0 && go mod tidy
::error::  git commit -am 'devops: prepare release v1.7.0' && git push
::error::Then re-publish the release pointing at the new commit.
```

The release page exists, but no sub-tags, no goreleaser binaries, no Docker image. **Cleanest recovery**: delete the release + tag, then `make prepare-release VERSION=v1.7.0` and proceed normally.

### `make tag-release` without the PR merged

`tag-release.yml`'s first guard checks that main HEAD's `go.mod` references the target version. If you ran `make tag-release VERSION=v1.7.0` without first merging the release-prep PR, that guard fails:

```
::error::go.mod references github.com/highflame-ai/zeroid/pkg/dpop v1.6.0 but target is v1.7.0.
::error::Did you merge the release-prep PR for v1.7.0?
```

No release is created. Re-run `make prepare-release`, merge the PR, then re-run `make tag-release`.

### Abandoning a release-prep PR

If you close a release-prep PR without merging, the sub-tags pushed by `prepare-release.yml` become **orphans** — they point at a real commit with valid source, but no root tag references them. They're not catastrophic, but worth cleaning up:

```bash
git push --delete origin pkg/authjwt/v1.7.0 pkg/dpop/v1.7.0
```

---

## The svu gate, briefly

`release.yml`'s first gate (after the tag-format check) runs [svu](https://github.com/caarlos0/svu) to compute the expected next version from commit-prefix history. It maps:

- `feat:` → MINOR bump (e.g. v1.6.0 → v1.7.0)
- `fix:` → PATCH bump (e.g. v1.6.0 → v1.6.1)
- `feat!:` or `BREAKING CHANGE:` → MAJOR bump (e.g. v1.x.x → v2.0.0)
- `devops:`, `build(deps)`, `[Snyk]`, `Bump`, `Merge`, `Revert` — no bump (housekeeping)

The gate **fails if your release tag is below svu's recommendation** (e.g. you pick `v1.6.1` but svu says `v1.7.0` because there's been a `feat:` commit since the last tag — that would silently ship a feature as a patch). The gate **allows tags at or above the recommendation**, so a maintainer can force a higher bump when intentional.

The `devops: prepare release vX.Y.Z` commit created by `prepare-release.yml` is correctly classified by svu as housekeeping (no version movement), so the bump commit itself doesn't perturb svu's recommendation for the release.

Run `make next-version` at any time to see what svu would recommend.

---

## Adding a new nested module

If you introduce a new module (e.g. `pkg/dcr/`), update **four places**:

1. **`go.work`** — add `./pkg/dcr` to the `use (...)` list.
2. **`.github/workflows/release.yml`** — append `pkg/dcr` to the `SUBMODULES=(...)` array in both `tag-submodules` AND the cross-module validate-gate.
3. **`.github/workflows/prepare-release.yml`** — append `pkg/dcr` to the `SUBMODULES=(...)` array in the tag-sub-modules step, and add `-require=github.com/highflame-ai/zeroid/pkg/dcr@${VERSION}` to the `go mod edit` step.
4. **`.github/workflows/tag-release.yml`** — append `pkg/dcr` to the `SUBMODULES=(...)` array in the verify-go.mod-refs step AND the verify-sub-module-tags step.

After the next release, downstream consumers can `go get github.com/highflame-ai/zeroid/pkg/dcr@vX.Y.Z`.

---

## Industry context

This pattern (workspace for dev + real version refs in go.mod + PR-based release prep + CLI-triggered tagging) is the standard Go-monorepo idiom. References:

- **opentelemetry-go** — `make prerelease` opens release-prep PR, `make tag` creates tags atomically. [RELEASING.md](https://github.com/open-telemetry/opentelemetry-go/blob/main/RELEASING.md)
- **etcd** — `./scripts/release` opens release-prep PR, separate script tags. [github.com/etcd-io/etcd/release](https://github.com/etcd-io/etcd/tree/main/release)
- **kubernetes/staging** — uses publishing-bot to mirror each module to a separate read-only repo. Different approach for much larger scale; overkill for zeroid.

None of these use the GitHub release UI as the primary release entry point — the UI is treated as a downstream side effect of CLI/automation, never as the source of truth.
