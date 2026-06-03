# Releasing ZeroID

ZeroID is published as **three Go modules** from this one repository:

| Module path | Source tree | Tag prefix | Release cadence |
|----|----|----|----|
| `github.com/highflame-ai/zeroid` (the root OAuth/OIDC server library) | `./` | `vX.Y.Z` | Whenever zeroid features/fixes ship |
| `github.com/highflame-ai/zeroid/pkg/authjwt` | `./pkg/authjwt/` | `pkg/authjwt/vX.Y.Z` | **Clubbed with zeroid** — same vX.Y.Z |
| `github.com/highflame-ai/zeroid/pkg/dpop` (RFC 9449 DPoP primitive — also consumed by Cerberus, Shield, Firehog directly) | `./pkg/dpop/` | `pkg/dpop/vX.Y.Z` | **Decoupled** — released independently when its source changes |

The asymmetry between pkg/authjwt and pkg/dpop is deliberate:

- **pkg/dpop** is imported in zeroid's non-test code (the DPoP RFC 9449 verifier in `/oauth2/token`). That makes it a transitive dep for everyone who consumes zeroid — `go get zeroid@vX.Y.Z` causes Go to also fetch pkg/dpop's source. So zeroid/go.mod must reference a real published pkg/dpop tag, and it gets a decoupled release cadence so we only bump it when pkg/dpop actually changes.
- **pkg/authjwt** is imported only from `tests/integration/`. Go doesn't follow test imports across module boundaries, so its version reference in zeroid/go.mod is invisible to downstream consumers and never needs to be a real version. The pkg/authjwt tag is created at every zeroid release (clubbed) for convenience of direct consumers.

---

## How to cut a normal zeroid release (the common case)

If you haven't touched `pkg/dpop/` source since the last release, this is your whole flow:

```
1. github.com/highflame-ai/zeroid → Releases → "Draft a new release"
2. Choose a tag → "Create new tag: vX.Y.Z on publish"
3. Generate release notes
4. Click "Publish release"
5. Wait ~3-5 minutes
```

The `release.yml` workflow validates the tag format, runs svu against commit history, checks pkg/dpop source matches what go.mod references (the drift guard), tags `pkg/authjwt/vX.Y.Z` at the release commit, runs integration tests, builds goreleaser binaries, and pushes the Docker image.

To preview what svu would recommend:

```bash
make next-version
```

---

## When you change pkg/dpop/

If you've modified anything under `pkg/dpop/`, **cut a new pkg/dpop release first**, BEFORE the next zeroid release:

```bash
# 1. Cut a new pkg/dpop release (tags pkg/dpop/vX.Y.Z + opens a PR
#    bumping zeroid/go.mod's pkg/dpop reference)
make release-dpop VERSION=v1.6.1

# 2. Review + merge the auto-opened PR titled
#    "devops: bump pkg/dpop to v1.6.1"

# 3. (Later) Cut your zeroid release normally via GitHub UI.
#    It will ship with pkg/dpop v1.6.1.
```

If you skip step 1-2 and try to cut a zeroid release directly, `release.yml`'s drift guard fails with a clear error:

```
::error::pkg/dpop/ source has drifted from pkg/dpop/v1.6.0 but go.mod still references it.
::error::Releasing zeroid now would ship a binary using the OLD pkg/dpop v1.6.0, while
::error::in-repo tests passed against the NEW local source. Silent regression risk.
::error::Fix by running release-dpop.yml first to cut a new pkg/dpop release and update
::error::zeroid/go.mod's reference:
::error::  gh workflow run release-dpop.yml --field version=<next-dpop-vX.Y.Z>
::error::  # ...review + merge the PR opened by release-dpop, then re-publish this release.
```

This is the safety net — you can't silently ship a zeroid binary built against a different pkg/dpop than what consumers will resolve from the proxy.

---

## How pkg/dpop versioning works

`zeroid/go.mod` references a specific pinned version of pkg/dpop:

```
require github.com/highflame-ai/zeroid/pkg/dpop v1.6.0
```

This reference is **static across most zeroid releases**. When zeroid v1.7.0 ships, its go.mod still says `pkg/dpop v1.6.0` if pkg/dpop hasn't changed. Consumers `go get zeroid@v1.7.0` and transitively resolve `pkg/dpop v1.6.0` from the proxy — fine, because that tag exists.

The reference only changes when:

1. You modify pkg/dpop/ source.
2. You run `make release-dpop VERSION=v1.6.1`.
3. The workflow tags `pkg/dpop/v1.6.1` and opens a PR updating zeroid/go.mod's require directive.
4. You merge the PR.

Now main's go.mod says `pkg/dpop v1.6.1`, and the next zeroid release ships that reference.

### In-repo dev

The `go.work` file at the repo root makes Go use local pkg/dpop source for in-repo builds, regardless of what versions go.mod references. So you can iterate on pkg/dpop/ freely without bumping anything until you're ready to cut a new pkg/dpop release.

### Why this works

| Concern | How it's handled |
|---------|------------------|
| Chicken-and-egg (bump go.mod to vX.Y.Z before vX.Y.Z exists on proxy) | Eliminated. zeroid releases don't bump pkg/dpop refs. The release-dpop flow tags pkg/dpop FIRST, then opens the PR — the PR's CI can resolve the new version. |
| Force-pushing tags | Never needed. The release tag is created at the correct commit on the first try. |
| Source drift (changing pkg/dpop/ without releasing it) | Caught by the drift guard in `release.yml`. Fails the release with a clear pointer at `release-dpop.yml`. |
| Orphan tags (abandoning a release-dpop PR) | The orphan `pkg/dpop/vX.Y.Z` tag points at a real commit with valid source. Easy cleanup: `git push --delete origin pkg/dpop/vX.Y.Z`. |

---

## The svu gate, briefly

`release.yml`'s validation runs [svu](https://github.com/caarlos0/svu) against commit history. It maps:

- `feat:` → MINOR bump
- `fix:` → PATCH bump
- `feat!:` or `BREAKING CHANGE:` → MAJOR bump
- `devops:`, `build(deps)`, `[Snyk]`, `Bump`, `Merge`, `Revert` — no bump

The gate fails if your release tag is below svu's recommendation (you'd silently ship a `feat:` as a patch). It allows tags at or above the recommendation, so you can manually force a higher bump.

Run `make next-version` to preview.

---

## What if something goes wrong

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Invalid version format` | Tag doesn't match `vMAJOR.MINOR.PATCH` | Use a semver tag |
| `Release tag X is below svu's computed next version Y` | A `feat:` commit since the last tag implies a minor bump | Re-create the release at Y or higher |
| `pkg/dpop/ source has drifted from pkg/dpop/X` | You changed pkg/dpop/ since the last pkg/dpop release | `make release-dpop VERSION=<next>`, merge the PR, then re-publish your zeroid release |
| `Tag pkg/dpop/X does not exist` | go.mod references a pkg/dpop tag that was never created | Either fix go.mod to reference an existing tag, or run `make release-dpop` |
| Auto-opened release-dpop PR fails CI | go.sum got out of sync or there's a real test regression in pkg/dpop | Check the PR's CI logs; fix on the branch or close the PR |

---

## Adding a new nested module

Going forward, nested modules should follow the same pattern as pkg/dpop — decoupled release cadence — IF they get imported in zeroid's non-test code. If they're test-only (like pkg/authjwt currently), they can stay clubbed.

To add a new decoupled nested module (e.g. `pkg/dcr/`):

1. **`go.work`** — add `./pkg/dcr` to the `use (...)` list.
2. **`zeroid/go.mod`** — add `require github.com/highflame-ai/zeroid/pkg/dcr vX.Y.Z` with a real published version.
3. **`.github/workflows/release.yml`** — extend the drift guard step to also check pkg/dcr.
4. **Add `.github/workflows/release-dcr.yml`** — copy `release-dpop.yml` and adjust paths.
5. **`Makefile`** — add `make release-dcr` target.

To add a test-only nested module that stays clubbed (like pkg/authjwt):

1. **`go.work`** — add it to the `use (...)` list.
2. **`zeroid/go.mod`** — leave at `v0.0.0`.
3. **`.github/workflows/release.yml`** — extend the tag-submodules step to also tag pkg/<new>/vX.Y.Z at release commit.

---

## Industry context

This pattern (decoupled release cadence for genuinely-shared subpackages, clubbed for test-only ones, with a drift guard catching the foot-gun) maps closely to how `golang.org/x/*` modules relate to Go itself — they're versioned independently and consumers pin them explicitly. It's also similar to how kubernetes-staging modules work (those are even more decoupled, with a separate publishing bot).

For zeroid's scale (one maintainer, low release frequency, slow pkg/dpop churn), this trade-off lands cleanly:

- Common case: zero CLI commands. Click Publish in UI.
- pkg/dpop changes case: one extra CLI command (`make release-dpop`) plus a PR review. Infrequent.
- Foot-gun: caught by the drift guard before it ships.

If pkg/dpop ever ends up changing on every zeroid release (defeating the decoupled benefit), it's a signal to revisit — maybe clubbing makes more sense, or maybe the design got refactored. Today, the cadences are genuinely different and the decoupled pattern is right.
