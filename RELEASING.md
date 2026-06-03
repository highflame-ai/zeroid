# Releasing ZeroID

ZeroID is published as **three Go modules** from this one repository:

| Module path | Source tree | Tag prefix |
|----|----|----|
| `github.com/highflame-ai/zeroid` (the root OAuth/OIDC server library) | `./` | `vX.Y.Z` |
| `github.com/highflame-ai/zeroid/pkg/authjwt` | `./pkg/authjwt/` | `pkg/authjwt/vX.Y.Z` |
| `github.com/highflame-ai/zeroid/pkg/dpop` (RFC 9449 DPoP primitive — also consumed by Cerberus, Shield, Firehog directly) | `./pkg/dpop/` | `pkg/dpop/vX.Y.Z` |

Every release tags all three modules at the **same `vX.Y.Z`**. The release flow is **driven entirely from the GitHub UI**; the workflow handles cross-module bumping invisibly.

---

## How to cut a release

```
1. github.com/highflame-ai/zeroid → Releases → "Draft a new release"
2. Choose a tag → "Create new tag: vX.Y.Z on publish"
3. (Optional) Generate release notes
4. Click "Publish release"
5. Wait ~3–5 minutes
```

That's it. No CLI commands, no PRs to review, no manual go.mod edits. Whatever version you pick (subject to the svu gate — see below), the `release.yml` workflow takes over and handles everything.

To preview what version svu would recommend (based on commit prefixes since the last tag):

```bash
make next-version
```

---

## What happens after you click Publish

`release.yml` fires on the `release: published` event and runs these jobs in order:

```
1. bump-go-mod
   ├─ Validate tag format (vMAJOR.MINOR.PATCH)
   ├─ Verify release was cut from main (not a feature branch)
   ├─ Tag pkg/authjwt/vX.Y.Z + pkg/dpop/vX.Y.Z at current main HEAD
   ├─ go mod edit -require=...@vX.Y.Z for each subpackage
   ├─ go mod tidy (works because sub-tags now exist)
   ├─ git commit -m "devops: prepare release vX.Y.Z"
   ├─ git push origin main          ← new commit on main
   ├─ git tag -f vX.Y.Z + git push --force origin vX.Y.Z   ← release tag now points at bump commit
   └─ gh release edit vX.Y.Z --target <bump-sha>           ← release page UI updates

2. highflame-validate
   ├─ svu gate: verifies vX.Y.Z is at or above what commit-history implies
   └─ cross-module gate: defensive — verifies go.mod refs match vX.Y.Z (bump-go-mod should have ensured this)

3. tag-submodules
   └─ Idempotent skip — sub-tags already created in step 1

4. highflame-sast → integration tests
5. highflame-goreleaser → binaries attached to the release
6. highflame-docker → image pushed to GHCR
```

Total wall-clock: ~3–5 minutes from clicking Publish to the release being fully complete.

---

## Why the auto-bump exists

zeroid's root module **imports `pkg/dpop`** in its non-test source code (the DPoP RFC 9449 verifier wires into `/oauth2/token` for DPoP-bound tokens). Concretely:

```
server.go                              → import ".../pkg/dpop"
internal/handler/routes.go             → import ".../pkg/dpop"
internal/handler/oauth.go              → import ".../pkg/dpop"
internal/store/postgres/dpop_replay.go → import ".../pkg/dpop"
```

`pkg/authjwt` is imported only from `tests/integration/` — Go's module resolution doesn't follow test imports across module boundaries, so it's not a transitive dep for downstream consumers. But `pkg/dpop` IS a real load-bearing transitive dep. Every external `go get github.com/highflame-ai/zeroid@vX.Y.Z` requires Go to resolve `pkg/dpop@vX.Y.Z` from the proxy.

**Go's `replace` directives don't propagate across module boundaries.** A `replace github.com/highflame-ai/zeroid/pkg/dpop => ./pkg/dpop` in zeroid's go.mod works for in-repo dev but every external consumer sees the `require pkg/dpop v0.0.0` directive instead, fails to resolve it, and breaks. Hence the need to keep `zeroid/go.mod` referencing real released subpackage versions in lockstep with the release tag.

In-repo dev is unaffected — the `go.work` file at the repo root makes Go use the local subdirectories regardless of what versions go.mod declares.

---

## The force-moved tag

`bump-go-mod` does the bump AFTER the release tag is created (when you click Publish), then force-moves the tag to point at the bump commit. This sounds scary but is fine in practice:

- The force-move happens within ~30 seconds of the original tag creation.
- No downstream consumer has had time to pull v1.7.0 in that window.
- The GitHub release page is updated via `gh release edit --target` so users see the correct commit.
- The Go module proxy fetches on-demand; subsequent fetches return the post-bump commit's source.

The "no force-pushing tags" rule from git lore is about long-lived tag history, not about adjustments within seconds of creation before anyone has noticed. goreleaser-pro and several other Go release tools do the same thing internally.

---

## Subtle consistency note

`bump-go-mod` creates the sub-module tags BEFORE the bump commit exists. So:

- `pkg/authjwt/vX.Y.Z` → pre-bump commit (the commit you clicked Publish on)
- `pkg/dpop/vX.Y.Z` → pre-bump commit (same)
- `vX.Y.Z` (root) → post-bump commit (the `devops: prepare release vX.Y.Z` commit)

The two commits differ only in `zeroid/go.mod` and `zeroid/go.sum`. `pkg/dpop/` and `pkg/authjwt/` source trees are byte-identical at both commits. A downstream `go get github.com/highflame-ai/zeroid/pkg/dpop@vX.Y.Z` and a downstream `go get github.com/highflame-ai/zeroid@vX.Y.Z` produce a consistent view of the source tree.

This is the same approach kubernetes-staging and opentelemetry-go use for their multi-module release patterns. The alternative — tagging subpackages at the bump commit — would require running `go mod tidy` BEFORE the subpackage tags exist, which creates a chicken-and-egg the proxy can't resolve.

---

## The svu gate, briefly

`release.yml`'s second job (`highflame-validate`) runs [svu](https://github.com/caarlos0/svu) to compute the expected next version from commit-prefix history. It maps:

- `feat:` → MINOR bump (e.g. v1.6.0 → v1.7.0)
- `fix:` → PATCH bump (e.g. v1.6.0 → v1.6.1)
- `feat!:` or `BREAKING CHANGE:` → MAJOR bump (e.g. v1.x.x → v2.0.0)
- `devops:`, `build(deps)`, `[Snyk]`, `Bump`, `Merge`, `Revert` — no bump (housekeeping)

The gate **fails if your release tag is below svu's recommendation** (you'd silently ship a `feat:` as a patch). The gate **allows tags at or above the recommendation**, so a maintainer can force a higher bump when intentional. Run `make next-version` to preview.

The `devops: prepare release vX.Y.Z` commit created by `bump-go-mod` is correctly classified by svu as housekeeping (no version movement) — the bump commit itself doesn't perturb the next release's recommendation.

---

## What if something goes wrong

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Refuse releases from non-main branches` | You picked a `target_commitish` that isn't main | Re-create the release with target = main |
| `Invalid version format` | Tag doesn't match `vMAJOR.MINOR.PATCH` | Use a semver tag |
| `Release tag X is below svu's computed next version Y` | A `feat:` commit since the last tag implies a minor bump | Re-create the release at version Y (or higher), or audit the commit prefixes |
| `App token failed to push to main` | The release-bot App lacks branch-protection bypass | Add the bot to the bypass list in repo settings → branches → main |
| `tag-submodules` already exist | Re-running a release that previously partially succeeded | Idempotent skip; no action needed |
| go.mod references a different version after bump | bump-go-mod failed mid-way and you have a partial state | Manually verify go.mod on main is consistent with the latest release tag; re-run any failed workflows |

The most common failure mode is **App token can't push to main due to branch protection.** The fix is to add `highflame-release-bot[bot]` to the bypass list for `main`. Without this, `bump-go-mod` will fail at the commit-and-push step and the rest of the release workflow won't run.

---

## Adding a new nested module

If you introduce a new module (e.g. `pkg/dcr/`), update **two places**:

1. **`go.work`** — add `./pkg/dcr` to the `use (...)` list.
2. **`.github/workflows/release.yml`** — append `pkg/dcr` to the `SUBMODULES` arrays in BOTH `bump-go-mod` AND `tag-submodules`, and add the corresponding `-require=github.com/highflame-ai/zeroid/pkg/dcr@${VERSION}` to the `go mod edit` step in `bump-go-mod`.

After the next release, downstream consumers can `go get github.com/highflame-ai/zeroid/pkg/dcr@vX.Y.Z`.

---

## Industry context

For curiosity: bigger Go monorepos (opentelemetry-go, etcd, kubernetes) typically use a **PR-based release-prep flow** where a CLI command opens a `release: prepare vX.Y.Z` PR for human review, then a separate command creates the tags. They do this because:

- Many maintainers with cut-release permission → diff review acts as a "did the right person review this" gate
- Larger module sets with cross-module changes that aren't purely mechanical
- Compliance environments that forbid direct-push to main from any source

For zeroid's scale (small maintainer team, mechanical version bumps), the auto-bump-on-publish pattern is cleaner — no CLI ritual, no PR overhead. The trade-off cost (force-moving a tag within 30 seconds of creation, no human review of a literal version-number change) is negligible.

If zeroid outgrows this — multiple maintainers, more nested modules, contributor-driven releases — the PR-based pattern can be added back. Today, this design is right-sized.
