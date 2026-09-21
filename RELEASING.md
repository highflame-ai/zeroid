# Releasing ZeroID

ZeroID is published as **four Go modules** from this one repository:

| Module path | Source tree | Tag prefix | Release cadence |
|----|----|----|----|
| `github.com/highflame-ai/zeroid` (the root OAuth/OIDC server library) | `./` | `vX.Y.Z` | Whenever zeroid features/fixes ship |
| `github.com/highflame-ai/zeroid/pkg/authjwt` (token verification for resource servers) | `./pkg/authjwt/` | `pkg/authjwt/vX.Y.Z` | **Lockstep** — same vX.Y.Z |
| `github.com/highflame-ai/zeroid/pkg/dpop` (RFC 9449 DPoP primitive — also consumed by Cerberus, Shield, Firehog directly) | `./pkg/dpop/` | `pkg/dpop/vX.Y.Z` | **Lockstep** — same vX.Y.Z |
| `github.com/highflame-ai/zeroid/pkg/jwks` (remote JWKS fetch/cache/rotate — shared by the server and by pkg/authjwt) | `./pkg/jwks/` | `pkg/jwks/vX.Y.Z` | **Lockstep** — same vX.Y.Z |

**Layering.** `pkg/jwks` is a primitive both sides may import. `pkg/authjwt` is the
verification library resource servers use, and **zeroid's non-test code must never
import it** — that would put a consumer-facing API in the authorization server's
graph. `TestNonTestSourceDoesNotImportAuthjwt` enforces this; RELEASING.md saying so
was not enough last time.

**Every nested module is referenced by a real published tag in `zeroid/go.mod`.** Local `replace` directives do not reach consumers — Go ignores `replace` in dependency modules — so the `require` pins are exactly what the proxy serves.

- **pkg/dpop** — the RFC 9449 DPoP verifier used by `/oauth2/token`, also consumed directly by cerberus, shield and firehog. Lockstep cadence, as of this change: it previously had a decoupled one, and the section below records why that was abandoned.
- **pkg/authjwt** — token verification for resource servers. Consumed directly by cerberus, shield and authn; inside this repo it is now reached **only from tests**, because extracting `pkg/jwks` moved the non-test importers (`server.go`, `internal/service/client_jwks.go`, `internal/service/external_issuer_registry.go`) onto the primitive instead. Lockstep cadence: tagged at every zeroid release.

  **Its pin must stay a real tag anyway**, and the reason matters more than the status: a `require` puts a module in the consumer's graph whether or not any imported package reaches it, so `go get zeroid@vX.Y.Z` resolves this pin regardless. Verified — a fresh module with no `replace` lists all four modules in `go list -m all`. The old `v0.0.0` pin broke consumers during the window when non-test code did import it — but "test-only" was never the property that made a real tag optional, so restoring that status does not make the placeholder safe again. The status itself is now enforced by `TestNonTestSourceDoesNotImportAuthjwt` rather than left to memory, which is what changed since the note below.

> **This section used to describe an asymmetry that no longer exists, and the drift was expensive.** It said pkg/authjwt was imported "only from `tests/integration/`", that Go doesn't follow test imports across module boundaries, and that its version reference was therefore "invisible to downstream consumers and never needs to be a real version" — so it was pinned `v0.0.0`. That was true when written. It stopped being true on **2026-06-19**, when #211 (direct OIDC IdP federation) added `internal/service/external_issuer_registry.go` and the `server.go` option plumbing — both importing pkg/authjwt from non-test code. `internal/service/client_jwks.go` joined later with `private_key_jwt` (#347). Nobody revisited the pin either time.
>
> The effect was that **zeroid could not be resolved from the proxy at all**, for every release from **v1.7.1** onward: `go get github.com/highflame-ai/zeroid@vX.Y.Z` in a fresh module fails with `unknown revision pkg/authjwt/v0.0.0` (verified on both v1.7.1 and v1.9.3). In-repo builds never noticed, because the local `replace` hides it. Only consumers who already pinned pkg/authjwt explicitly (as highflame-authn does) were unaffected.
>
> Two things now make that transition unrepeatable, rather than merely noticed. `TestNonTestSourceDoesNotImportAuthjwt` fails the build if non-test code imports pkg/authjwt at all, and the release check covers every nested module — comparing each pin against the version being released, which is strictly stronger than rejecting `v0.0.0`, since it also catches a pin left at any stale real tag.

---

## How to cut a zeroid release

All modules release in **lockstep**: `zeroid`, `pkg/authjwt`, `pkg/dpop` and `pkg/jwks` carry the
SAME version and are tagged at the SAME commit, every time.

```bash
# 1. Point go.mod at the version you are about to release.
make release-prep VERSION=v1.9.4
#    ...commit + merge that.

# 2. github.com/highflame-ai/zeroid → Releases → "Draft a new release"
#    Choose a tag → "Create new tag: v1.9.4 on publish" → Publish
```

`release.yml` then validates the tag format, runs svu against commit history,
**verifies go.mod's nested-module pins equal the release version**, tags
`pkg/authjwt/vX.Y.Z`, `pkg/dpop/vX.Y.Z` and `pkg/jwks/vX.Y.Z` at the release commit, runs integration
tests, builds goreleaser binaries and pushes the Docker image.

To preview what svu would recommend:

```bash
make next-version
```

### Why lockstep, and what it replaced

Nested modules used to have a **decoupled cadence**: `pkg/dpop` was released on its
own schedule via `release-dpop.yml`, `zeroid/go.mod` pinned whichever version it
last got, and a drift guard at release time checked the pinned tag still matched
`pkg/dpop/` source.

That scheme failed in a way it could not detect, and the failure is the reason for
this section:

- **A release guard runs too late to be a gate.** For a Go module, *pushing the tag
  IS publication.* `release.yml` runs afterwards. v1.9.3 failed the drift guard
  correctly — and shipped anyway: the module tag went live serving a `go.mod` that
  referenced a stale `pkg/dpop`, while `tag-submodules`, goreleaser and the Docker
  build were all skipped. v1.9.3 has zero release assets and no `pkg/authjwt/v1.9.3`
  tag. It cannot be un-published.
- **Nobody used the decoupled cadence as a feature.** Consumers pinned mismatched
  versions and lagged by minors — cerberus on `authjwt v1.7.5`, shield on `v1.8.1`,
  authn on `v1.8.8` with `dpop v1.6.1` — not because they were deliberately holding
  back, but because nothing coordinated them. The independence cost coordination and
  bought nothing measurable.
- **The coordination it required is what stranded a security fix.** The #347
  replay-store namespacing fix sat in `pkg/dpop/` source, unpublished, because the
  release-dpop dance was never run. Every consumer silently resolved the old module.

Lockstep removes the failure mode rather than detecting it: a nested module's tag
points at the commit whose `go.mod` names it, so "go.mod references a stale
submodule" has no representable state. The check in `release.yml` is now a string
comparison that runs **before** any tag is created.

The costs are real but small: version numbers advance without changes, and
`pkg/dpop` made a one-time forward jump from `v1.6.3` to join the shared line.

---

## How nested-module versioning works

`zeroid/go.mod` names the version **about to be released**, not the last one:

```
require (
	github.com/highflame-ai/zeroid/pkg/authjwt v1.9.4
	github.com/highflame-ai/zeroid/pkg/dpop    v1.9.4
	github.com/highflame-ai/zeroid/pkg/jwks    v1.9.4
)
```

At release time `pkg/authjwt/v1.9.4`, `pkg/dpop/v1.9.4` and `pkg/jwks/v1.9.4` are tagged **at the commit
whose go.mod says that**, so the tree is self-consistent: a consumer resolving
`zeroid@v1.9.4` gets exactly the nested-module source that shipped with it.

The chicken-and-egg ("bump go.mod to vX.Y.Z before vX.Y.Z exists") is not a problem,
because a `require` directive is just text until something resolves it — and nothing
resolves it before the tag is created at that same commit. `make release-prep` does
the bump; `release.yml` refuses to release if it was skipped.

### In-repo dev

`go.work` and the `replace` directives make Go use local nested-module source for
in-repo builds regardless of what go.mod names. Iterate freely; only `release-prep`
touches the pins.

**This is also the trap to keep in mind.** Local `replace` directives do NOT reach
consumers — Go ignores `replace` in dependency modules — so in-repo builds pass
against local source while consumers resolve the published tags. Every failure mode
below was invisible in-repo for exactly this reason.

### Why this works

| Concern | How it's handled |
|---------|------------------|
| Source drift (nested-module source not matching its published tag) | **Structurally impossible.** The tag is created at the commit whose go.mod names it, so there is no state where they can disagree. |
| Stale pins (go.mod referencing an old nested version) | Caught by the lockstep check in `release.yml`, which runs **before** any tag is created — unlike the old drift guard, which could only report a bad release after the tag was already published. |
| Placeholder pins (`v0.0.0`) | Cannot occur: the check requires the pin to equal the release version. Previously `pkg/authjwt` sat at `v0.0.0` on the premise it was test-only, which stopped being true at #211 and made every release from v1.7.1 unresolvable. |
| Force-pushing tags | Never needed. All tags are created at the correct commit on the first try. |
| A failed release | Nested-module tags are created *after* validation, so a failed run leaves none behind. The zeroid tag itself is still published by the act of pushing it — see "What if something goes wrong". |

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
| `go.mod pins ... to X, but this release is Y` | You skipped `make release-prep` | `make release-prep VERSION=Y`, merge, then re-publish |
| Both at once: go.mod pins `vA.B.C`, and svu demands `vA.B+1.0` | A `feat:` landed on `main` **after** you ran `release-prep`. The gates now disagree — the pin names the version you prepared, svu names a higher floor — and satisfying one violates the other. | `make release-prep VERSION=<svu's version>`, merge, then publish at that version. To avoid it: run `release-prep` **last**, after the final merge to `main`. Any `feat:` merged in between silently invalidates the pins. |
| The release tag exists but the run failed | **Expected, and not recoverable in place.** Pushing the tag publishes the Go module; the workflow runs afterwards. Cut the next patch version — do not force-push the tag, since the proxy may already have cached it. |

---

## Adding a new nested module

Every nested module joins the **lockstep line** — same version as zeroid, tagged at
the same commit. There is no decoupled option; see "Why lockstep" above for what that
cost us.

To add one (e.g. `pkg/dcr/`):

1. **`go.work`** — add `./pkg/dcr` to the `use (...)` list.
2. **`zeroid/go.mod`** — add `require github.com/highflame-ai/zeroid/pkg/dcr vX.Y.Z`
   at the **current lockstep version**, plus a `replace` for in-repo builds.
3. **`.github/workflows/release.yml`** — add `dcr` to the `for MOD in ...` loops in
   BOTH the lockstep check and the tag-nested-modules step.
4. **`Makefile`** — extend the `release-prep` sed to cover the new module path.
5. **`Dockerfile`** — add `COPY pkg/<new>/go.mod pkg/<new>/go.sum ./pkg/<new>/`
   before `RUN go mod download`. Missing this fails the Docker build outright:
   zeroid's `replace` points at a directory that is not in the build context, and
   the lockstep pin names a tag the proxy has not indexed yet, so there is no
   network fallback. This step was missed when `pkg/jwks` was added and broke both
   `highflame-docker-check` and `highflame-notebook-check`, which builds the same
   image.

> Whether a module is imported from test-only or non-test code makes **no difference**
> to any of this, and deliberately so. `pkg/authjwt` was pinned `v0.0.0` on the
> grounds it was test-only and therefore invisible to consumers. That was true when
> written and silently stopped being true at #211, leaving every release from v1.7.1
> unresolvable from the proxy. A module's test-only status is not a property anyone
> maintains, so the process no longer depends on it.

---

## Industry context

Lockstep versioning across a repo's modules is what **Kubernetes staging repos** and
**OpenTelemetry-Go** do: many modules, one version line, tagged together. The
alternative — independent versioning per module, as `golang.org/x/*` does relative to
Go — works when the modules genuinely evolve on different timescales AND consumers
deliberately pin different combinations.

zeroid tried the independent model and the evidence says it did not fit:

- Consumers never exercised the independence. They pinned whatever they happened to
  get and lagged unevenly — cerberus on `authjwt v1.7.5`, shield on `v1.8.1`, authn
  on `v1.8.8` + `dpop v1.6.1`. No one was deliberately holding a version back.
- The coordination it demanded is what stranded the #347 replay-store fix unpublished,
  and what let `pkg/authjwt` sit at a `v0.0.0` placeholder for three months of
  unresolvable releases.

The trade now:

- **Common case:** one command (`make release-prep`) plus Publish in the UI.
- **Cost:** version numbers advance without changes. Harmless.
- **Foot-gun:** no longer detected, but *structurally absent* — the tag is created at
  the commit whose go.mod names it.

The signal to revisit would be an outside consumer genuinely needing to hold an old
`pkg/dpop` while taking a new zeroid. Nobody does today, and if it happens the answer
is probably a real API break in dpop, which semver already handles.
