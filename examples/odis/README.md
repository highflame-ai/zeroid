# ZeroID as ODIS Layers 1–2

Executable walkthroughs of ZeroID using the vocabulary of the
[ODIS draft](https://github.com/cosai-oasis/ws4-odis/blob/main/RFCs/ODIS.md)
(Open Delegation & Identity Standard, CoSAI/OASIS WS4): Agent Registration
Record → attestation-gated trust → DPoP-bound Agent Runtime Credential →
Delegation Record with monotonic attenuation → compromise-signal cascade
revocation → audit lineage.

Two notebooks, two vantage points:

- **[`odis-walkthrough.ipynb`](./odis-walkthrough.ipynb)** — raw HTTP, the
  wire-format view: what the *authorization server* enforces at issuance
  (policy-gated fail-closed issuance, DPoP holder binding and replay
  rejection, attestation-driven trust promotion, the delegation explorer).
- **[`odis-walkthrough-sdk.ipynb`](./odis-walkthrough-sdk.ipynb)** — the
  Python SDK (`pip install highflame`), adding the *ODIS-aware target* view
  (ODIS §2.5 native mode): local JWKS verification with typed guards
  (`require_scope` / `require_trust` / `is_delegated`), target-side trust
  gating, attenuation's two modes (silent narrowing vs. refusal), and why
  native-mode targets must check revocation state, not just signatures.

Companion to the
[role-capability statement](../../docs/odis/role-capability-statement.md),
which maps every ODIS requirement to code and tests — including the ones
ZeroID does not meet.

## Run it

From the repo root:

```bash
make setup-keys          # ES256 + RSA signing keys into ./keys
docker compose up -d     # zeroid + postgres on localhost:8899
pip install requests pyjwt cryptography jupyter
jupyter notebook examples/odis/odis-walkthrough.ipynb
```

The SDK notebook additionally needs `pip install "highflame==0.3.23"` — the
version its committed outputs were generated against.

## Which configuration each notebook runs under

Both notebooks execute against the stock compose deployment — in particular
`token.require_dpop: false`, the default:

- The raw-HTTP walkthrough **chooses** the default so §5 can show the Bearer
  fallback and the configuration switch that closes it; every DPoP behavior
  (holder binding, replay rejection) is still demonstrated live.
- The SDK walkthrough **requires** the default: the Python SDK (0.3.23) cannot
  construct DPoP proofs yet (highflame-sdk#105), so under `require_dpop: true`
  — the hardened posture the role-capability statement grades L1-09 against —
  its issuance calls are refused with `invalid_dpop_proof`.

The committed outputs contain no credential material: cells print decoded
claims and selected fields, never raw tokens, API keys, or private keys. CI
enforces this with a credential-material lint and re-executes both notebooks
against a fresh server on every PR (`highflame-notebook-check`).

Upgrading a checkout whose postgres volume predates the CIBA grant joining
the default credential policy? Current zeroid heals stored default policies
on startup (migration `044_default_policy_add_ciba_grant`); if you are
running an older build, `docker compose down -v` for a fresh volume.

The notebook is re-runnable: every run registers fresh identities under a
random suffix. The committed outputs are from a real run against a local
instance — if you re-execute, tokens, JTIs, and timings will differ; the
status codes and semantics will not.

## What it demonstrates (and what it deliberately doesn't)

Demonstrated live: fail-closed issuance for unattested identities
(ODIS-L2-14/L1-11), DPoP proof-of-possession with replay rejection
(L1-05/L1-09), three-way scope intersection and refused privilege escalation
at delegation (L2-01/05/06), critical-signal cascade revocation in
milliseconds (L1-12/L3-04/05), and delegation lineage that survives the kill
(CC-01/02).

Not demonstrated, because ZeroID does not implement it: software/supply-chain
attestation, bridge-mode provider adapters, presenter isolation, velocity
limits. The role-capability statement documents those gaps with the same
candor. The local run also uses the dev-stub attestation proof (`image_hash`)
instead of the production OIDC workload verifier, which needs a real issuer
(GitHub Actions / GCP WIF / Kubernetes) — see `docs/attestation.md`.
