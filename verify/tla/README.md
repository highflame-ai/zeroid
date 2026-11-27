# Lock-order model: delegated issuance against cascade revocation

A TLA+ model of how a token exchange that stores a delegated token interleaves,
row lock by row lock, with the three cascade revocations. TLC checks every
order of those steps in a few small delegation trees.

**Property.** Once a revocation commits, no unrevoked token has a revoked token
above it, and no exchange stores a token below one.
**Harm if broken.** A revoked delegation chain keeps a live token for up to its
whole lifetime, and no revocation event is sent for it.

**Property.** Issuance and revocation never wait on each other in a cycle, and
every revocation that starts commits.
**Harm if broken.** PostgreSQL aborts one of them (40P01). An aborted
revocation revokes nothing, and an exchange fails with a 500.

## Run it

```
verify/tla/run.sh                     # every check, about 1 minute on 32 cores
verify/tla/run.sh head-residual-deadlock   # one check, with TLC's trace
```

Needs Java 11+ and `curl`. The script downloads `tla2tools.jar` v1.7.4 into
`~/.cache/zeroid-tla/` and checks its SHA-256 before it runs. Each check's
full TLC output goes to `verify/tla/out/<check>.txt` (not tracked).

Each check states what TLC must report: `pass`, or the invariant it must find
violated. The script fails if any result differs. The checks that are expected
to fail keep proving that each property can fail. If one of them starts to
pass, the model has stopped describing the code it names.

The script runs Java with `-XX:TieredStopAtLevel=1`. The C2 JIT in the Ubuntu
OpenJDK 17.0.21 build crashed inside TLC's evaluator (SIGSEGV), and once gave
a bogus evaluation error.

## Results at d43098e

| Check | Code | Result | Meaning |
|---|---|---|---|
| `head-chain`, `-mutual`, `-return`, `-samedepth` | head | pass | Safety and no deadlock, up to 4 processes at once |
| `head-residual-safety`, `head-inverted-safety` | head | pass | Safety holds in both residual deadlock shapes |
| `head-residual-deadlock` | head | **deadlock** | Residual 1, rows stored by this release (below) |
| `head-inverted-deadlock` | head | **deadlock** | Residual 2, pre-release rows with an inverted `issued_at` (below) |
| `head-*-live` (Chain, Mutual, Return, SameDepth, Residual) | head | pass | Every process finishes, and every revocation commits within 3 attempts |
| `head-inverted-live` | head | a revocation fails | Pre-release rows: see "Liveness" |
| `head-residual-live-nowait` | head, without assumption 6 | a revocation fails | The retry needs its backoff |
| `noretry-residual-live`, `noretry-inverted-live` | head, 1 attempt | a revocation fails | Without the retry, the residuals lose a revocation |
| `round3-mutual`, `round3-return` | 455764f | **deadlock** | The fourth audit's cross-delegation deadlocks |
| `round3-chain` | 455764f | pass | The third audit's fix held for overlapping trees |
| `round2-chain` | e5cb06f | **deadlock** | The third audit's overlapping-cascade deadlock |
| `main-mutual` | origin/main | **deadlock** | Plan-order UPDATEs of two cascades |
| `main-chain-safety` | origin/main | **live token below a revoked one** | The original race, fixed by this PR |
| `no_recheck-chain` | head without the `is_revoked` check under lock | **child stored below a revoked token** | The re-check is necessary |
| `one_snapshot-chain` | head with statement 2 on statement 1's snapshot | **live token below a revoked one** | The fresh snapshot is necessary |

### The counterexamples, in the code's terms

**Residual 1 (head, rows stored by this release).** X's token A → B (Z's,
depth 1) → S (Y's, depth 2). An exchange of A stores C for Y at depth 1, so C
sorts before S.

1. The exchange's `lockLineageSQL` takes A FOR SHARE and inserts C.
2. Y's identity cascade starts statement 1. Its snapshot has S but not C. It
   locks S.
3. The exchange commits C.
4. Y's statement 2 takes a new snapshot that has C, and wants C (depth 1)
   while it already holds S (depth 2).
5. A second cascade over Y's tokens (Y's owner, or X's identity cascade, whose
   tree holds S) starts after C committed. Its statement 1 locks C, then wants
   S. That is a wait cycle, and PostgreSQL aborts one of the two.

C needs to commit only while the other cascade's first statement is running.
That statement does not have to be waiting. `runCascade`'s comment describes
the case where the statement waited. The retry absorbs this deadlock:
`TestCascadeRetryAbsorbsDeadlockOnTokenStoredDuringFirstStatement` builds the
interleaving with X's and Y's identity cascades, sees 40P01 in every trial, and
checks that both cascades then commit with nothing live below a revoked token.

**Residual 2 (head, pre-release rows).** Y's R → X's P → X's Q, with P and Q at
the same depth and Q stored with an earlier `issued_at` than P, which an older
release could write. An exchange of Q locks R, then P (root first), and wants
Q. X's identity cascade locks Q first (it sorts first), then wants P. That is
the case the PR leaves to the retry.

**Round 3 (455764f), the fourth audit.** R1 (X) → M1 (Y), R2 (Y) → M2 (X). X's
cascade locks its anchors R1 and M2. Y's locks R2 and M1. X's statement 2 wants
M1, and Y's wants M2.

**Round 2 (e5cb06f), the third audit.** R (X) → M (Y) → L1, L2. X's UPDATE locks
L1 in plan order while holding R. Y's cascade holds its anchor M and wants L1,
and X wants M.

**Main, the original race.** The exchange checks M as active. The RFC 7009
cascade of M walks M's subtree (without C), revokes and commits. The exchange
then inserts C, live below revoked M.

## What each action is in the code

One action is one indivisible database step: a statement, or one row lock
inside a statement that locks rows in a stated order.

| Action | Code (at d43098e) |
|---|---|
| `IssueCheck` | `checkLineageUsable` → `CredentialLineage`, an unlocked read (`internal/service/credential.go:160`, called at `:821`); `time.Now()` at `:1048`, stored at `:1354`. On main: `IntrospectToken` of the subject (`internal/service/oauth.go:1323` on main) |
| `IssueLockRow` | one row of `lockLineageSQL`, `ORDER BY lineage.depth DESC FOR SHARE OF ic` (`internal/store/postgres/credential.go:83-98`) |
| `IssueFinish` | the `is_revoked` check in `lockUnrevokedLineage` (`credential.go:120-130`), the `issued_at` move (`:56-58`), the INSERT (`:60`) and the commit of `RunInTx` (`:71`) |
| `IssueInsert` | an INSERT with no lock: a token with no parent (`credential.go:66`), or any issuance on main |
| `CascadeStart` | the start of statement 1 of the cascade function: its snapshot, the walk, the sort. `revoke_credential_cascade` in `migrations/073_cascade_revocation_locks_anchor.up.sql:72-92`; `revoke_credentials_cascade` in `074_…up.sql:74-93`; `revoke_credentials_by_owner` in `074_…up.sql:160-184` |
| `CascadeLockRow` | one row lock of statement 1's `PERFORM … ORDER BY delegation_depth, issued_at, id FOR NO KEY UPDATE`, or of statement 2's `locked` CTE (`073:108-116`, `074:107-115`, `074:200-208`) |
| `CascadeStmt2` | the start of statement 2 (`RETURN QUERY`, `073:94`, `074:95`, `074:186`): a new snapshot and a new walk |
| `CascadeCommit` | the UPDATE (`073:117-126`, `074:116-125`, `074:209-218`) and the commit of the autocommit function call |
| `DeadlockAbort` | PostgreSQL's deadlock detector, and `runCascade`'s retry (`credential.go:273-297`, `CascadeRevocationAttempts = 3`) |

The earlier versions are the same actions over the SQL at those commits:
`git show 455764f:migrations/074_bulk_cascade_revocation_locks_anchors.up.sql`
and `git show e5cb06f:…` for round 3 and round 2, and
`migrations/031_cascade_walk_dead_intermediates.up.sql` and
`043_revoke_by_owner_reject_whitespace.up.sql` for main.

The properties: `NoLiveTokenBelowRevoked` is the query `rlLiveBelowRevokedSQL`
in `tests/integration/revoked_lineage_helpers_test.go`. `NoIssuanceBelowRevoked`
is checked at each committed INSERT. `NoDeadlock` says no process is on a cycle
of waits.

## Scenarios and bounds

Each `MC_<shape>.tla` holds a few rows and a pool of processes. TLC tries every
set of 2 to `MaxProcs` processes from the pool (3, or 4 for the four head
scenarios), every order of their steps, and each issuance's clock reading
early or late (`Clock`).

| Scenario | Rows | Pool |
|---|---|---|
| `Chain` | R (X) → M (Y) → L1, L2 (Y); new C (Z) below M | exchange of M, identity X / Y / Z, RFC 7009 of M / R, owner of X and Y |
| `Mutual` | R1 (X) → M1 (Y), R2 (Y) → M2 (X); new C (Z) below M1 | exchange of M1, identity X / Y / Z, RFC 7009 of R1, owner |
| `Return` | R (X) → M (Y) → K (X); new C (Z) below K | exchange of K, identity X / Y / Z, RFC 7009 of M / R, owner of X |
| `SameDepth` | R (Y) → P (X) → Q (X), P and Q at depth 1, Q stored after P; new C (Z) below Q | exchange of Q, identity X / Y / Z, RFC 7009 of P / Q, owner of X |
| `Inverted` | as `SameDepth`, but Q stored with an `issued_at` before P's (a pre-release row) | the same, without identity Z |
| `Residual` | A (X) → B (Z) → S (Y); new C (Y, depth 1) below A | exchange of A, identity X / Y, RFC 7009 of A, owner of Y |

A run of every check explores about a million distinct states in total (17 CPU-minutes).

## Assumptions

1. READ COMMITTED, which is all the code uses. Each statement of a VOLATILE
   plpgsql function takes a new snapshot, and a row committed after a
   statement's snapshot is invisible to that statement.
2. FOR SHARE conflicts with FOR NO KEY UPDATE (which an UPDATE also takes). Two
   FOR SHAREs do not conflict. Locks are held until commit.
3. A statement with `ORDER BY … FOR SHARE/NO KEY UPDATE` locks rows one at a
   time in the sorted order (LockRows runs above the Sort). A locked row that a
   transaction committed while this one waited is rechecked against the WHERE
   on its latest version, and is skipped if it no longer matches, but its lock is
   kept. An UPDATE with no ORDER BY (main, round 2) may lock its rows in any
   order. That is more orders than a real plan produces, so a deadlock the
   model finds there may be one the planner never reaches.
4. A blocked lock waits for every holder that conflicts with it. Who gets a
   freed row is not fixed. PostgreSQL's queue of waiters on one tuple is not
   modeled. Its extra wait edges point at another waiter for the same row, so
   they only shorten cycles the model already has.
5. The deadlock detector aborts any one process on a cycle. PostgreSQL
   normally aborts the one that has waited longest, so the model allows more
   victim choices than the database makes.
6. `BackoffOutlastsWakeup`: a cascade retried after 40P01 starts again only once
   every process that its rollback woke has taken its lock. `runCascade` sleeps
   at least 25 ms first; a woken backend takes its row in microseconds.
7. An INSERT and its COMMIT are one step, and so are a cascade's UPDATE and its
   COMMIT. No other process can tell the difference: the rows are invisible
   until COMMIT, and every row the UPDATE writes is already locked by it.
8. `delegation_depth` and `issued_at` never change after the INSERT, apart from
   the move to parent + 1 µs that `Create` makes before inserting.

## Liveness

`FairSpec` (weak fairness on every step) has only finite behaviors. `Progress`,
a ranking function that every step lowers, is checked on every transition. So
"every process finishes" is the same as TLC finding no stuck state. And "every
revocation commits" is the same as the invariant `NoRevocationFails`. TLC's own
temporal checker re-evaluates the scenario constants in every state. It did
not finish in 10 minutes on 3 processes, or in 90 seconds on 2. The `*-live` checks check these
equivalent forms instead.

With 3 attempts and assumption 6, every revocation commits in every scenario
of rows stored by this release. Two results depend on that:

- Without assumption 6, a retried cascade can re-take its first row before the
  waiter it woke does, and lose 3 times in a row (`head-residual-live-nowait`).
- With pre-release inverted rows, one waiting exchange and two cascades can
  take turns being the victim until a cascade runs out of attempts
  (`head-inverted-live`). This needs PostgreSQL to pick a cascade as the victim
  each time, rather than the exchange that has waited longest (assumption 5).

## Not covered

- Expiry. No token expires, so the `expires_at > p_revoked_at` filters are
  always true.
- Tenancy (`account_id`, `project_id`), the depth bound of 50, and cycles in
  `parent_jti`. Every row is in one tenant, and the trees are small and
  acyclic.
- Whether a deactivated identity can still be issued a token. The identity
  status checks in `IssueCredential` are not modeled.
- Each issuance exchanges a token that is present when the run starts. No
  scenario chains two exchanges made during the run.
- A cascade inside a caller's transaction. `runCascade` does not retry it, and
  the caller's other statements are not modeled.
- REPEATABLE READ or SERIALIZABLE, and errors other than 40P01. The model never
  raises 40001.
- Introspection, verify and token exchange refusing a token below a revoked
  one (the PR's first layer). The model checks the stored rows only.
- The Go code itself. This is a model of the SQL and the transaction steps,
  written by hand. A change to the files below needs a person to update the
  model.

## Coverage record

Last confirmed to describe the code at **d43098e** (branch
`fix/exchange-revocation-race`):

- `internal/store/postgres/credential.go`: `Create`, `lockLineageSQL`,
  `lockUnrevokedLineage`, `runCascade`, `CascadeRevocationAttempts`
- `internal/service/credential.go`: `IssueCredential` (lineage check, `now`)
- `migrations/073_cascade_revocation_locks_anchor.up.sql`
- `migrations/074_bulk_cascade_revocation_locks_anchors.up.sql`

When any of these changes, read the change against the action table above,
update the model if a step, a lock order or a snapshot changed, run
`verify/tla/run.sh`, and only then move the commit above forward. If a check
that should pass fails, translate the trace into the code's terms before you
decide whether the code or the model is wrong. In the trace, the `last` field
of each state names the step and the process.

## CI

The repo has no CI job for this yet, and this change does not add one. One
would run `verify/tla/run.sh` on `ubuntu-latest` with `actions/setup-java`
(Temurin 17), with a path filter on the files in the coverage record and on
`verify/tla/**`. It would cache `~/.cache/zeroid-tla`. It takes about a minute
on 32 cores, and longer on a 4-core runner. Set `MaxProcs` back to 3 there if
that is too slow.
