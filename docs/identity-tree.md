# Identities registered by identities

**Decision.** When the embedding service authenticates an admin request as a
registered identity acting as itself, every identity that request registers is
that identity's child. The child records its parent, takes the parent's owner
and, unless the request names its own, the parent's scope ceilings, narrowed
to what the token the parent presented holds. A child whose `allowed_scopes`
is empty holds no scope, so a parent whose token holds none can still
register children. It can hold no scope, credential
policy, trust level or lifetime beyond its parent's and that token's, it
receives no token while any identity above it is not active, no token that
speaks for it is exchanged or reported active while that lasts, and it is
deactivated whenever its parent is. A request authenticated as an identity
changes only that identity's children, and can stop them but never restart
them.
The parent comes only from the authenticated caller, never from the request.

This lets a workload that provisions other workloads (an orchestrator that
registers its sub-agents, a platform that mints an identity per job) do so
without being able to hand out more authority than it holds, and lets one
deactivation retire everything it created.

## Who the caller is

ZeroID's admin routes have no built-in authentication. The embedding service
authenticates each request in its `AdminAuth` middleware, and when the caller
is a registered identity acting as itself it says so:

```go
srv.AdminAuth(func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := verify(r) // your own verification of the caller's credential
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if claims.ActsAsItself() {
			r = r.WithContext(zeroid.WithCallerIdentity(r.Context(), zeroid.CallerIdentity{
				WIMSEURI: claims.Subject,  // or IdentityID, or both
				Scopes:   claims.Scopes,   // the verified scopes claim
				APIKeyID: claims.APIKeyID, // the verified api_key_id claim, if any
			}))
		}
		next.ServeHTTP(w, r)
	})
})
```

"Acting as itself" means the access token is the identity's own, issued to it
for itself (its `sub` is the identity, with no `act`, not held for a person). A
token held on someone else's behalf, or a person's session, must not be marked.

| `CallerIdentity` field | Fill it from | What ZeroID does with it |
|---|---|---|
| `IdentityID` / `WIMSEURI` | `sub` (the WIMSE URI), or the id it names; both must then agree | Resolves the caller in the request's tenant |
| `Scopes` | the verified `scopes` claim | A child, and any identity the request changes, can hold no scope outside them. Empty means the token holds none: a child it registers holds none too (see [Empty means no scope](#empty-means-no-scope)) |
| `APIKeyID` | the verified `api_key_id` claim, set on `api_key`-grant tokens; empty otherwise | Loads the key, which must be an active, unexpired key of the caller in the same tenant (403 otherwise); the child cannot outlive it, and when the key names a credential policy the child is held to that policy as well as the caller's own (see [Credential policy](#credential-policy)) |

Fill nothing else, and never from the request. The token's own `exp` is not a
bound: a child would otherwise expire within the hour.

- The caller, and every identity above it, must be active and unexpired, and
  its credential policy (or its key's) active and unexpired.
- The caller is looked up in the account and project the request is made in.
  A caller from another account or project is refused with 403, as is one that
  is not `active`, has expired, sits below an identity that is not active, is
  on an inactive or expired credential policy, or has no `owner_user_id`.
- `X-User-ID` stays what it was, the actor recorded in the audit trail; it
  never makes a parent. Nor does anything in the body: the registration
  schemas have no `parent_identity_id` field (a request that sends one is
  refused with 422), and `labels` and `metadata` are opaque.
- Without the mark, registration behaves exactly as before.

The routes that register children are `POST /identities` and
`POST /agents/register`. Discovery ingest and the service identity an API key
provisions for a product never record a parent.

## What a child gets

| Field | Value |
|---|---|
| `parent_identity_id` | The caller's id. Written once, at registration |
| `owner_user_id` | The caller's owner. A value in the request is ignored |
| `created_by` | The caller's WIMSE URI: the creation is attributed to the identity that made it. Its id when the URI is longer than the column (255 characters) |
| `trust_level` | As the request names it, which may not be above the caller's; otherwise the registration default (`unverified`), capped at the caller's |
| `allowed_scopes` | As the request names it (every scope in the token, none reserved); otherwise the scopes both the caller's ceiling and its token hold, without reserved scopes. If that is nothing, it is empty, and the child holds no scope |
| `credential_policy_id` | As the request names it (a subset, on every axis, of the caller's own policy and of its presented API key's policy when that names one); otherwise the caller's own policy (the tenant default when the caller is on it) or, when the key names a policy, whichever of the two is within the other. When neither is, the request must name one within both (`400`) |
| `expires_at` | As the request names it, which may not be later than the earliest `expires_at` of the caller, any identity above it, and the presented API key; naming none takes that earliest one (or none, when none is set) |
| API key from `POST /agents/register` | `created_by` is the inherited owner, the human the key's tokens are attributed to |

The owner is inherited at registration and not kept in step afterwards. It
changes afterwards only in a context the embedder marks
`zeroid.WithTrustedOwnerWrite`; any other change to a child's
`owner_user_id`, and any owner change from a request marked with
`WithCallerIdentity` (on any identity, a child or not), is refused with 403.
The owner is who rotations are attributed to and whom four-eyes approvals
exclude, so an identity must not choose it.

## The scope ceiling

A token never carries a scope outside the intersection of its identity's
restricting layers: its `allowed_scopes` and its credential policy's
`allowed_scopes`, or, for a chain acting for a person, the policy's
`user_grant_scopes` in place of its `allowed_scopes`
([scope-ceilings.md](scope-ceilings.md)). An empty layer restricts nothing,
with one exception, below: a child's own `allowed_scopes`. A child is held
inside its parent by comparing those intersections:

- The child's ceiling, in both forms (its own authority, and what it may hold
  for a person), must be within its parent's. A child's own `allowed_scopes`
  always restricts it (see [Empty means no scope](#empty-means-no-scope)), so
  no child is left with no restricting layer, the escape an empty layer would
  otherwise open: a child of a restricted parent placed on a policy with no
  ceiling and then free to request any scope.
- Every scope the request names, on `allowed_scopes` or on a named credential
  policy's `allowed_scopes` or `user_grant_scopes`, must be within the
  parent's ceiling.
- A named credential policy that places no scope ceiling is refused when the
  parent has one. Naming the parent's own policy is the same as inheriting it.
- A layer copied from the parent is checked only through the intersection. It
  is the parent's own, and may list a scope the parent's other layer removes.

- The token the caller presented is one more restricting layer, and one that
  restricts even when empty: the child's ceilings, in both forms, must be
  within its scopes. Reserved scopes (`Server.SetReservedScopes`) never pass
  to a child: they are left out of what it inherits, and naming one is refused.

So a child that names nothing has its parent's ceiling narrowed to the token,
and a parent with no ceiling places none beyond the token's.

### Empty means no scope

On an identity that has a parent, an empty `allowed_scopes` means the
identity holds no scope. It never means no restriction, in any
`token.scope_rules` mode. Identities with no parent are unchanged: their empty
list places no restriction. No identity registered before the tree has a
parent, so no existing row changes meaning.

- **Registration.** A caller whose token holds no scope registers a child
  (`201`) whose `allowed_scopes` is empty. That child registers its own
  children the same way, and they too hold none.
- **Issuance.** Wherever ZeroID applies an identity's `allowed_scopes` as a
  ceiling, a child's empty list admits nothing. A request that names a scope
  is refused as a scope the ceiling does not list is refused: `invalid_scope`
  where the grant computes its scopes (`api_key`, `client_credentials`,
  `jwt_bearer`, token exchange, the CIBA pre-checks), and the issuance
  chokepoint's `insufficient_scope` on the grants that take their scopes from
  a person's grant. A request that names no scope is issued a token with no
  `scopes` claim, instead of the first restricting layer's scopes: the
  credential policy the child inherited lists scopes it does not hold.
- **Delegation.** A child that holds no scope delegates none (its token
  carries none), and as the actor of a token exchange it is delegated none;
  the refusal says the actor identity is not registered for the scopes.
- **API keys.** A key for a child carries only scopes the child lists, so a
  child with an empty list gets keys with no scope; a key naming any is
  refused with `400`. Keys for identities with no parent are created as
  before and checked at issuance.
- **Changes.** Setting a child's `allowed_scopes` to empty narrows it to no
  scope and is accepted, from an admin or from the parent itself. Giving such
  a child a scope again is a widening, held to the rules above.
- **Shadow.** The stricter rules' shadow count judges what issuance did, and
  issuance already applies a child's empty list, so the count never records
  that change as one the rules would make. A refusal is recorded exactly as
  the same refusal of an unlisted scope is (rule D, where its code is not
  `invalid_scope`).
- **Reserved scopes** never pass to a child, whatever its list.

A refusal is a `400` whose message names the scope (or the policy that places
no ceiling), for example
`invalid identity field: exceeds the parent identity's scope ceiling: allowed_scopes lists "admin:all"`.

The same rules hold when a child's `allowed_scopes` or `credential_policy_id`
is changed (`PATCH /identities/{id}`), whoever makes the change. An empty
`credential_policy_id` resets a child to its parent's policy rather than the
tenant default. A change that leaves the identity no wider than it was (scopes
within the stored ones, and a policy that is the stored one or a subset of it)
is always accepted, so re-sending an unchanged value after a parent was
narrowed is not refused. An empty `allowed_scopes` is within any stored list,
so clearing a child's list is always accepted.

A request marked with `WithCallerIdentity` changes only the caller's children
(see [Writes by a calling identity](#writes-by-a-calling-identity)), and is
held to the caller the same way on each: it cannot widen a child's scopes or
policy beyond the caller's and its token's, raise its trust level above the
caller's, or set its expiry beyond the caller's bound.

## Credential policy

A named credential policy must be within the caller's own policy, and within
its presented API key's policy when the key names one, on every axis, not only scopes: grant types, `max_ttl_seconds`,
`max_delegation_depth`, `required_principal_type`, `required_trust_level`,
`required_attestation` (the full `EnforceSubset` check API keys get), and it
may not expire later than the caller's policy. A violation is a `400` naming
the axis, for example
`invalid identity field: exceeds the parent identity's credential policy: credential policy "wide": ... grant type "client_credentials" permitted by credential policy but not by identity policy`.
Nothing registers under a caller whose own policy, or whose key's, is
inactive or expired.

A key's policy was a subset of its identity's when the key was made, but
either can change afterwards. So a child registered through a key is held to
both: naming the key's policy, when it is now wider than the identity's on
some axis, is refused, and a child that names none inherits the narrower of
the two.

The check is made when a child's ceiling is written. Narrowing a parent later,
or editing a credential policy that a child uses, does not rewrite its
children; every token is still checked at issuance against its own identity's
layers. Narrow or deactivate the children too. Sub-type is not compared with
the parent's.

## Trust level

A child is no more trusted than its parent, so an identity cannot use its own
credential to mint identities that policies requiring a higher
`trust_level` would accept. Levels are ordered `unverified` <
`verified_third_party` < `first_party`.

- **Registration.** A `trust_level` above the caller's is refused with `400`,
  for example
  `invalid identity field: exceeds the parent identity's trust level: trust_level "first_party" is above the parent's "verified_third_party"`.
  The caller's level or a lower one is accepted. A request that names none
  gets the registration default, `unverified`, capped at the caller's level.
- **Changes.** `PATCH /identities/{id}` and `PATCH /agents/registry/{id}`
  refuse, the same way, a `trust_level` that would raise a child above its
  parent's, whoever makes the change. Lowering a child is always allowed, and so is naming the level it
  already holds.
- **Attestation.** A verified attestation (`/attestation/verify`) promotes a
  child no higher than its parent's level. The attestation level is the
  submitter's claim, not something the proof establishes, so a child cannot
  attest its way above its parent.
- Lowering a parent later does not lower its children; lower them too if they
  must follow.

## Writes by a calling identity

Every write a request marked with `WithCallerIdentity` makes to an existing
identity (`PATCH /identities/{id}`, `DELETE /identities/{id}`,
`POST /identities/{id}/expire`, `POST /identities/{id}/dismiss`,
`POST /identities/{id}/adopt`, and the agent registry's `PATCH`, `DELETE`,
`activate`, `deactivate` and `rotate-key`) first requires:

- the caller to be resolvable exactly as for a registration: an active,
  unexpired identity in the request's account and project, every identity
  above it active and unexpired, its credential policy active and
  unexpired, and the API key it presented (when `APIKeyID` is set) its own
  active, unexpired key;
- the target to be an identity the caller registered: its direct child. A
  calling identity never writes to itself, its parent, a sibling, a
  grandchild, or any identity it did not register.

Anything else is a `403`. On a child, then:

- **Status goes down, never up.** The caller may suspend an active child and
  deactivate or expire a child, but may not make a child `active` again,
  whether it was suspended or deactivated, by the caller or by anyone else.
  Reactivation is a request that is not marked with `WithCallerIdentity`, so
  a parent cannot undo a stop the deployer made. Since the target is never
  the caller itself, a calling identity never changes its own status either:
  a suspended identity cannot set itself active.
- **No `identity_type` change** (`403`).
- **No owner change** (`403`; see above).
- `allowed_scopes`, `credential_policy_id`, `trust_level` and `expires_at`
  stay within the caller's bound, as for a registration.
- **`expires_at` only moves earlier.** A child that has an expiry stored can
  have it brought forward, never moved later and never cleared (`403`), so a
  parent cannot revive a child whose expiry has passed before the hourly
  sweep ran, or push back an expiry the deployer brought forward. A child
  with no expiry stored can be given any date within the caller's bound.
- `name`, `labels`, `metadata`, the descriptive fields and `sub_type` are
  otherwise the caller's to set on its children.

Offboarding an owner (`POST /identities/offboard-by-owner`) and the discovery
routes (`/identities/discovered`, its batch, prune, release-source and
purge-source) are refused outright with `403` for a marked request.

## Embedder responsibilities

`CallerIdentity` is consulted on the identity and agent registry routes
listed above and nowhere else. The routes that create or revoke API keys,
issue, rotate or revoke credentials, create or edit credential policies,
submit or verify attestations, or ingest signals do not consult it: on those
a marked request is treated as any other admin request. The embedder must not
let an identity's own token reach those routes. Mark only the routes an
identity may use to manage its children, and send everything else through the
embedder's own authorization.

An identity needs no scope to register children: mark its requests whether
or not its token holds any, and fill `Scopes` with what it holds (nothing,
when the token has no `scopes` claim). Its children then hold no scope until
one is listed for them. A resource server reads a token with no `scopes`
claim as holding none.

The embedder must not set `CallerIdentity` on requests from its own internal
services, for example discovery ingest or owner offboarding: a marked request
is refused on those routes (see
[Writes by a calling identity](#writes-by-a-calling-identity)). Mark only the
requests an identity's own token makes.

## Deactivation

Deactivating an identity deactivates every identity below it in the tree
(children, their children, and so on, within the same account and project),
whichever path retires it:

- `DELETE /identities/{id}` and `PATCH /identities/{id}` with `status: deactivated`;
- `DELETE /agents/registry/{id}` and `POST /agents/registry/{id}/deactivate`;
- `POST /identities/{id}/expire`, and the sweep that deactivates identities
  past their `expires_at`;
- offboarding an owner (`POST /identities/offboard-by-owner`);
- a retirement written by a release that predates the tree, which the
  cleanup worker finds (see [Rolling back](#rolling-back)).

Each identity below gets the same cleanup a direct deactivation does: its API
keys are revoked, its credentials are revoked together with the tokens
delegated from them, and a retirement signal is emitted. The revocation events
and the signal carry the reason `parent_deactivated`.

### No token below a stopped identity

A token is not issued, and an issued token is not honoured, while it speaks
for or acts as a stopped identity: one that is not `active` (suspended,
deactivated, expired by status) or is past its `expires_at`, or that sits
below such an identity. So a tree stops the moment its root's status
changes, before and whether or not the walk below reaches every identity, and
suspension, which does not change the children's status, still stops them.

- **Issuance.** Every grant checks the identity the token is issued to (for a
  token exchange, the actor) and its ancestors. A delegated issuance (token
  exchange, the on-behalf exchange, a CIBA step-up into a requesting chain)
  also checks every identity that the parent token, and each token it was
  delegated from, was issued to, which covers the chain's principal and every
  prior actor, and their ancestors. Any stopped identity refuses the
  issuance as for an unusable identity (`400`, `invalid_grant` on the token
  endpoint).
- **Introspection.** A token is reported `active: false` while the identity
  it was issued to, any identity a token it was delegated from was issued to,
  or any identity above one of them is stopped. The same check gates every
  internal use of a presented token (the subject of an exchange, a CIBA
  requesting token, the self-service key route). Suspension pauses: once the
  identities above are active again, a child's unexpired, unrevoked tokens
  are active again. Deactivation revokes them.
- **Cost.** One recursive statement per identity, following
  `parent_identity_id` up by primary key, at most 64 lookups (the hard depth
  cap) and in practice one per level; a delegated token adds one statement
  that follows `parent_jti` up, at most 50 hops (the cascade revocation cap).
  A chain that does not end at a root within the cap, names an identity
  outside its tenant or one that no longer exists, or a delegation chain
  longer than 50, refuses. A delegation lineage longer than 50 links reads
  inactive on introspection for the same reason: it is held to the same cap
  as the revocation walk, so a token the walk could not reach is never
  reported active.
- **What it cannot do.** A token verified locally, from its signature
  alone, is not checked: a resource server that must honour a stop at once
  introspects. And the issuance check reads the chain, then signs: a stop
  that commits between the two lets one token through, issued just after the
  stop. Introspection reports that token inactive, so the window is one
  locally verified token, at most the token's lifetime.

### The walk

The walk goes a level at a time. One conditional `UPDATE … RETURNING`
deactivates every child of the level that is not already deactivated, writing
only its status and the mark below; each identity it returns then gets its
cleanup. Identities already deactivated are passed through, so anything below
them is reached too, and each identity is visited once per run (offboarding
an owner whose identities registered each other walks each subtree once).
Because the `UPDATE` is conditional, two walks that overlap never clean an
identity twice, and a whole-row update that read an identity before the walk
deactivated it is refused (`409`) rather than writing its old status back.

The walk is not tied to the request: a client that disconnects does not stop
it. Its cost is one `UPDATE` and one `SELECT` per level plus each deactivated
identity's cleanup (about a millisecond per identity on a local database), so
deactivating the root of a very large tree takes a request proportionally
long. The tree has stopped minting from the first statement either way.

### The mark, and resuming

`cascade_pending_at` is set in the same `UPDATE` that retires an identity, and
on each identity the walk deactivates. It is cleared on an identity once its
own cleanup succeeded, and on the root once the walk below it finished. An
identity still marked has unfinished work, which these resume:

- the cleanup worker, on every pass (hourly), resumes up to 500 marked
  identities, oldest mark first, read through a partial index on the mark;
- repeating the deactivation (`DELETE`, the expire route, a status write, or
  offboarding the owner, which lists marked identities too).

A resume that fails (the walk errs, or the identity's own cleanup does)
moves the mark to the time of the attempt, so a mark that keeps failing goes
to the back of the queue and cannot keep newer ones out of the batch. Two
alerts cover it: the oldest mark older than two passes means the backlog is
larger than a batch; any mark present for several passes in a row means a
resume keeps failing, and the worker's error log names the identity:

```sql
SELECT count(*), min(cascade_pending_at) FROM identities WHERE cascade_pending_at IS NOT NULL;
```

Resuming repeats the identity's cleanup (revocation is idempotent; its
retirement signal may be emitted again, with the reason it was retired with:
`expired` for an identity past its `expires_at`) and walks below it. A canceled sweep
stops between levels and leaves the mark for the next pass. If a step fails,
the request answers `500` and says to repeat it; the deactivation itself
stands. An identity cannot be reactivated while it is marked (`409`).

- **Reactivation does not cascade.** Reactivating an identity leaves the
  identities below it deactivated; each is reactivated on its own, and only
  while every identity above it is active and unexpired (`409` otherwise). The
  ancestors are locked for that write, so it cannot race a deactivation above.
- **Suspension does not change the children's status**, but they receive no
  token while it lasts (above). A suspended identity cannot register children.
- **Races.** A child is inserted under a lock on its parent (`FOR NO KEY
  UPDATE`) and every identity above it (`FOR SHARE`), all of which must be
  active and unexpired, and the walk lists an identity's children only after
  that identity's deactivation has committed, so a registration racing a
  deactivation anywhere above is either refused or found.

## Limits

| Setting | Default | Meaning |
|---|---|---|
| `identity_tree.max_depth` | 8 | The most identities above any identity (an identity an admin registers is at depth 0). At most 64 |
| `identity_tree.max_children` | 1000 | The most children, not deactivated, one identity may have |

A registration beyond either is refused with `409`, for example
`identity tree limit reached: the parent identity has as many children as allowed: it has 1000 that are not deactivated; the limit is 1000`.
Both are checked under the parent's lock, so concurrent registrations cannot
overrun them. Deactivated children do not count, but they stay in the tree and
the walk passes through them. Reactivating a deactivated child counts it
again, so it is checked against `max_children` under the same lock and
refused with the same `409` when the parent is full.

## Reading the tree

- `parent_identity_id` is returned by every identity and agent read:
  `GET /identities/{id}`, `GET /identities`, `GET /agents/registry/{id}`,
  `GET /agents/registry` and both registration responses. It is omitted for an
  identity with no parent.
- `GET /identities?parent_identity_id={id}` and
  `GET /agents/registry?parent_identity_id={id}` list an identity's children.
  The filter must be an identity id; anything else is a `400`.
- `Server.IsRegisteredBy(ctx, identityID, zeroid.CallerIdentity{...}, accountID, projectID)`
  reports whether the named identity is `identityID`'s parent and that parent,
  and every identity above it, is active and unexpired. Only the direct parent
  counts. ZeroID applies this rule itself on the routes listed under
  [Writes by a calling identity](#writes-by-a-calling-identity); an embedder
  uses it to apply the same rule on its own routes:

  ```go
  caller := zeroid.CallerIdentity{WIMSEURI: claims.Subject}
  ok, err := srv.IsRegisteredBy(ctx, targetID, caller, claims.AccountID, claims.ProjectID)
  ```

`parent_identity_id` is unrelated to anything a registrant writes into
`metadata`, such as the `parent_external_id` key the agent registry's
`include_parents` option reads to nest sub-agents for display.

## Schema

`identities.parent_identity_id` is a nullable `UUID` (migration 071), indexed
by `(account_id, project_id, parent_identity_id)` for the rows that have one
(migration 072). Existing identities have no parent; there is no backfill.
`identities.cascade_pending_at` (`TIMESTAMPTZ`, also 071) is the mark, with a
partial index on the rows that carry it (072), so the hourly pass reads the
index, not the table; the identity audit trigger ignores it.
There is no foreign key: identities are soft-deleted, and the write path
resolves the parent inside the child's own account and project under a row
lock, which a key on `id` alone could not express.

### Large tables

072 builds both indexes inside the migration runner's transaction, which
holds writes to `identities` for two table scans. The runner applies each file
as one transaction, so it cannot build them `CONCURRENTLY`. On a large table,
apply 071 and 072 by hand first:

1. Run, on every pod, a release that tolerates columns it does not know
   (v1.31.0 or later).
2. From one session, add the columns, retrying on a lock timeout:

   ```sql
   SET lock_timeout = '3s';
   ALTER TABLE identities
       ADD COLUMN IF NOT EXISTS parent_identity_id UUID,
       ADD COLUMN IF NOT EXISTS cascade_pending_at TIMESTAMPTZ;
   ```

3. Build both indexes, each statement on its own (outside a transaction),
   with 072's definitions:

   ```sql
   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_parent
       ON identities (account_id, project_id, parent_identity_id)
       WHERE parent_identity_id IS NOT NULL;
   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_cascade_pending
       ON identities (cascade_pending_at)
       WHERE cascade_pending_at IS NOT NULL;
   ```

   and check both are valid:

   ```sql
   SELECT c.relname, i.indisvalid FROM pg_index i
   JOIN pg_class c ON c.oid = i.indexrelid
   WHERE c.relname IN ('idx_identities_parent', 'idx_identities_cascade_pending');
   ```

   Drop an invalid one (`DROP INDEX CONCURRENTLY <name>`) and build it again:
   `IF NOT EXISTS` would skip it.
4. Deploy the release with the tree. 071 then only swaps the audit trigger
   (catalog-only), and 072 finds both indexes.

### Rolling back

Rolling back past 071 keeps both columns, so roll back only to a release that
tolerates columns it does not know (v1.31.0 or later).

A release from before [Empty means no scope](#empty-means-no-scope) reads a
child's empty `allowed_scopes` as no restriction, so a child registered with
none would be issued any scope its policy allows. Finish rolling out a
release with the rule before any identity registers children with a
scopeless token, and before rolling back to a release without it, find such
children and deactivate them or list their scopes:

```sql
SELECT id, account_id, project_id FROM identities
WHERE parent_identity_id IS NOT NULL
  AND COALESCE(cardinality(allowed_scopes), 0) = 0
  AND status <> 'deactivated';
```

A release without the tree, whether the rollback target or an old pod still
serving during a rollout, deactivates one identity and sets no mark, so
nothing walks the identities below it. The cleanup worker covers this: on
every pass, before resuming marks, it marks up to 500 retired (deactivated
or expired) identities that still have a child that is not deactivated, and
the resume then walks them. To mark all of them at once instead of over
passes, run the same repair by hand once the release with the tree is
deployed; the next pass, or repeating each deactivation, walks them:

```sql
UPDATE identities p SET cascade_pending_at = now()
WHERE p.status IN ('deactivated', 'expired')
  AND p.cascade_pending_at IS NULL
  AND EXISTS (
      SELECT 1 FROM identities c
      WHERE c.account_id = p.account_id
        AND c.project_id = p.project_id
        AND c.parent_identity_id = p.id
        AND c.status <> 'deactivated');
```

Until the walk reaches them, the identities below a retired one receive no
token and have none reported active on any request a release with the tree
serves (see [No token below a stopped identity](#no-token-below-a-stopped-identity)).
