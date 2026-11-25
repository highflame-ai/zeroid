# Identities registered by identities

**Decision.** When the embedding service authenticates an admin request as a
registered identity acting as itself, every identity that request registers is
that identity's child. The child records its parent, takes the parent's owner
and, unless the request names its own, the parent's scope ceilings, narrowed
to what the token the parent presented holds. It can hold no scope, credential
policy, trust level or lifetime beyond its parent's and that token's, it
receives no token while any identity above it is not active, and it is
deactivated whenever its parent is.
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
| `Scopes` | the verified `scopes` claim | A child, and any identity the request changes, can hold no scope outside them. Empty means the token holds none, so the child could hold none and is refused |
| `APIKeyID` | the verified `api_key_id` claim, set on `api_key`-grant tokens; empty otherwise | Loads the key, which must be an active, unexpired key of the caller in the same tenant (403 otherwise); the child cannot outlive it, and the key's credential policy, when it names one, is the policy the child is held to and inherits |

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
| `allowed_scopes` | As the request names it (every scope in the token, none reserved); otherwise the scopes both the caller's ceiling and its token hold, without reserved scopes. If that is nothing, the registration is refused |
| `credential_policy_id` | As the request names it (a subset of the caller's on every axis); otherwise the caller's effective policy: its presented API key's policy if that names one, else the caller's own policy, which is the tenant default when the caller is on it |
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
([scope-ceilings.md](scope-ceilings.md)). An empty layer restricts nothing.
A child is held inside its parent by comparing those intersections:

- The child's ceiling, in both forms (its own authority, and what it may hold
  for a person), must be within its parent's. A child left with no restricting
  layer under a parent that has one is refused: that is the escape an empty
  layer would otherwise open, a child of a restricted parent placed on a
  policy with no ceiling and then free to request any scope.
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

A refusal is a `400` whose message names the scope (or the policy that places
no ceiling), for example
`invalid identity field: exceeds the parent identity's scope ceiling: allowed_scopes lists "admin:all"`.

The same rules hold when a child's `allowed_scopes` or `credential_policy_id`
is changed (`PATCH /identities/{id}`), whoever makes the change. An empty
`credential_policy_id` resets a child to its parent's policy rather than the
tenant default. A change that leaves the identity no wider than it was (scopes
within the stored ones, and a policy that is the stored one or a subset of it)
is always accepted, so re-sending an unchanged value after a parent was
narrowed is not refused.

A request marked with `WithCallerIdentity` is held to the caller the same way
on every identity it changes, child or not: it cannot widen an identity's
scopes or policy beyond the caller's and its token's, raise its trust level
above the caller's, or set its expiry beyond the caller's bound.

## Credential policy

A named credential policy must be within the caller's effective policy on
every axis, not only scopes: grant types, `max_ttl_seconds`,
`max_delegation_depth`, `required_principal_type`, `required_trust_level`,
`required_attestation` (the full `EnforceSubset` check API keys get), and it
may not expire later than the caller's policy. A violation is a `400` naming
the axis, for example
`invalid identity field: exceeds the parent identity's credential policy: credential policy "wide": ... grant type "client_credentials" permitted by credential policy but not by identity policy`.
Nothing registers under a caller whose own policy is inactive or expired.

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
  parent's. Lowering a child is always allowed, and so is naming the level it
  already holds.
- **Attestation.** A verified attestation (`/attestation/verify`) promotes a
  child no higher than its parent's level. The attestation level is the
  submitter's claim, not something the proof establishes, so a child cannot
  attest its way above its parent.
- Lowering a parent later does not lower its children; lower them too if they
  must follow.

## Deactivation

Deactivating an identity deactivates every identity below it in the tree
(children, their children, and so on, within the same account and project),
whichever path retires it:

- `DELETE /identities/{id}` and `PATCH /identities/{id}` with `status: deactivated`;
- `DELETE /agents/registry/{id}` and `POST /agents/registry/{id}/deactivate`;
- `POST /identities/{id}/expire`, and the sweep that deactivates identities
  past their `expires_at`;
- offboarding an owner (`POST /identities/offboard-by-owner`).

Each identity below gets the same cleanup a direct deactivation does: its API
keys are revoked, its credentials are revoked together with the tokens
delegated from them, and a retirement signal is emitted. The revocation events
and the signal carry the reason `parent_deactivated`.

### No token below a stopped identity

Every token issuance, on every grant, checks the issuing identity's ancestors
when it has a parent: if any of them is not `active` (suspended, deactivated,
expired by status) or is past its `expires_at`, the token is refused as for an
unusable identity. So a tree stops minting the moment its root's status
changes, before and whether or not the walk below reaches every identity, and
suspension, which does not change the children's status, still stops them.

The check is one recursive statement that follows `parent_identity_id` up by
primary key, at most 64 lookups (the hard depth cap) and in practice one per
level; it runs only for identities that have a parent. A chain that does not
end at a root within the cap, or names an identity outside the tenant, refuses.

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
  identities, oldest first;
- repeating the deactivation (`DELETE`, the expire route, a status write, or
  offboarding the owner, which lists marked identities too).

Resuming repeats the identity's cleanup (revocation is idempotent; its
retirement signal may be emitted again) and walks below it. A canceled sweep
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
the walk passes through them.

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
  counts. An embedder uses it to let a calling identity change the
  identities it registered and nothing else:

  ```go
  caller := zeroid.CallerIdentity{WIMSEURI: claims.Subject}
  ok, err := srv.IsRegisteredBy(ctx, targetID, caller, claims.AccountID, claims.ProjectID)
  ```

`parent_identity_id` is unrelated to anything a registrant writes into
`metadata`, such as the `parent_external_id` key the agent registry's
`include_parents` option reads to nest sub-agents for display.

## Schema

`identities.parent_identity_id` is a nullable `UUID` (migration 069), indexed
by `(account_id, project_id, parent_identity_id)` for the rows that have one
(migration 070). Existing identities have no parent; there is no backfill.
`identities.cascade_pending_at` (`TIMESTAMPTZ`, also 069) is the mark; it is
not indexed, since only the hourly worker scans for it, and the identity audit
trigger ignores it.

Rolling back past 069 keeps both columns, so roll back only to a release that
tolerates columns it does not know. A large deployment can build 070's index
out of band first, `CONCURRENTLY` from one session, and check
`pg_index.indisvalid` before deploying (see the migration).
There is no foreign key: identities are soft-deleted, and the write path
resolves the parent inside the child's own account and project under a row
lock, which a key on `id` alone could not express.
