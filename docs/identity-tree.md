# Identities registered by identities

**Decision.** When the embedding service authenticates an admin request as a
registered identity acting as itself, every identity that request registers is
that identity's child. The child records its parent, takes the parent's owner
and, unless the request names its own, the parent's scope ceilings. It can
hold no scope its parent cannot and no higher trust level, and it is
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
				WIMSEURI: claims.Subject, // or IdentityID, or both
			}))
		}
		next.ServeHTTP(w, r)
	})
})
```

"Acting as itself" means the credential is the identity's own: its API key,
client credentials or signed assertion, or an access token issued to it for
itself (its `sub` is the identity, with no `act`, not held for a person). A
token held on someone else's behalf, or a person's session, must not be marked.

- `zeroid.CallerIdentity` names the caller by `IdentityID`, by `WIMSEURI`, or
  by both, which must then agree.
- The caller is looked up in the account and project the request is made in.
  A caller from another account or project is refused with 403, as is one that
  is not `active`, has expired, or has no `owner_user_id`.
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
| `allowed_scopes` | As the request names it, otherwise the caller's |
| `credential_policy_id` | As the request names it, otherwise the caller's policy. Never the tenant default |
| API key from `POST /agents/register` | `created_by` is the inherited owner, the human the key's tokens are attributed to |

The owner is inherited at registration and not kept in step afterwards.

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

So a child that names nothing has exactly its parent's ceiling, and a parent
with no ceiling places none on its children.

A refusal is a `400` whose message names the scope (or the policy that places
no ceiling), for example
`invalid identity field: exceeds the parent identity's scope ceiling: allowed_scopes lists "admin:all"`.

The same rules hold when a child's `allowed_scopes` or `credential_policy_id`
is changed (`PATCH /identities/{id}`), whoever makes the change. An empty
`credential_policy_id` resets a child to its parent's policy rather than the
tenant default.

The check is made when a child's ceiling is written. Narrowing a parent later,
or editing a credential policy that a child uses, does not rewrite its
children; every token is still checked at issuance against its own identity's
layers. Narrow or deactivate the children too. Sub-type and expiry are not
compared with the parent's.

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
- **Attestation.** A verified attestation (`/attestation/verify`) still
  promotes a child by its own evidence, above its parent's level if the proof
  earns it. The cap applies to levels a caller chooses, not to ones a proof
  earns.
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

Each identity below goes through the same deactivation a direct one does: its
API keys are revoked, its credentials are revoked together with the tokens
delegated from them, and a retirement signal is emitted. The revocation events
and the signal carry the reason `parent_deactivated`. The walk passes through
identities that are already deactivated, so an identity reactivated below a
deactivated one is still reached when an identity above them both is
deactivated.

- **Reactivation does not cascade.** Reactivating an identity leaves the
  identities below it deactivated; each is reactivated on its own.
- **Suspension does not cascade.** A suspended identity's own and delegated
  tokens are revoked, as before; the identities it registered keep their
  status. A suspended identity cannot register children.
- **Failures.** If an identity below cannot be deactivated, the request
  answers `500` and says to repeat it. The identity's own deactivation stands,
  and repeating the request (each path is idempotent) finishes the walk.
- **Races.** A child is inserted under a share lock on its parent's row, and
  the walk lists an identity's children only after that identity's
  deactivation has committed, so a registration racing a deactivation is
  either refused or found.

## Reading the tree

- `parent_identity_id` is returned by every identity and agent read:
  `GET /identities/{id}`, `GET /identities`, `GET /agents/registry/{id}`,
  `GET /agents/registry` and both registration responses. It is omitted for an
  identity with no parent.
- `GET /identities?parent_identity_id={id}` and
  `GET /agents/registry?parent_identity_id={id}` list an identity's children.
  The filter must be an identity id; anything else is a `400`.
- `Server.IsRegisteredBy(ctx, identityID, zeroid.CallerIdentity{...}, accountID, projectID)`
  reports whether the named identity is `identityID`'s parent. Only the direct
  parent counts. An embedder uses it to let a calling identity change the
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
There is no foreign key: identities are soft-deleted, and the write path
resolves the parent inside the child's own account and project under a row
lock, which a key on `id` alone could not express.
