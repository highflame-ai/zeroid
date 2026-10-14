# Trusted issuers

ZeroID accepts tokens from a customer's IdP on two person grants: an ID-JAG redeemed with `jwt-bearer` (P1b) and an OpenID Connect ID token exchanged with RFC 8693 (P1c).
The IdP has to be a **trusted issuer**.
This page is the reference for how trusted issuers are stored, how the two grants use them, and the admin API that manages them.
The design is highflame-architecture ADR 0042 (D3a, D4, D4a, D5, D5a, D6, D7); the capability is CAP-IDN-028 and the invariant INV-IDN-014.

## Two stores

`federation.issuer_store` chooses where trusted issuers come from.

| Value | Source | Tenant on the grants | For |
|---|---|---|---|
| `config` (default) | The static `external_issuers` list | ID-token exchange: the caller's `account_id`/`project_id`, inside the entry's `allowed_accounts`. ID-JAG: the authenticated client's linked identity, inside `allowed_accounts` | Standalone ZeroID |
| `db` | Per-account rows, managed through the admin API below | Derived from the issuer row and the agent's binding; a caller-supplied tenant must match | SaaS (AuthN) |

ZeroID refuses to start with `issuer_store: db` and a non-empty `external_issuers`, so trust never comes from two lists.

```yaml
federation:
  issuer_store: db                 # Env: ZEROID_FEDERATION_ISSUER_STORE
  allow_private_endpoints: false   # Env: ZEROID_FEDERATION_ALLOW_PRIVATE_ENDPOINTS
  shared_issuers: []               # empty = the built-in list below
```

`allow_private_endpoints` relaxes the SSRF guard on issuer rows' JWKS fetches and admits `http` issuer and JWKS URLs.
It exists for local development against `cmd/zeroid-mockidp` and is a deployment setting, never a row field.
Production keeps it false.
Static entries keep their own `allow_private_endpoints`.

## Issuer rows

A row (`external_issuers`, migration 056) belongs to one account and holds:

| Field | Meaning |
|---|---|
| `issuer` | The `iss` tokens carry, matched exactly. https. |
| `kind` | `person`: an IdP whose ID-JAGs and ID tokens name people. `workload`: a client-assertion issuer (P2, not yet accepted by any grant). |
| `jwks_uri` | https. Fetched through the SSRF-guarded client. |
| `audiences` | Optional on a `person` row, required on a `workload` row. Extra accepted `aud` values. On the ID-token exchange an enabled binding already makes the presenting client's `client_id` an accepted audience, so an agent's app id is written once, as the binding's subject key; an ID-JAG's `aud` must be ZeroID's issuer whatever this lists. |
| `algorithms` | A subset of RS256, ES256, PS256. |
| `claim_mapping` | ZeroID name to token claim. `user_id` is the person's **user key** (Entra `oid`, Okta `sub`) and is required on a person row. Also `email`, `email_verified` (Entra `xms_edov`), `name`, `role`, `privilege_scope`, `scope`, `trust_level`. |
| `propagate_claims` | A subset of `auth_time`, `acr`, `amr`. |
| `claim_constraints` | Claim to accepted values. Every listed claim must be present and equal one of its values (for an array claim, contain one). Required on a shared issuer. |
| `max_token_age_seconds` | 1 to 3600, default 600. |
| `jwks_cache_ttl_seconds` | 30 to 86400, default 300. |
| `source`, `source_ref` | `admin`, or `connector` with the connector that created the row. |
| `enabled` | A disabled row refuses every token at the next request. |

### Who may hold an issuer

- An issuer unique to one customer (an Entra tenant, an Okta org, an AWS account's STS issuer, a cluster, a SPIFFE trust domain) is trusted by **one account at most**, whatever its claim constraints.
- Only an issuer on the platform's shared list may appear in several accounts, and only with claim constraints that pin it to the customer.
  Two rows of the same kind with the same constraints are refused.
- An issuer has at most one row per kind in its account, so an Entra tenant can be both the account's `person` issuer and its `workload` issuer.

Writers check these rules under a per-issuer Postgres advisory lock, backed by a unique index on `(issuer, kind, constraints_key)`; `constraints_key` is empty for a customer-unique issuer and a hash of the constraints for a shared one.
The built-in shared list is `https://accounts.google.com`, `https://token.actions.githubusercontent.com`, Entra's `common`, `organizations` and `consumers` v2.0 endpoints, and the Microsoft consumer tenant `9188040d-6c67-4c5b-b112-36a304b66dad`.
`federation.shared_issuers` replaces it.

A person row refuses a templated issuer (`{tenantid}`) and Entra's multi-tenant endpoints, which name no single tenant.

### Presets

`preset` fills only the fields the request leaves unset.

| Preset | Issuer | Fills |
|---|---|---|
| `entra` | `https://login.microsoftonline.com/<tenant-guid>/v2.0` | `jwks_uri` `.../<tid>/discovery/v2.0/keys`, `algorithms` RS256, `claim_mapping` `user_id: oid`, `email`, `email_verified: xms_edov`, `name`, and the constraint `tid: [<tid>]` |
| `okta` | `https://<org>.okta.com` or `.../oauth2/<server-id>` | `jwks_uri` (`/oauth2/v1/keys` or `/v1/keys`), `algorithms` RS256, `claim_mapping` `user_id: sub`, `email`, `email_verified`, `name` |
| `generic` or absent | any | nothing |

The user key is `oid` for Entra because Entra's `sub` is pairwise per application, so one person would carry a different `sub` in every agent's app.
For `email_verified` on Entra, ask the customer to emit the optional claims `email` and `xms_edov`.

### Read live

On every federated grant ZeroID reads the issuer's rows with one indexed query and caches no row, so a disable or delete applies at the next request on every replica.
Only JWKS clients are cached: keyed by `(row id, jwks_uri, updated_at)`, so an edited row never verifies with its old keys; created on first use; closed after 30 idle minutes; capped at 20 per account and 1000 in total.
Tokens already issued under a deleted row live out their 15 minutes; bulk revocation on delete is ADR 0042 open question 6.

## Bindings

A binding (`external_issuer_bindings`) maps `(issuer row, subject key)` to one identity in the row's account (ADR 0042 D6).
The subject key is the value the credential carries at runtime:

| Grant | Subject key |
|---|---|
| ID-JAG (P1b) | `act.sub`, the agent's client id at the IdP |
| ID-token exchange (P1c) | the presenting client's `client_id`, which is the ID token's `aud` |

At most one **enabled** binding may exist per `(issuer row, subject key)`.
A binding for an identity that is not `active` is created disabled, and enabling one requires the identity to be active, so a discovered agent's binding turns on at adoption.

## The person grants with issuer rows

Both grants resolve the issuer first: the token's `iss` must have an **enabled `person`** row whose claim constraints the token satisfies.
An unknown issuer is `invalid_request` on the ID-token exchange and `invalid_grant` on ID-JAG, as before; a workload, disabled or unmatched row is `invalid_grant`.
The token's `aud` must name an accepted audience: on the ID-token exchange the presenting client's `client_id` when an enabled binding on the row has it as subject key, on ID-JAG ZeroID's issuer, and on both any value in the row's `audiences`.

### P1c: the ID-token exchange

```
POST /oauth2/token
  grant_type         = urn:ietf:params:oauth:grant-type:token-exchange
  subject_token      = <the person's ID token>
  subject_token_type = urn:ietf:params:oauth:token-type:id_token
  client_id          = <the agent's app id at the IdP>
  client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer
  client_assertion   = <private_key_jwt>
  resource           = <optional; audience-restricts the token>
  scope              = <optional>
```

All of these must hold (ADR 0042 D3a), or the exchange is refused with `invalid_grant` (`invalid_client` for client authentication):

1. The client authenticates with `private_key_jwt`; a client secret is `invalid_client`, on static issuers too.
   Its `client_id` is in the ID token's `aud`; `azp`, when present, equals it; several audiences without `azp` are refused.
   The `aud` is accepted because an enabled binding on the row has the `client_id` as subject key (the binding is the audience rule), or because it is in the row's `audiences`.
2. The subject token is positively an ID token: it carries `iss`, `sub`, `aud`, `exp` and `iat`, and no access-token marker (`scp`, `scope`, or a `typ` of `at+jwt` or `application/at+jwt`).
3. The issuer row is `person`, and the subject is not a workload: no Entra `idtyp=app`, no `system:serviceaccount:` subject, no SPIFFE ID.
4. An enabled binding maps the client's `client_id` under the row to an identity, which is the agent.
   If the client's registration links an identity, it must be that one.
   The account is the row's and the project is the agent's; a request's `account_id`, `project_id` or `application_id` must match.
5. The person resolver finds the person in the account (below).
6. The agent is `active` (D7).

The token's `sub` is the person's user id with `user_id_iss` ZeroID's issuer, the IdP's pair is in `idp_iss` and `idp_sub`, `principal_type` is `user`, the agent is the current actor in `act`, `client_id` is the presenting client, and `resource` audience-restricts it.

### P1b: ID-JAG

The request is unchanged ([identity-model.md](identity-model.md#enterprise-managed-authorization-id-jag)).
Its `aud` must name ZeroID's issuer (draft §4.3); the row's `audiences` play no part.
With issuer rows the agent is the ID-JAG's `act.sub` mapped through an enabled binding, not the client's linked identity or `application_id`, and there is no synthetic identity.
A registered client linked to a different identity is refused, and a CIMD client gets its tenant from the binding.
The subject must not be a workload, and checks 4 to 6 above apply.
Every check, including person resolution, runs before the ID-JAG's `jti` is consumed, after the replay check, so a refused request leaves the grant redeemable.

### Refusals that are events

- **Unmatched agent** (ADR 0027): no `act.sub`, no enabled binding, a binding to no identity in the account, or a client linked to a different identity.
  Logged as `federation_unmatched_agent` (account, issuer, subject key, grant, reason) and counted in `zeroid.federation.unmatched_agent{account_id, grant_type, reason}`.
- **Agent not adopted** (D7): the error names the state (`agent identity is discovered; ...`); logged as `federation_agent_not_adopted` and counted in `zeroid.federation.agent_not_adopted{account_id, grant_type, status}`, the adoption queue's demand.

ZeroID has no event bus; an embedder that needs ADR 0027 findings reads these.

## Person resolution

```go
srv.SetFederatedPersonResolver(func(ctx context.Context, r zeroid.FederatedPersonRequest) (string, error) {
	// r.GrantType        zeroid.PersonGrantIDJAG or zeroid.PersonGrantExternalIDToken
	// r.AccountID, r.ProjectID   the tenant the token is minted into
	// r.Issuer, r.Subject        the IdP and the person's user key (claim_mapping.user_id)
	// r.Email, r.EmailVerified   the mapped email, and whether the IdP asserted it verified
	// r.ClientID, r.AgentIdentityID
	return highflameUserID, nil // or zeroid.ErrPersonNotMember
})
```

- The returned id becomes the token's `sub`.
  `user_id_iss` keeps meaning "the issuer of `sub`", so it becomes ZeroID's own issuer, as on `authorization_code` and the external-principal exchange (under the `rfc8693` profile; the legacy profile emits no `user_id_iss` for such a `sub`).
  The IdP's pair travels together in the reserved claims `idp_iss` (the IdP's issuer) and `idp_sub` (the user key).
  All three are written after caller-supplied claims, so no caller can set them.
- `ErrPersonNotMember` is `invalid_grant` ("the person is not a member of this organization").
- Any other error, an empty id or a panic is `server_error` with a fixed message; the cause is logged, never returned.
  Each call is bounded at 5 seconds.
- With issuer rows a resolver is required: without one the grants answer `server_error` ("person resolution is not configured").
  With static issuers and no resolver, `sub` stays the IdP subject, `user_id_iss` is the IdP's issuer, and there is no `idp_iss` or `idp_sub`.

The person-grant ceiling ([scope-ceilings.md](scope-ceilings.md#a-persons-ceiling)) then sees the resolved user id.

When the agent exchanges the person token (RFC 8693, `actor_token` = its own assertion) to narrow it, it is already the token's current actor, so under the `rfc8693` profile the child keeps `act` = the agent with no extra nesting and no added `delegation_depth`.
The legacy profile is frozen (ADR 0043 D1): there the exchange delegates as before, adding a level.
`idp_iss` and `idp_sub` travel with `sub` onto every exchanged `rfc8693` token; a different agent becomes a new actor level as usual.

## Admin API

The routes are on the admin router (`server.admin_path_prefix`), behind the deployer's admin authentication.
The account is always the caller's tenant: `TenantContextMiddleware` reads `X-Account-ID` and `X-Project-ID` (both required; the project is not used for issuer rows).
`X-User-ID` names the actor, recorded as `created_by`/`updated_by` and in `identity_audit_logs`.
Another account's rows answer 404.
In AuthN these routes are reached only through Admin, which checks the org role and forwards with its verified tenant (ADR 0042 D4a).

### Errors

Every refusal is an RFC 9457 problem with a stable `code`:

```json
{"status": 409, "title": "Conflict", "detail": "this issuer is already trusted and cannot be added again", "code": "issuer_already_trusted"}
```

| Status | `code` | When |
|---|---|---|
| 400 | `invalid_issuer` | Not an absolute https URL (http only with `allow_private_endpoints`), templated, an Entra multi-tenant endpoint on a person row, or not the shape a preset requires |
| 400 | `invalid_jwks_uri` | Not an absolute https URL |
| 400 | `invalid_identity_id`, `invalid_kind`, `invalid_audiences` (a workload row with none), `invalid_algorithms`, `invalid_claim_mapping`, `invalid_claim_constraints`, `invalid_propagate_claims`, `invalid_max_token_age`, `invalid_jwks_cache_ttl`, `invalid_source`, `invalid_preset`, `invalid_request`, `invalid_subject_key` | The named field is invalid |
| 401 | `unauthorized` | No tenant context |
| 404 | `not_found` | No such row or binding in this account |
| 409 | `issuer_already_trusted` | The issuer is trusted by another account, or this account has a row of this kind (and constraints) already. Never names the other account |
| 409 | `issuer_limit_reached` | The account has 20 issuers |
| 409 | `issuer_store_config` | Any route but the list and `/check` on a `config`-mode server |
| 409 | `binding_conflict` | Another enabled binding maps this subject key under this issuer |
| 409 | `binding_exists` | The same (issuer, subject key, identity) binding exists |
| 409 | `identity_not_active` | Enabling a binding for an identity that is not active |
| 409 | `client_conflict` | The requested OAuth client exists and is not this identity's `private_key_jwt` client |
| 422 | `jwks_unreachable` | The JWKS could not be fetched (no upstream detail is returned) |
| 422 | `jwks_empty` | The JWKS has no RSA or EC signing key |
| 422 | `jwks_private_address` | The JWKS host resolves to a private or reserved address |
| 422 | `shared_issuer_requires_constraints` | A shared issuer without `claim_constraints` |
| 422 | `identity_not_found` | `identity_id` names no identity in this account |
| 422 | `identity_has_no_public_key` | `oauth_client` was requested but the identity has no EC P-256 key |
| 500 | `internal_error` | Anything else |

A malformed body (wrong type, unknown field, missing `kind`/`issuer`) is huma's own 422 `application/problem+json` with `errors[]` and no `code`.

### `GET /external-issuers`

```json
{
  "issuer_store": "db",
  "items": [ <issuer>, ... ]
}
```

On a `config` server the items are the static entries that admit the account, with `source: "config"` and an empty `id`; they are read-only.

### `POST /external-issuers` → 201

```json
{
  "preset": "entra",
  "kind": "person",
  "issuer": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
  "display_name": "Contoso Entra",
  "audiences": [],
  "jwks_uri": "optional with a preset",
  "algorithms": ["RS256"],
  "claim_mapping": {"user_id": "oid", "email": "email", "email_verified": "xms_edov", "name": "name"},
  "propagate_claims": ["auth_time"],
  "claim_constraints": {"tid": ["11111111-2222-3333-4444-555555555555"]},
  "max_token_age_seconds": 600,
  "jwks_cache_ttl_seconds": 300,
  "source": "admin",
  "source_ref": "",
  "enabled": true
}
```

Only `kind` and `issuer` are always required; `jwks_uri` and `claim_mapping.user_id` (person) are required unless a preset fills them, and `audiences` is required on a workload row.
A person row needs no audiences: add each agent with a binding (below), whose subject key is its app id.
The JWKS is fetched before the row is written, and an unreachable or empty one is refused (422).
The response is the issuer:

```json
{
  "id": "6f1d...",
  "account_id": "acct_123",
  "issuer": "https://login.microsoftonline.com/1111.../v2.0",
  "kind": "person",
  "display_name": "Contoso Entra",
  "jwks_uri": "https://login.microsoftonline.com/1111.../discovery/v2.0/keys",
  "audiences": [],
  "algorithms": ["RS256"],
  "claim_mapping": {"user_id": "oid", "email": "email", "email_verified": "xms_edov", "name": "name"},
  "propagate_claims": [],
  "claim_constraints": {"tid": ["1111..."]},
  "max_token_age_seconds": 600,
  "jwks_cache_ttl_seconds": 300,
  "source": "admin",
  "source_ref": "",
  "enabled": true,
  "created_by": "user_abc",
  "updated_by": "user_abc",
  "created_at": "2026-10-15T10:00:00Z",
  "updated_at": "2026-10-15T10:00:00Z",
  "jwks_check": {"reachable": true, "key_count": 2, "kids": ["k1", "k2"], "checked_at": "2026-10-15T10:00:00Z"}
}
```

### `GET /external-issuers/{id}` → 200

The issuer, without `jwks_check`.

### `PATCH /external-issuers/{id}` → 200

Any of `display_name`, `jwks_uri`, `audiences`, `algorithms`, `claim_mapping`, `propagate_claims`, `claim_constraints`, `max_token_age_seconds`, `jwks_cache_ttl_seconds`, `enabled`; absent fields are unchanged.
`issuer`, `kind` and `source` never change (an unknown field is a 422); delete and re-create instead.
A changed `jwks_uri` is probed first and the response carries `jwks_check`.
The whole row is re-validated, and constraint changes on a shared issuer are re-checked for uniqueness.

### `DELETE /external-issuers/{id}` → 204

Deletes the row and its bindings.

### `POST /external-issuers/check` → 200

```json
{"jwks_uri": "https://.../keys"}
```

or `{"issuer": "...", "preset": "entra"}` to probe the URI a preset would derive.
The answer is a probe result, never an upstream body:

```json
{"reachable": true, "key_count": 1, "kids": ["k1"], "checked_at": "..."}
{"reachable": false, "key_count": 0, "kids": [], "error": "jwks_unreachable", "checked_at": "..."}
```

`error` is `jwks_unreachable`, `jwks_empty` or `jwks_private_address`.
Only an invalid URL is a 400.

### `GET /external-issuers/bindings` → 200

The account's bindings across all its issuers, in one query.
`?identity_id=<uuid>` returns only that identity's, which is how to answer "which credentials map to this agent" without walking every issuer.

```json
{"items": [ <binding>, ... ]}
```

A malformed `identity_id` is 400 `invalid_identity_id`; on a `config` server the route answers `issuer_store_config`.

### `GET /external-issuers/{id}/bindings` → 200

One issuer's bindings; takes the same `?identity_id=` filter.

```json
{"items": [ <binding>, ... ]}
```

### `POST /external-issuers/{id}/bindings` → 201

```json
{
  "subject_key": "<agent app id, or the ID-JAG act.sub>",
  "identity_id": "<agent identity uuid in this account>",
  "enabled": true,
  "oauth_client": {"client_id": "optional, defaults to subject_key"}
}
```

`oauth_client` also creates the OAuth client the agent presents on P1b/P1c, unless it exists already linked to this identity with `private_key_jwt`:
`client_id` as given, `token_endpoint_auth_method: private_key_jwt`, `jwks` built from the identity's registered EC P-256 public key (kid = the identity id), grant types `token-exchange` and `jwt-bearer`, and `identity_id` = the agent.
It is created in the same transaction as the binding.
On P1c the client id is the subject key; on Okta P1b the ID-JAG's `client_id` claim must equal the authenticated client, so set `client_id` to that value when it differs from `act.sub`.

```json
{
  "id": "b7c2...",
  "account_id": "acct_123",
  "issuer_id": "6f1d...",
  "subject_key": "<agent app id>",
  "identity_id": "9a0e...",
  "enabled": true,
  "created_by": "user_abc",
  "updated_by": "user_abc",
  "created_at": "...",
  "updated_at": "...",
  "oauth_client": {"client_id": "<agent app id>", "created": true}
}
```

`enabled` is `false` in the response when the identity is not active.

### `GET /external-issuers/{id}/bindings/{binding_id}` → 200

### `PATCH /external-issuers/{id}/bindings/{binding_id}` → 200

```json
{"enabled": true}
```

### `DELETE /external-issuers/{id}/bindings/{binding_id}` → 204

## Migration ordering

The tables are migration 056.
Migration 055 (the refresh-token family, PRs #421 to #423) must be applied before it: golang-migrate never applies a version below the database's current one, so a database that reached 056 first would silently skip 055.
If this change merges before 055, renumber it at merge.

## Audit

Every insert, update and delete of a row or binding writes `identity_audit_logs` (`table_name` `external_issuers` or `external_issuer_bindings`, actions `INSERT_EXTERNAL_ISSUER`, `UPDATE_EXTERNAL_ISSUER`, `DELETE_EXTERNAL_ISSUER`, `INSERT_ISSUER_BINDING`, ...), with the actor from `X-User-ID` and the binding's identity as `identity_id`.

## Running it locally

`cmd/zeroid-mockidp` serves an Entra-shaped tenant, an Okta org and a Kubernetes issuer and mints every token shape above; see its [README](../cmd/zeroid-mockidp/README.md).
`tests/integration/trusted_issuers_test.go` drives both person paths and every INV-IDN-014 refusal against it.

## Not yet

- Federated client assertions (P2) do not read workload rows yet.
- The connector "Trust for agent access" toggle (ADR 0042 open question 7) is not built; `source: connector` rows can be written through the API.
- Proof of issuer control (open question 8): the first account to add a customer-unique issuer holds it.
- Account lifecycle (D4a follow-up a): deleting an account in Admin does not yet remove its rows.
