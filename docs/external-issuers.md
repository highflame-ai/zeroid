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
  shared_issuers: []               # [{issuer, pin_claim}]; empty = the built-in list below
  first_contact:                   # bounds on first contact (below)
    rate_per_minute: 10            # Env: ZEROID_FEDERATION_FIRST_CONTACT_RATE_PER_MINUTE
    max_discovered_per_account: 500  # Env: ZEROID_FEDERATION_FIRST_CONTACT_MAX_DISCOVERED_PER_ACCOUNT
```

`allow_private_endpoints` relaxes the SSRF guard on issuer rows' discovery and JWKS fetches and admits `http` issuer and JWKS URLs.
It exists for local development against `cmd/zeroid-mockidp` and is a deployment setting, never a row field.
Production keeps it false.
Static entries keep their own `allow_private_endpoints`.

## Issuer rows

A row (`external_issuers`, migration 056) belongs to one account and holds:

| Field | Meaning |
|---|---|
| `issuer` | The `iss` tokens carry, matched exactly. https. |
| `kind` | `person`: an IdP whose ID-JAGs and ID tokens name people. `workload`: a client-assertion issuer for agents acting as themselves (P2); see [The workload path](#the-workload-path-federated-client-assertions). |
| `jwks_uri` | Never supplied by the caller. ZeroID reads it from the issuer's OpenID discovery document, `{issuer}/.well-known/openid-configuration`, whose `issuer` must equal the row's issuer exactly (OpenID Connect Discovery §4.3); both fetches go through the SSRF-guarded client. It changes only through `POST /external-issuers/{id}/refresh`, which re-reads discovery. A caller-chosen key set would let an admin sign tokens for anyone their IdP's issuer names. |
| `audiences` | Optional on a `person` row, required on a `workload` row. Extra accepted `aud` values. On the ID-token exchange an enabled binding already makes the presenting client's `client_id` an accepted audience, so an agent's app id is written once, as the binding's subject key; an ID-JAG's `aud` must be ZeroID's issuer whatever this lists. |
| `algorithms` | A subset of RS256, ES256, ES384, PS256 (all four by default). AWS STS signs with RS256 or ES384, as the caller asks. |
| `claim_mapping` | ZeroID name to token claim. `user_id` is the person's **user key** (Entra `oid`, Okta `sub`) and is required on a person row. Also `email`, `email_verified` (Entra `xms_edov`), `name`, `scope`, `trust_level`, and `groups`, the claim listing the person's groups (see [Groups](#groups)). `role` and `privilege_scope` are reserved and refused (`claim_mapping_reserved`): an IdP claim never sets a token's role or capabilities, and the ID-JAG grant ignores them on a row stored before the refusal. A static `external_issuers` entry naming one still loads, with a warning naming the issuer and the key, and the grant ignores it the same way. |
| `propagate_claims` | A subset of `auth_time`, `acr`, `amr`. |
| `claim_constraints` | Claim to accepted values. Every listed claim must be present and equal one of its values (for an array claim, contain one). Required on a shared issuer. |
| `max_token_age_seconds` | 1 to 3600, default 600. |
| `trust_email` | Person rows only, default false. The issuer vouches for its own email claim: a token that carries an email and **no** `email_verified` claim counts as verified. An explicit `email_verified: false` is never overridden. See [Trusting a directory's emails](#trusting-a-directorys-emails). |
| `jwks_cache_ttl_seconds` | 30 to 86400, default 300. |
| `source`, `source_ref` | `admin`, or `connector` with the connector that created the row. |
| `enabled` | A disabled row refuses every token at the next request. |
| `first_contact` | `off` (default), `discover` or `adopt`: what a credential that verified under this row does when no enabled binding maps its subject key. See [First contact](#first-contact). Stored on a disabled row, but acts only once the row is enabled. |
| `first_contact_project_id` | The project first contact registers agents into, and the only project whose agents an `adopt` row adopts. Required for `discover` and `adopt`. ZeroID checks its shape (a WIMSE URI path segment, at most 255 bytes), not that the project exists: the caller does. |
| `first_contact_owner_user_id` | The owner of the agents first contact adopts. Required for `adopt`, optional for `discover`. At most 255 bytes. |
| `first_contact_credential_policy_id` | `adopt` only, optional: the credential policy every agent the row adopts is assigned as its own, whether first contact registers it or a [standing adoption](#standing-adoption) activates it. Empty (the default, and always returned) assigns none, so the project's default credential policy governs the agents. It must name an active, unexpired credential policy in the row's account and `first_contact_project_id` that does not list `ciba:approve` (otherwise `first_contact_policy_invalid`). Setting `first_contact` to `off` or `discover` clears it. While a live row names a policy, that policy cannot be deleted (409). |
| `first_contact_updated_by`, `first_contact_updated_at` | Read-only: who last changed any of the four fields above, and when (on create or PATCH; empty until one is set). Every identity an `adopt` row adopts records them. |

### Who may hold an issuer

- An issuer unique to one customer (an Entra tenant, an Okta org, an AWS account's STS issuer, a cluster, a SPIFFE trust domain) is trusted by **one account at most**, whatever its claim constraints.
- Only an issuer on the platform's shared list may appear in several accounts.
  The list names, for each shared issuer, one **pinning claim** whose value says which customer a token belongs to.
  Every row on a shared issuer must constrain that claim; its other constraints only narrow the row.
  Two rows of the same kind, in any accounts, must not share a pinning value, and at a grant the token's pinning claim must be a single string (an array matches no row), so one token can never match two rows.
  Pinning only on the configured claim stops a first row on a near-universal claim (GitHub `event_name`, Entra `ver`) from blocking every other account, and array claims (`groups`) from making grants ambiguous.
- Constraints on claims every token carries (`iss`, `aud`, `exp`, `iat`, `nbf`, `jti`) are refused: they pin nothing.
- An issuer has at most one row per kind in its account, so an Entra tenant can be both the account's `person` issuer and its `workload` issuer.
- The Microsoft personal-account tenant (`9188040d-6c67-4c5b-b112-36a304b66dad`) belongs to no customer and cannot be trusted by any account.

Issuers are compared without trailing slashes, so `https://acme.okta.com/` and `https://acme.okta.com` are one issuer; a token's `iss` is still matched against the row exactly.
Writers check these rules under a per-issuer Postgres advisory lock (on the canonical issuer), backed by a unique index on `(rtrim(issuer, '/'), kind, constraints_key)`; `constraints_key` is empty for a customer-unique issuer and a hash of the pinning claim's values for a shared one.

**Known limitation.** ZeroID itself does not prove that an account owns the values it pins (`hd`, `tid`, `repository_owner_id`) or a customer-unique issuer it adds: the first account to claim them holds them (ADR 0042 open question 8).
For `person` rows the deployer closes the impersonation half with an ownership proof built on two routes, [`GET /external-issuers/{id}/discovery`](#get-external-issuersiddiscovery--200) and [`POST /external-issuers/{id}/verify-id-token`](#post-external-issuersidverify-id-token--200): the account's owner signs in through the issuer, ZeroID verifies the ID token as the ID-token exchange would, and the deployer (in SaaS, Admin) refuses person resolution through a row it has not verified.
For `workload` rows the deployer closes it with a challenge, [`POST /external-issuers/{id}/verify-workload-token`](#post-external-issuersidverify-workload-token--200): it writes the row disabled, hands the account a one-time audience, and enables the row only once ZeroID verifies a token the issuer minted for that audience under the row.

The built-in shared list (used when `federation.shared_issuers` is empty):

| Issuer | Pinning claim |
|---|---|
| `https://accounts.google.com` | `hd` |
| `https://token.actions.githubusercontent.com` (workload only) | `repository_owner_id` |

Entra is not on it.
Every Entra token carries its tenant's own issuer, `https://login.microsoftonline.com/<tenant-id>/v2.0`, and the multi-tenant endpoints (`common`, `organizations`, `consumers`) publish a templated issuer (`…/{tenantid}/v2.0`) in discovery, so a row on one could never pass the exact discovery match; they are refused for every kind.
A customer with several Entra tenants adds each tenant's issuer as its own (customer-unique) row.

`federation.shared_issuers` replaces it, as a list of `{issuer, pin_claim}`; ZeroID refuses to start if an entry lacks a pinning claim, pins `iss`, `aud`, `exp`, `iat`, `nbf` or `jti`, or is not https (http is admitted only with `federation.allow_private_endpoints`, for a local mock IdP).

Every row refuses a templated issuer (`{tenantid}`) and Entra's multi-tenant endpoints, which name no single tenant.
A person row also refuses an issuer that only issues workload tokens (GitHub Actions, `https://token.actions.githubusercontent.com`).

### Presets

`preset` fills only the fields the request leaves unset (`claim_mapping.groups` included, so an admin whose IdP names the claim differently sets their own), except the identity claims, which it pins: a request naming another claim for `user_id`, `email` or `email_verified` is refused (`invalid_claim_mapping`).

| Preset | Issuer | Fills |
|---|---|---|
| `entra` | `https://login.microsoftonline.com/<tenant-guid>/v2.0` | `algorithms` RS256, `claim_mapping` `user_id: oid`, `email`, `email_verified: xms_edov`, `name`, `groups`, and the constraint `tid: [<tid>]` |
| `okta` | `https://<org>.okta.com` or `.../oauth2/<server-id>` | `algorithms` RS256, `claim_mapping` `user_id: sub`, `email`, `email_verified`, `name`, `groups` |
| `generic` or absent | any | nothing |

The user key is `oid` for Entra because Entra's `sub` is pairwise per application, so one person would carry a different `sub` in every agent's app.
For `email_verified` on Entra, ask the customer to emit the optional claims `email` and `xms_edov`.

### Trusting a directory's emails

OpenID Connect returns `email_verified` from the UserInfo endpoint, not in the ID token, whenever the sign-in also issued an access token (OIDC Core 5.4).
An authorization-code sign-in does, so an organization's own directory (Okta is one) may put `email` in the tokens ZeroID sees and never `email_verified`; its ID-JAGs may carry an email and no `email_verified` either.
ZeroID only ever sees those tokens, so it cannot ask the UserInfo endpoint itself.

`trust_email: true` is the deployer's statement that this issuer is the organization's directory and its email claim can be trusted as given.
With it, a token that carries an email and no `email_verified` claim is passed to the person resolver as verified; a token that says `email_verified: false` stays unverified.
Without it (the default), such a token is unverified, as before.

Turn it on only for an issuer whose emails its users cannot set to someone else's address: the organization's own directory, not a social or multi-tenant identity provider.

### Read live

On every federated grant ZeroID reads the issuer's rows with one indexed query and caches no row, so a disable or delete applies at the next request on every replica.
Only JWKS clients are cached: shared by every row with the same `(jwks_uri, jwks_cache_ttl_seconds)`; created on first use, with one fetch however many requests race for a cold key set; a use by an account is dropped after 30 idle minutes and a client with no users is closed; capped at 20 per account (evicting only that account's use of a shared client) and 1000 in total.
A refresh triggered by an unknown `kid` is single-flight and at most one per 10 seconds per key set, since the kid comes from an unverified token.
Tokens already issued under a deleted row live out their 15 minutes; bulk revocation on delete is ADR 0042 open question 6.

## Bindings

A binding (`external_issuer_bindings`) maps `(issuer row, subject key)` to one identity in the row's account (ADR 0042 D6).
The subject key is the value the credential carries at runtime:

| Grant | Subject key |
|---|---|
| ID-JAG (P1b) | `act.sub`, the agent's client id at the IdP; the ID-JAG's `client_id` when it has no `act` (`act` is OPTIONAL in the draft) |
| ID-token exchange (P1c) | the presenting client's `client_id`, which is the ID token's `aud` |
| Federated client assertion (P2) | the assertion's `sub`: an AWS role ARN, `system:serviceaccount:<ns>:<name>`, a SPIFFE ID |

At most one **enabled** binding may exist per `(issuer row, subject key)`.
A binding for an identity that is not `active` is created disabled, and enabling one requires the identity to be active.
ZeroID never enables a binding itself: the deployer (in SaaS, Admin) enables an agent's bindings when an org admin adopts or activates it.
The exception is an `adopt` row's [first contact](#first-contact), whose standing mapping is the adoption: the binding it creates for an agent it registers, and the disabled binding of an agent it adopts ([standing adoption](#standing-adoption)).
Each binding carries `explicitly_disabled`: true when an admin disabled it (`PATCH {"enabled": false}`) or created it with `"enabled": false`, false when it is disabled only because its identity was not active yet.
At adoption the deployer enables bindings with the conditional PATCH below, which skips any with `explicitly_disabled: true`, so adoption never undoes an admin's decision; a plain `PATCH {"enabled": true}` clears it.
Until then the mint refuses it as not adopted (D7), naming the state.

## The workload path: federated client assertions

An agent acting as itself, with no person behind it, gets a token with `grant_type=client_credentials` and a `client_assertion` that its platform signed for it (ADR 0042 D8, path P2): an AWS STS web identity token, a Kubernetes service account token, or a SPIFFE JWT-SVID. The agent holds no secret and registers no OAuth client. Entra app-only tokens are not accepted yet: they carry `uti` rather than `jti`, and live far longer than the age cap allows.

```
POST /oauth2/token
grant_type=client_credentials
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<token from the workload issuer>
scope=tools:read                 (optional)
resource=https://gateway.example (optional, RFC 8707)
```

Before an agent can use it:

- The row's `audiences` must include ZeroID's issuer or its token endpoint (`<issuer>/oauth2/token`), whichever the platform puts in `aud`. Step 4 below requires `aud` to be both one of these and listed on the row.
- The bound identity's credential policy must allow `client_credentials` in `allowed_grant_types`, or the grant is refused after the binding is read.

When the assertion's `iss` names a `workload` row in database mode, ZeroID takes this path instead of looking for a registered client:

1. Exactly one enabled `workload` row for `iss` matches the assertion's claims. An `iss` with workload rows that are disabled, unmatched or ambiguous is refused, not passed on to the registered-client path.
2. `client_assertion_type` is jwt-bearer, and no `client_secret` is sent alongside the assertion.
3. The assertion verifies against the row's JWKS, with the row's algorithms, issuer, `audiences`, claim constraints and token-age cap (measured since `iat`).

   Every refusal up to here is the generic `invalid client credentials`, with the reason in the log: until the signature verifies, a distinct answer would tell an unsigned probe which issuers and claim values an account trusts.
4. `aud` is exactly one value. It must be ZeroID's issuer or its token endpoint (RFC 7523 §3), and also one of the row's `audiences`. STS can put several audiences in one token, and a token minted for several servers, or for a broad audience such as a cluster's API server, could be replayed at each of them.
5. `jti` is present, and the lifetime from `iat` to `exp` is at most the row's `max_token_age_seconds` (600 by default). That fits STS's 300-second default and Kubernetes' 600-second minimum, and refuses a long-lived token at any point in its life. A `client_id`, if sent, must be `sub` (RFC 7523 §3), `<iss>#<sub>`, or `iss`.
6. The `jti` is recorded for single use, keyed on `(iss, sub, jti)` because a Kubernetes subject repeats across clusters. It is spent here, before the binding is read, so a captured assertion cannot replay binding refusals. If minting then fails on the server side (5xx) and nothing was issued, the `jti` is released, so retrying the same platform token works: a Kubernetes or STS token can't be re-signed on demand. A refusal (4xx) keeps it spent.
7. An enabled binding maps `(row, sub)` to an `active` identity (D6, D7). The tenant is that identity's, and a request that names another tenant is refused (D5).
   With no enabled binding, the row's `first_contact` may first register the agent, or adopt it under the row's standing mapping ([First contact](#first-contact)).

The token is for the bound identity. Scopes are the request narrowed by the identity's policy and allowed scopes. The agent must have a scope limit: if neither its identity nor its credential policy sets `allowed_scopes`, the request is refused with `invalid_scope`, whatever it asks for, as a registered `client_credentials` client with no scopes is. Without that, the grant would issue whatever scopes the request names. `client_id` is always `<iss>#<sub>`: a Kubernetes subject repeats across clusters, and any account can add its own issuer and bind any subject string, so `sub` alone never names one client. Issuer URLs carry no fragment, so the first `#` separates the two. `client_auth` is `federated_assertion`. No registered OAuth client can carry a `client_id` containing `#`: admin registration and a binding's presenting client refuse one with 400, and a CIMD client id containing `#` is invalid. So a registered client can never share a `client_id` with a federated one.

A token with `client_auth=federated_assertion` cannot enroll a key through `POST /agents/self/public-key`. The token is held by whatever runs the agent's credential provider, such as an AgentCore token vault or a gateway, and the agent was meant to hold no secret.

Failures before the binding is read are `invalid_client` (401): those in steps 1–3 with the generic answer, and a multi-valued or foreign `aud`, an over-long assertion, a missing `jti`, a mismatched `client_id` or a replay with their reason. A missing, disabled or unadopted binding is `invalid_grant`, with the same unmatched-agent and not-adopted events as the person grants.
A server-side failure while verifying, such as an issuer whose JWKS cannot be fetched, keeps its 5xx status (`server_error`) but answers with the generic `client authentication is temporarily unavailable`; the detail, which names the issuer, goes to the log.

The agent cannot revoke its own token at `POST /oauth2/token/revoke`. It has no registered client to authenticate as, so presenting the federated assertion, or `<iss>#<sub>` as `client_id`, is refused with `invalid_client` (401). A revocation with no client authentication is refused the same way unless `token.allow_unauthenticated_token_inspection` is set, which production never allows. The token lives 15 minutes, or less if the identity's credential policy sets a shorter `max_ttl_seconds`, unless an administrator revokes it through `POST /credentials/{id}/revoke`. Disabling the binding or the row stops new tokens but does not revoke ones already issued, so 15 minutes is how long a token can outlive that change.

## The person grants with issuer rows

Both grants resolve the issuer first: the token's `iss` must have an **enabled `person`** row whose claim constraints the token satisfies.
The client authenticates first; nothing about the token's issuer is looked up for an anonymous caller.
Every issuer refusal (unknown, workload row, disabled row, no or several rows matching its constraints) is then the same `invalid_grant` ("…'s issuer is not trusted for this grant"), since the token is not verified yet and a distinct answer would tell a probe which IdPs are trusted.
The reason is logged as `federation_issuer_refused` and counted in `zeroid.federation.issuer_refused{reason}`.
This also applies to static issuers, where an unknown issuer on the ID-token exchange used to be `invalid_request`.
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

A client may name the subject token with the generic type `urn:ietf:params:oauth:token-type:jwt` instead (RFC 8693 §3).
Some credential brokers do this when they exchange, on a workload's behalf, the token the workload was called with.
The request is then an ID-token exchange too, when it authenticates a client and the caller is not a trusted service, and the same rules apply.
Any other request with that type keeps the broker path.

All of these must hold (ADR 0042 D3a), or the exchange is refused with `invalid_grant` (`invalid_client` for client authentication):

1. The client authenticates with `private_key_jwt`; a client secret is `invalid_client`.
   This rule is for issuer rows: a static issuer (standalone ZeroID) keeps the client's registered method, secrets included.
   Its `client_id` is in the ID token's `aud`; `azp`, when present, is a string equal to it; several audiences without `azp` are refused.
   The `aud` is accepted because it names the presenting `client_id`, which must then be the subject key of an enabled binding on the row (rule 4; the binding is the audience rule), or because it is in the row's `audiences`.
2. The subject token is positively an ID token (static issuers too): it carries `iss`, `sub`, `aud`, `exp` and `iat`, and no access-token marker: no `scp`, `scope`, `azpacr` or `appidacr` (Entra stamps one of the last two on every access token, app-only ones included), and no `typ` of `at+jwt`, `application/at+jwt` or `oauth-id-jag+jwt`.
   `roles` alone is not a marker: Entra ID tokens carry a user's app roles in it.
3. The issuer row is `person`, and the subject is not a workload (static issuers too): no Entra `idtyp=app`, no `system:serviceaccount:` subject, no SPIFFE ID, no GitHub Actions `repo:` subject.
4. An enabled binding maps the client's `client_id` under the row to an identity, which is the agent.
   If the client's registration links an identity, it must be that one.
   The account is the row's and the project is the agent's; a request's `account_id`, `project_id` or `application_id` must match.
5. The person resolver finds the person in the account (below).
6. The agent is `active` (D7).

The token's `sub` is the person's user id with `user_id_iss` ZeroID's issuer, the IdP's pair is in `user_idp_iss` and `user_idp_sub`, `principal_type` is `user`, the agent is the current actor in `act`, `client_id` is the presenting client, and `resource` audience-restricts it.

### P1b: ID-JAG

The request is unchanged ([identity-model.md](identity-model.md#enterprise-managed-authorization-id-jag)).
Its `aud` must name ZeroID's issuer (draft §4.3); the row's `audiences` play no part.
With issuer rows the agent is the ID-JAG's `act.sub` (its `client_id` when it has no `act`) mapped through an enabled binding, not the client's linked identity or `application_id`, and there is no synthetic identity.
The draft also makes the `resource` claim OPTIONAL: an ID-JAG without one is bound to the RFC 8707 `resource` the request names, and refused when the request names none, so every minted token is still audience-restricted.
A registered client linked to a different identity is refused, and a CIMD client gets its tenant from the binding.
The subject must not be a workload, and checks 4 to 6 above apply.
Every check, including person resolution, runs before the ID-JAG's `jti` is consumed, after the replay check, so a refused request leaves the grant redeemable.
The exception is [first contact](#first-contact), which spends the `jti` before it registers or adopts the agent.

### Refusals that are events

- **Unmatched agent** (ADR 0027): no binding for the subject key, only a disabled binding for an active identity, a binding to no identity in the account, or a registered client not linked to the bound identity.
  On both grants the binding is read only after the token's signature and the checks that need no binding have passed, so a forged token raises no event under an account and learns nothing of its bindings.
  Logged as `federation_unmatched_agent` (account, issuer, subject key, grant, reason) and counted in `zeroid.federation.unmatched_agent{account_id, grant_type, reason}`.
- **Agent not adopted** (D7): the bound identity, through an enabled or disabled binding, is not `active`; the error names the state (`agent identity is discovered; ...`); logged as `federation_agent_not_adopted` and counted in `zeroid.federation.agent_not_adopted{account_id, grant_type, status}`, the adoption queue's demand.

ZeroID has no event bus; an embedder that needs ADR 0027 findings reads these.

## First contact

An agent can become known on its first call, instead of waiting for an inventory sync or an admin to bind it.
And an agent an inventory sync found first can be adopted on its first call, instead of waiting for a person.
An issuer row's `first_contact` says what a credential does when it has verified in full under the row and names an agent no enabled binding maps:

| `first_contact` | No binding at all | Only a disabled binding |
|---|---|---|
| `off` (default) | The refusal above: `invalid_grant`, "no enabled binding", and the unmatched-agent event. | The refusal above: "agent identity is discovered; ..." (the not-adopted event) for an agent that is not `active`, else "no enabled binding". |
| `discover` | ZeroID registers a `discovered` identity in `first_contact_project_id`, with a **disabled** binding on the subject key, then refuses the request as it refuses any unadopted agent: `invalid_grant`, "agent identity is discovered; ...". The unmatched-agent event names the new identity (`reason` `first_contact_registered`, `identity_id`), and the not-adopted event follows. Adoption later enables the binding as for any discovered agent (its `explicitly_disabled` is false). | As `off`: the agent is in the adoption queue already. |
| `adopt` | ZeroID registers an **active** identity in `first_contact_project_id`, owned by `first_contact_owner_user_id`, governed by `first_contact_credential_policy_id` when the row names one, with trust level `verified_third_party` and an **enabled** binding, and the request goes on to mint for it. | ZeroID adopts the agent's existing identity under the same mapping, enables its binding, and the request goes on to mint: [standing adoption](#standing-adoption), with the guards it lists. |

Setting `adopt` on a row is the adoption decision for every agent the row's issuer vouches for, whether ZeroID first hears of the agent from its call or from an inventory sync, so set it only where the account means that.

**The credential policy.** An `adopt` row's `first_contact_credential_policy_id` is part of that decision: every agent the row adopts is assigned that policy as its own `credential_policy_id`, the reference `PATCH /identities/{id}` sets, so it governs the agent's mints in place of the project's default. Without one the project's default governs, and a default that sets no `allowed_scopes` refuses the first call of every workload agent the row adopts (`invalid_scope`, "the agent has no scope limit"; see the scope rule above): name a policy that allows the grant and the scopes the agents need. The policy is assigned when an agent is adopted. Changing it later changes nothing for agents adopted before, and an agent's own policy can still be changed afterwards like any identity's.
If the policy is missing, inactive, expired, or lists `ciba:approve` when an agent arrives, first contact fails closed: nothing is registered or adopted, and the request is refused exactly as with `first_contact` `off`, logged with outcome `policy_unusable` and the policy's id. On the ID-JAG this is decided before the person is resolved and the `jti` is spent, so the ID-JAG stays redeemable once the policy is usable again. A row write checks the policy (it must exist and be usable in the row's account and `first_contact_project_id`, 400 `first_contact_policy_invalid` otherwise) only when it names the policy or moves the row to another project, so a row whose policy became unusable later can still be renamed or disabled.
`DELETE /credential-policies/{id}` refuses (409) a policy that a live `adopt` row in its tenant (the row's account and `first_contact_project_id`) names, disabled rows included, with a detail naming the first-contact mapping, as it refuses one a service key holds: clear `first_contact_credential_policy_id` on the row, or move it off `adopt`, first.

**Triggers.** Two, each only once the credential has verified in full against an enabled row of the right kind:

- A federated client assertion under a `workload` row ([steps 1 to 6](#the-workload-path-federated-client-assertions): signature, `aud`, lifetime, the `jti` spent) whose `(iss, sub)` has no enabled binding. The subject key is `sub`.
- An ID-JAG under a `person` row whose agent (`act.sub`, or the ID-JAG's `client_id` when it has no `act`) has no enabled binding under the row. Only when the redeeming client is a CIMD client, whose registration is the IdP-signed ID-JAG itself: a registered client must be linked to the agent it redeems for, and first contact never creates or links OAuth clients. A registered client's ID-JAG is refused as with `off` (logged with outcome `registered_client`), and stays redeemable.
  The tenant is the row's account and `first_contact_project_id`; a request that names another is refused, and so is an `application_id` that is not the agent (an agent to register has none yet). The ID-JAG passes every check that needs no binding, then the replay check, then **person resolution** in that tenant (`AgentIdentityID` is the existing identity for a standing adoption, and empty for an agent not registered yet). Only then is its `jti` spent and the agent registered or adopted, so a person the resolver refuses leaves no identity or binding behind, leaves an agent awaiting a standing adoption `discovered`, and its ID-JAG stays redeemable once the person is a member. With `adopt` the request then mints with the person already resolved; a later refusal, such as the person-grant scope ceiling, keeps the registered or adopted agent.

The ID-token exchange (P1c) never registers or adopts an agent: its presenting client must already be bound.

**What it never does.**

- It never registers an agent that has a binding, enabled or not. It changes an existing identity only through a standing adoption, and never one a person has decided on: an explicitly disabled binding, a `pending`, `active`, `suspended` or `deactivated` (dismissed) identity, and an identity in another project are refused as before.
- It never creates a person, a membership or an OAuth client, and never trusts an issuer that is not already a row of the account.
- A disabled row registers and adopts nothing, whatever its mode. A deployer that creates workload rows disabled until their control is proven therefore keeps first contact inert until then.

**The identity.** Filled from the verified credential only:

| Field | Value |
|---|---|
| `origin` | `first_contact`. Reserved: no API caller can create an identity with it, and the discovered-identity ingest refuses it (400). |
| `status`, `trust_level`, `owner_user_id` | `discover`: `discovered`, `unverified`, the mapped owner if set. `adopt`: `active` (with `adopted_at`), `verified_third_party`, the mapped owner. |
| `account_id`, `project_id` | The row's account, `first_contact_project_id`. |
| `identity_type`, `sub_type` | `agent`, `tool_agent`. |
| `credential_policy_id` | Under `adopt`, the row's `first_contact_credential_policy_id` when it names one; otherwise, and under `discover`, the project's default credential policy. For `adopt` to mint, that policy must allow the grant (`client_credentials` or `jwt_bearer`) and, on the workload path, set `allowed_scopes` (see the scope rule above). |
| `name` | The subject key (cut to 255 bytes). |
| `external_id` | `first_contact.` followed by the subject key when that is a valid WIMSE URI path segment (letters, digits, `.`, `-`, `_`) of at most 128 bytes, as an opaque IdP client id is. Otherwise (an AWS role ARN, a Kubernetes service account, a SPIFFE ID, a URL) `first_contact.` followed by its last 160 bytes with every other byte replaced by `_`, then `-` and 20 hex digits of SHA-256(issuer row id, subject key). The `first_contact.` prefix is reserved: no other caller can create an identity whose `external_id` starts with it, and a discovered-identity ingest that sends one is refused with 400. So an inventory record whose own id is the agent's subject key (an IdP app the agent uses as its OAuth client, say) never lands on the agent: it is a separate identity, and an ingest reaches the agent only through `metadata.issuer_binding` (below). The subject key itself is always in the binding and in the metadata below. If the project already has an identity with that `external_id`, nothing is registered: the request gets the plain refusal, logged with outcome `external_id_taken`. |
| `labels` | `{"discovered_via": "first_contact"}`, so `GET /identities?label=discovered_via:first_contact` lists them (add `status=discovered` for the unadopted ones: a list leaves those out unless asked). Under `adopt`, also `"adopted_via": "first_contact"`, as on every identity a standing mapping activated. |
| `metadata.first_contact` | `issuer`, `issuer_id`, `subject_key`, `first_seen_at`, `grant_type` (`client_credentials` or `id_jag`), `mode`, and for an AWS STS web identity token `aws`: `account`, `org_id`, `ou_path` and `principal_tags` from its `https://sts.amazonaws.com/` claims. Request tags are never kept: the caller of `GetWebIdentityToken` chooses them. The person behind an ID-JAG is never recorded on the agent. |
| `metadata.first_contact_adoption` | Under `adopt` only: the [adoption record](#standing-adoption). |

The binding's `created_by` is `system:first_contact`, and so is the actor of every audit row the registration writes.

### Standing adoption

An inventory sync usually reaches ZeroID before an agent's first call: it ingests the agent as `discovered` and binds its runtime subject under the row with a binding that starts disabled.
Under an `adopt` row, that agent's first verified call adopts it under the row's standing mapping, as if the row had registered it, when all of these hold:

1. No binding of the subject key under the row is **explicitly disabled**. An explicit disable is a person's decision, and it always wins.
2. Exactly **one** binding maps the subject key under the row. With several, which identity the agent is is for a person to decide.
3. The bound identity is **`discovered`**. A `pending` identity (a person has taken it on), and an `active`, `suspended` or `deactivated` (dismissed) one, are left as they are, even when its binding is disabled.
4. The identity is in the row's account **and in `first_contact_project_id`**. An identity in another project is refused as before, and logged (outcome `other_project`): the row's mapping names one project, and adopting into another is not what anyone set. This is the conservative choice; a row that should adopt across its account's projects is not built.
5. The identity is not an **approval channel** (sub-type `approval_channel`, or `ciba:approve` on the identity or its credential policy). Only a person activates an approval channel.
6. The row is enabled, its `first_contact` is `adopt`, and its mapping is complete.
7. The row's `first_contact_credential_policy_id`, when it names one, can be assigned: it exists in the row's account and `first_contact_project_id`, is active and unexpired, and does not list `ciba:approve` (outcome `policy_unusable` otherwise).

Then, in one transaction under the same per-account lock as a registration, with the row, the bindings, the identity and the binding re-read (the last two locked):

- the identity takes the lifecycle transition `discovered → active` (the direct activation of [identity-lifecycle.md](identity-lifecycle.md)), owned by `first_contact_owner_user_id`, with trust level `verified_third_party` and `adopted_at`. When the row names a `first_contact_credential_policy_id`, that policy becomes the identity's own `credential_policy_id`, replacing the one it had (an inventoried agent carries its project's default from birth); otherwise it keeps its credential policy, or takes the project's default when it has none, as a registered agent does. Its `origin`, `external_id`, name and the rest are unchanged;
- it gets the label `"adopted_via": "first_contact"` and `metadata.first_contact_adoption`: `issuer`, `issuer_id`, `subject_key`, `grant_type`, `credential_policy_id` (the row's `first_contact_credential_policy_id`, absent when it names none), and `mapping_updated_by` and `mapping_updated_at`, the row's `first_contact_updated_by` and `first_contact_updated_at`, so the record names the person whose mapping adopted it;
- the binding the credential arrived through is enabled, with `updated_by` `system:first_contact`. The identity's bindings under other rows are left as they are.

The request then mints for the adopted agent. If any guard fails, nothing is written and the request is refused as without first contact. An agent first contact registered under a `discover` row is adopted the same way once its row is switched to `adopt`; its `metadata.first_contact` keeps the mode it first arrived under.

`GET /identities?label=adopted_via:first_contact` lists every identity a standing mapping activated, registered by first contact or not. A discovered-identity ingest can neither add nor remove the label and the record: it keeps them on an identity that has them, whatever it sends, and drops them from an identity that has not. The identity API's own create and update write labels and metadata as given, so the audit row of the activation, whose actor is `system:first_contact`, is the record to rely on.

The audit rows of the transition and of the binding enable name `system:first_contact` as the actor, and the transition's row carries the adoption record, with who last set the mapping. The row's own audit trail shows when that person set it.

**Bounds.** Two, from `federation.first_contact` (defaults above):

- `rate_per_minute`: the agents registered or adopted under one row in any minute.
- `max_discovered_per_account`: the account's `first_contact` identities still `discovered`. `adopt` registers and adopts active identities, which this does not count, and a standing adoption creates nothing.

Past either, nothing is written, and the credential is refused as without first contact: the plain no-binding refusal for an unbound agent, "agent identity is discovered" for one awaiting a standing adoption. The attempt is logged.

**Concurrency.** Registration and standing adoption run in one transaction under a per-account lock, and re-read the row (still enabled, still on, same project) and the subject's bindings under it. Concurrent first contacts for one subject therefore register one identity and one binding, or adopt the agent once; the later ones read the first one's binding and are answered as for any bound agent.

**Events.** Every attempt is logged as `federation_first_contact` (account, issuer row, subject key, grant, mode, `outcome`, and the identity registered, adopted or considered; for one registered or adopted, also its `credential_policy_id`) and counted in `zeroid.federation.first_contact{account_id, grant_type, mode, outcome}`. Outcomes: `registered`, `adopted`, `already_bound`, `row_changed` (disabled, deleted, switched off or re-mapped since the request read it), `rate_limited`, `account_cap`, `external_id_taken`, `subject_too_long`, `registered_client`, `policy_unusable` (the row's credential policy is missing or cannot be assigned; logged with its `credential_policy_id`), and the standing adoption's guards: `explicitly_disabled`, `ambiguous_binding`, `not_discovered`, `other_project`, `approval_channel`. A `discover` row logs nothing for an agent that is bound already.

**Merging with an inventory sync.** An agent first contact registered may later be found by a discovery connector. A `POST /identities/discovered` (or the batch) whose `external_id` matches no identity, and whose `metadata.issuer_binding` names the same subject, updates the first-contact identity instead of creating a second one:

```json
{"metadata": {"issuer_binding": {"issuer_id": "<issuer row id>", "subject_key": "<subject key>"}}}
```

`issuer` (the row's issuer URL) may stand in for `issuer_id`. Only within the same account and project: an ingest into another project creates its own identity. The update is the usual discovered reconcile (name, description, labels, metadata and the rest), except that the `discovered_via` label and `metadata.first_contact` are kept whatever the ingest sends, as are the standing-adoption markers above. The identity keeps its `external_id` and `origin`.

An ingest's `external_id` never names a first-contact identity, even one registered before its `external_id` moved into the `first_contact.` namespace and so holding the bare subject key: such an ingest is refused with 409, and names the agent through `metadata.issuer_binding` instead.

## Person resolution

```go
srv.SetFederatedPersonResolver(func(ctx context.Context, r zeroid.FederatedPersonRequest) (string, error) {
	// r.GrantType        zeroid.PersonGrantIDJAG or zeroid.PersonGrantExternalIDToken
	// r.AccountID, r.ProjectID   the tenant the token is minted into
	// r.Issuer, r.Subject        the IdP and the person's user key (claim_mapping.user_id)
	// r.IssuerID                 the issuer row that verified the token ("" for a static issuer)
	// r.Email, r.EmailVerified   the mapped email, and whether the IdP asserted it verified
	// r.ClientID, r.AgentIdentityID
	return highflameUserID, nil // or zeroid.ErrPersonNotMember
})
```

- The returned id becomes the token's `sub`.
  `user_id_iss` keeps meaning "the issuer of `sub`", so it becomes ZeroID's own issuer, as on `authorization_code` and the external-principal exchange (under the `rfc8693` profile; the legacy profile emits no `user_id_iss` for such a `sub`).
  The IdP's pair travels together in the reserved claims `user_idp_iss` (the IdP's issuer) and `user_idp_sub` (the user key).
  They are prefixed `user_` because they describe the person, and to stay clear of the agent's own IdP provenance (`agent_idp_iss`), which Shield projects as `principal.idp_iss`.
  All three are written after caller-supplied claims, so no caller can set them.
- Key links on `IssuerID` as well as `(Issuer, Subject)`: a row deleted and added again gets a new id, so its people re-link on first sight under the new row's rules and never inherit links made under the old one (whose claim mapping may have differed).
- `ErrPersonNotMember` is `invalid_grant` ("the person is not a member of this organization").
- Any other error, an empty id or a panic is `server_error` with a fixed message; the cause is logged, never returned.
  Each call is bounded at 5 seconds.
- With issuer rows a resolver is required: without one the grants answer `server_error` ("person resolution is not configured").
  With static issuers and no resolver, `sub` stays the IdP subject, `user_id_iss` is the IdP's issuer, and there is no `user_idp_iss` or `user_idp_sub`.

The person-grant ceiling ([scope-ceilings.md](scope-ceilings.md#a-persons-ceiling)) then sees the resolved user id.

When the agent exchanges the person token (RFC 8693, `actor_token` = its own assertion) to narrow it, it is already the token's current actor, so under the `rfc8693` profile the child keeps `act` = the agent with no extra nesting and no added `delegation_depth`.
The legacy profile is frozen (ADR 0043 D1): there the exchange delegates as before, adding a level.
`user_idp_iss` and `user_idp_sub` travel with `sub` onto every exchanged `rfc8693` token; a different agent becomes a new actor level as usual.

## Groups

An issuer that sets `claim_mapping.groups` copies the person's groups from the ID token or ID-JAG into the issued token's `groups` claim (RFC 9068 §2.2.3.1), an array of strings.
A resource server reads it as `authjwt.Claims.Groups`.

- The claim may be a JSON array of strings or a single string (one group). Entries are skipped when they are not strings, are empty or blank, have leading or trailing whitespace, or contain control characters, format characters, any space separator other than U+0020 (such as a no-break space or a line separator), the replacement character U+FFFD (which JSON decoding substitutes for invalid UTF-8, so two different malformed names would otherwise collapse into one), or a blank-rendering Hangul filler (U+115F, U+1160, U+3164, U+FFA0). Duplicates collapse.
- Names are copied byte for byte: no trimming, case folding or Unicode normalization, because a policy must match what the IdP sends. Matching a group is case-sensitive and exact.
- No such claim in the IdP token means no `groups` claim. That is not an error.
- A claim of any other shape (a number, an object) is ignored with a warning; the grant still succeeds.
- Limits: at most 1000 raw entries are read, and at most 100 groups are kept after skipped entries and duplicates are removed, each at most 256 bytes and 8 KiB in total. Above any limit the whole claim is dropped with a warning, never truncated, so a token's list is either the IdP's whole usable list or absent.
- Entra sends an overage indicator instead of the list when a person is in too many groups (`_claim_names` naming the claim, or `hasgroups`). That reads as no groups, with a warning. Entra's `groups` claim holds group object ids unless the app registration emits names.
- Groups are fixed at issue time, like the other person claims; a change at the IdP takes effect at the next exchange. They never set `role` or `privilege_scope`.
- `groups` is reserved: `additional_claims` cannot set it. It is written only on a token whose `sub` is the person, and travels with `sub` onto every exchanged `rfc8693` token, like `user_idp_sub`, and onto a CIBA approval made with a `requesting_token` that carries it, when the approval's `sub` is that person. Under the legacy profile an exchanged token's `sub` is the actor, so it carries none.
- **An absent `groups` claim means unknown, not "a member of no group".** The list is dropped above the limits or on overage, and several person tokens never carry it: `authorization_code` and `refresh_token` grants, the trusted external-principal exchange, CIBA approvals made without a `requesting_token`, and legacy-profile delegated tokens. A resource server must never grant access on the absence of a group, and a deny rule keyed on a group must treat an absent claim as unknown (fail closed where that matters).

- Token introspection (RFC 7662) returns `groups` for an active token that carries it.
- **Rollout:** before this feature `groups` was not a reserved claim, so a token minted earlier could carry a `groups` value injected through `additional_claims`, which a token exchange or CIBA continuation would copy onward. Do not rely on group-based policies until one access-token lifetime after the rollout completes.

`claim_mapping.groups` is not an identity key, so a PATCH may change or remove it. It is refused (`invalid_claim_mapping`) with surrounding whitespace, and on a workload row, where nothing reads it; a static `external_issuers` entry breaking either rule fails at startup with the same message.
An empty value (`"groups": ""`) turns groups off: on create it keeps a preset from filling the key, and on create or PATCH it is stored as no mapping, so the row's `claim_mapping` has no `groups` key afterwards. A PATCH whose `claim_mapping` leaves `groups` out removes it the same way; presets apply on create only, so nothing refills it. Rows that existed before `groups` was added are not changed.

`POST /external-issuers/{id}/verify-id-token` returns the groups it read as `groups`, filtered and limited exactly as the grants do, and omits the field when the mapping is unset or yields none.

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
| 400 | `invalid_identity_id`, `invalid_kind`, `invalid_audiences` (a workload row with none), `invalid_algorithms`, `invalid_claim_mapping`, `invalid_claim_constraints`, `invalid_propagate_claims`, `invalid_max_token_age`, `invalid_jwks_cache_ttl`, `invalid_trust_email` (on a workload row), `invalid_source`, `invalid_preset`, `invalid_request`, `invalid_subject_key` | The named field is invalid |
| 400 | `first_contact_mapping_required` | `first_contact` is `discover` without `first_contact_project_id`, or `adopt` without `first_contact_project_id` and `first_contact_owner_user_id`; on PATCH, checked against the stored fields the patch leaves unchanged |
| 400 | `invalid_first_contact` | `first_contact_project_id` is not a WIMSE URI path segment, or either mapping field is over 255 bytes. A `first_contact` other than `off`, `discover` or `adopt` is refused by the body schema first (huma's 422) |
| 400 | `first_contact_policy_invalid` | `first_contact_credential_policy_id` is set while the row's resulting `first_contact` is not `adopt` (on PATCH, including a patch that sets `off` or `discover` and names a policy), is over 255 bytes, names no credential policy in the row's account and `first_contact_project_id` (also when a PATCH moves the row to a project the kept policy does not belong to), or names one that is inactive, expired or lists `ciba:approve`. Checked on create, and on a PATCH that names the policy or changes the project |
| 400 | `claim_mapping_reserved` | `claim_mapping` names `role` or `privilege_scope`, on create or on any PATCH that is not only a rename or a disable (a row stored with one must drop it to be edited) |
| 401 | `unauthorized` | No tenant context |
| 404 | `not_found` | No such row or binding in this account |
| 409 | `issuer_already_trusted` | The issuer is trusted by another account, or this account has a row of this kind (and constraints) already. Never names the other account |
| 409 | `issuer_limit_reached` | The account has 20 issuers |
| 409 | `issuer_store_config` | Any route but the list and `/check` on a `config`-mode server |
| 409 | `issuer_changed` | A PATCH with `if_updated_at` whose value is no longer the row's `updated_at` |
| 409 | `binding_conflict` | Another enabled binding maps this subject key under this issuer |
| 409 | `binding_exists` | The same (issuer, subject key, identity) binding exists |
| 409 | `binding_explicitly_disabled` | A conditional enable of a binding an admin disabled |
| 409 | `identity_not_active` | Enabling a binding for an identity that is not active |
| 409 | `client_conflict` | The requested OAuth client exists and is not this identity's `private_key_jwt` client |
| 422 | `wrong_kind` | `/discovery` or `/verify-id-token` on a `workload` row; `/verify-workload-token` on a `person` row |
| 422 | `issuer_disabled` | `/verify-id-token` on a disabled row |
| 422 | `token_invalid`, `audience_mismatch`, `constraint_mismatch`, `nonce_mismatch` | `/verify-id-token` refused the token ([below](#post-external-issuersidverify-id-token--200)) |
| 422 | `token_invalid`, `audience_mismatch`, `constraint_mismatch`, `audience_not_a_challenge`, `pin_not_single` | `/verify-workload-token` refused the token or the challenge ([below](#post-external-issuersidverify-workload-token--200)) |
| 422 | `discovery_unreachable` | `{issuer}/.well-known/openid-configuration` could not be fetched: unreachable, not 200, a redirect (discovery is never followed through one), or a private or reserved address (not told apart, so the API is no internal-DNS oracle; the log says which) |
| 422 | `discovery_issuer_mismatch` | The discovery document names a different issuer |
| 422 | `discovery_invalid` | The discovery document names no usable `jwks_uri`; on `/discovery`, also no usable `authorization_endpoint` or `token_endpoint` |
| 422 | `jwks_unreachable` | The JWKS could not be fetched, including from a private address; redirects are followed only to https, at most 3 (no upstream detail is returned). On `/verify-id-token` and `/verify-workload-token`, the row's key set could not be loaded |
| 422 | `jwks_empty` | The JWKS has no RSA or EC signing key |
| 422 | `shared_issuer_requires_constraints` | A shared-issuer row that does not constrain its pinning claim |
| 422 | `claim_mapping_immutable` | A PATCH changing `claim_mapping.user_id`, `email` or `email_verified` |
| 422 | `issuer_is_self` | The issuer is ZeroID's own (`token.issuer`, compared without trailing slashes); static `external_issuers` listing it are refused at boot |
| 422 | `identity_not_found` | `identity_id` names no identity in this account |
| 422 | `identity_has_no_public_key` | `oauth_client` was requested but the identity has no EC P-256 key |
| 500 | `internal_error` | Anything else |

Sizes: `issuer` and each audience at most 2000 bytes, at most 50 audiences, `subject_key` at most 2000 bytes, claim names at most 128 bytes, at most 20 constrained claims with at most 50 values of at most 256 bytes each.

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
  "algorithms": ["RS256"],
  "claim_mapping": {"user_id": "oid", "email": "email", "email_verified": "xms_edov", "name": "name"},
  "propagate_claims": ["auth_time"],
  "claim_constraints": {"tid": ["11111111-2222-3333-4444-555555555555"]},
  "max_token_age_seconds": 600,
  "jwks_cache_ttl_seconds": 300,
  "source": "admin",
  "source_ref": "",
  "enabled": true,
  "first_contact": "off",
  "first_contact_project_id": "",
  "first_contact_owner_user_id": "",
  "first_contact_credential_policy_id": ""
}
```

Only `kind` and `issuer` are always required; `claim_mapping.user_id` (person) is required unless a preset fills it, and `audiences` is required on a workload row.
`jwks_uri` is not accepted (422, an unknown field): it comes from the issuer's discovery document.
A person row needs no audiences: add each agent with a binding (below), whose subject key is its app id.
The discovery document and the JWKS are fetched before the row is written; a refusal is a 422 with a `discovery_*` or `jwks_*` code.
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
  "first_contact": "off",
  "first_contact_project_id": "",
  "first_contact_owner_user_id": "",
  "first_contact_credential_policy_id": "",
  "first_contact_updated_by": "",
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

Any of `display_name`, `audiences`, `algorithms`, `claim_mapping`, `propagate_claims`, `claim_constraints`, `max_token_age_seconds`, `jwks_cache_ttl_seconds`, `trust_email`, `enabled`, `first_contact`, `first_contact_project_id`, `first_contact_owner_user_id`, `first_contact_credential_policy_id`; absent fields are unchanged.
An empty `first_contact_project_id`, `first_contact_owner_user_id` or `first_contact_credential_policy_id` clears it. Switching `first_contact` to `off` keeps the project and the owner, and switching it to `off` or `discover` clears `first_contact_credential_policy_id`, which applies to `adopt` only; switching back to `adopt` does not restore it. A row that keeps its policy moves only to a project that policy belongs to: name a policy of the new project in the same patch, or clear it.
A patch that changes any of the four records its caller in `first_contact_updated_by`, which is read-only.
`issuer`, `kind`, `source` and `jwks_uri` never change through PATCH (an unknown field is a 422).
Neither do `claim_mapping.user_id`, `claim_mapping.email` and `claim_mapping.email_verified`: they decide who a token's person is, and remapping one to a claim an IdP user can set (`upn`, `preferred_username`) would let that user take over an existing link (nOAuth).
A `claim_mapping` patch replaces the whole map, so it must repeat those three unchanged; otherwise it is 422 `claim_mapping_immutable`. Delete and re-create the issuer to change them.
The whole row is re-validated and re-checked for uniqueness, except for a patch that changes only `display_name` and the first-contact fields (which are checked on their own) and/or disables the row, so rows stay manageable when the deployment's rules move under them (an issuer dropped from the shared list leaves rows in several accounts that can still be renamed and disabled).
Any patch that enables a row is re-checked, so a row stranded in conflict cannot be re-enabled.
`if_updated_at` (the row's `updated_at` as last read) makes the patch conditional: it applies only while the row is unchanged since then, checked under the issuer lock every writer takes, else 409 `issuer_changed`. A deployer that checked a row before enabling it, as for a workload row's proof of control, enables exactly the row it checked.
A workload create refused with 409 `issuer_already_trusted` is logged as a warning (account, issuer, actor): the first account to add an issuer holds it, so it can be a rightful customer blocked by a squatter's row, for an operator to resolve.

### `POST /external-issuers/{id}/refresh` → 200

Re-reads the issuer's discovery document and, when it names a different `jwks_uri`, probes that key set and moves the row to it.
The response is the issuer with `jwks_check`; a discovery or key-set refusal is the same 422 as on create.

### `DELETE /external-issuers/{id}` → 204

Soft-deletes the row and its bindings (`deleted_at`; audited as `DELETE_*`).
They disappear from every read and grant at once, and stop holding the issuer: the same account, or another, may trust it again.
An identity that is hard-deleted (only a purge of a never-adopted discovered identity does that) takes its bindings with it.

### `POST /external-issuers/check` → 200

```json
{"issuer": "https://acme.okta.com"}
```

Runs what a create would fetch: the discovery document, then the key set it names.
The answer is a probe result, never an upstream body:

```json
{"jwks_uri": "https://acme.okta.com/oauth2/v1/keys", "reachable": true, "key_count": 1, "kids": ["k1"], "checked_at": "..."}
{"reachable": false, "key_count": 0, "kids": [], "error": "discovery_issuer_mismatch", "checked_at": "..."}
```

`error` is one of the `discovery_*` or `jwks_*` codes above.
Only an invalid issuer URL is a 400.

### `GET /external-issuers/{id}/discovery` → 200

The sign-in endpoints of a `person` row, for a deployer starting an authorization-code sign-in through the issuer (the ownership proof above).
ZeroID re-reads `{issuer}/.well-known/openid-configuration` with the same fetch a create uses: the SSRF-guarded client (a private address refused unless `federation.allow_private_endpoints`), a 10-second timeout, no redirects, a 256 KiB cap, and the document's `issuer` equal to the row's exactly.

```json
{
  "issuer": "https://login.microsoftonline.com/1111.../v2.0",
  "authorization_endpoint": "https://login.microsoftonline.com/1111.../oauth2/v2.0/authorize",
  "token_endpoint": "https://login.microsoftonline.com/1111.../oauth2/v2.0/token"
}
```

Both endpoints must be absolute https URLs with no userinfo, query or fragment (http only with `allow_private_endpoints`), or the answer is 422 `discovery_invalid`.
An endpoint with a query (Azure AD B2C's `?p=<policy>`) is refused; such an issuer cannot be a row anyway, since its `jwks_uri` carries the same query.
A fetch failure is the create's 422 (`discovery_unreachable`, `discovery_issuer_mismatch`, `discovery_invalid`).
A `workload` row is 422 `wrong_kind`; another account's row is 404.
A disabled row still answers, so a deployer can prepare a sign-in before enabling it; `/verify-id-token` refuses it.
Nothing is stored: the row's `jwks_uri` changes only through `/refresh`.

### `POST /external-issuers/{id}/verify-id-token` → 200

```json
{"id_token": "<the ID token from the sign-in>", "client_id": "<the verification app's client id>", "nonce": "<the nonce sent on the authorization request>"}
```

All three are required: `id_token` at most 16384 bytes, `client_id` and `nonce` at most 512 (400 `invalid_request` otherwise).
A body of 32 KiB or more is refused with 413, and a refusal before the handler runs (malformed JSON, or a missing or unknown field: 400 or 422 with no `code`) redacts every echoed value, so the token never comes back.
ZeroID verifies the token under this row with the routine the ID-token exchange (P1c) runs, so it accepts nothing the exchange's token checks would refuse:

- the row is `person` (else `wrong_kind`) and enabled (else `issuer_disabled`), checked before the token is read;
- the signature, against the row's JWKS (an unknown `kid` triggers the same single-flight refresh), with an algorithm on the row's list;
- `iss` equal to the row's issuer; `exp`, `nbf` and `iat` with the 60-second skew; `iat` within `max_token_age_seconds`; `sub` present;
- an ID token, not an access token (rule 2 of P1c);
- `aud` containing `client_id`, `azp` (when present) a string equal to it, and several audiences only with `azp`;
- the row's claim constraints, including a shared issuer's pinning claim, on the verified claims;
- the mapped `user_id` present, and the subject a person (rule 3 of P1c);
- and, beyond P1c, a `nonce` claim equal to `nonce`, compared in constant time.

It needs no binding (the verification app is not an agent), mints nothing, and records no `jti`: the token is only read, and the deployer makes its own record single-use.
The answer is the person as the row's claim mapping reads them, exactly as P1c hands them to the person resolver:

```json
{
  "issuer_id": "6f1d...",
  "issuer": "https://login.microsoftonline.com/1111.../v2.0",
  "subject": "<claim_mapping.user_id, e.g. the Entra oid>",
  "email": "owner@contoso.com",
  "email_verified": true
}
```

`email_verified` is true when the claim `claim_mapping.email_verified` names (default `email_verified`; `xms_edov` with the Entra preset) is JSON `true` or the string `"true"` or `"1"`, or, on a row with `trust_email`, when that claim is absent and the token carries an email.

A refused token is 422 with one of these codes, and never the token, its claims, or why in more detail (the log line has the account, the row and the code only):

| `code` | When |
|---|---|
| `token_invalid` | Malformed, a disallowed algorithm, a bad signature or unknown key, `iss` not the row's, expired or not yet valid, too old, no `sub`/`exp`/`iat`, an access token, no mapped `user_id`, or a workload subject |
| `audience_mismatch` | `client_id` is not in `aud`, `azp` names another party or is not a string, or several audiences and no `azp` |
| `constraint_mismatch` | The verified claims do not satisfy the row's claim constraints |
| `nonce_mismatch` | The token has no `nonce` claim, or not this one |
| `issuer_disabled` | The row is disabled |
| `wrong_kind` | The row is a `workload` row |
| `jwks_unreachable` | The row's key set could not be loaded (not the token's fault) |

Another account's row is 404.

### `POST /external-issuers/{id}/verify-workload-token` → 200

The proof of control for a `workload` row (ADR 0042 open question 8).
The deployer issues a one-time challenge; the account mints a token from its issuer for that audience and nothing else, for example `aws sts get-web-identity-token --audience <challenge>`, `kubectl create token <sa> --audience <challenge>`, a SPIFFE JWT-SVID for it, or `core.getIDToken('<challenge>')` in a GitHub Actions workflow; and the deployer has ZeroID verify it here.

```json
{"token": "<a token from the issuer>", "audience": "<the challenge>"}
```

Both are required: `token` at most 16384 bytes, `audience` at most 512 (400 `invalid_request` otherwise).
A body of 32 KiB or more is refused with 413, and a refusal before the handler runs redacts every echoed value, as on `/verify-id-token`.
ZeroID verifies the token under this row with the routine a federated client assertion (P2) runs:

- the row is `workload` (else `wrong_kind`); a **disabled row is accepted**, since a row waits disabled for this proof;
- the signature, against the row's JWKS, with an algorithm on the row's list;
- `iss` equal to the row's issuer; `exp`, `nbf` and `iat` with the 60-second skew; `iat` within `max_token_age_seconds`, and the whole lifetime (`exp` − `iat`) within it too; `sub` present;
- the row's claim constraints, including a shared issuer's pinning claim, on the verified claims, so a row pinning another customer's `repository_owner` cannot be proven; and a shared issuer's row must pin **exactly one** value (else 422 `pin_not_single`), since a token carries one and a proof with one value must not stand for a row that also pins another customer's;
- `aud` exactly `[audience]`: one value, the challenge.

`audience` itself must not be one of the row's `audiences` or ZeroID's own issuer (422 `audience_not_a_challenge`), so an ordinary P2 assertion, captured in transit, never stands in for the proof.
It needs no binding, mints nothing and records no `jti`; the deployer makes its challenge single-use.

```json
{"issuer_id": "6f1d...", "issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/ABC...", "subject": "system:serviceaccount:agents:planner"}
```

A refused token is 422 with one of `token_invalid`, `audience_mismatch` (`aud` is not exactly the challenge), `constraint_mismatch`, `wrong_kind` or `jwks_unreachable`, and never the token or its claims.
Another account's row is 404.

An issuer whose tokens cannot name an arbitrary audience (an Entra or Okta access token's `aud` is fixed by its resource) cannot answer the challenge; the deployer may accept its `person` row's sign-in proof instead (see the deployer's rules).

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
  "subject_key": "<agent app id, or the ID-JAG act.sub (its client_id when it has no act)>",
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
  "explicitly_disabled": false,
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
{"enabled": true, "only_if_not_explicitly_disabled": true}
```

`{"enabled": false}` sets `explicitly_disabled`; a plain `{"enabled": true}` clears it (an admin's own decision).
The deployer enables an agent's bindings at adoption with `only_if_not_explicitly_disabled: true`: the enable is applied in one statement only where `explicitly_disabled` is false, so it cannot undo an admin's disable even when the two race, and it is 409 `binding_explicitly_disabled` otherwise.
Either enable needs the identity to be `active` (409 `identity_not_active`).

### `DELETE /external-issuers/{id}/bindings/{binding_id}` → 204

Soft-deletes the binding.
It keeps the OAuth client that `oauth_client` created, and that client stays linked to the identity.

### Moving an IdP app to another identity

A client belongs to one identity, and `client_id` is unique, so binding the app to another identity with `oauth_client` is 409 `client_conflict` while the old identity's client exists.
Free the client id first, then bind:

1. `DELETE /external-issuers/{id}/bindings/{binding_id}` for the old identity's binding (at most one binding per issuer and subject key is enabled).
2. `GET /identities/{old_identity_id}/oauth-clients` lists the clients linked to the old identity. Take the client's `id` (its UUID), not its `client_id`.
3. `DELETE /identities/{old_identity_id}/oauth-clients/{client_uuid}` → 200 deletes it. It is 404 when the identity is not in the caller's tenant, or when the client is linked to another identity or to none, so a tenant can remove only its own identities' clients. An approval-channel client is removed only from a trusted approval-channel context (403 otherwise).
4. `POST /external-issuers/{id}/bindings` with the new identity and `oauth_client`.

Deactivating an identity (`DELETE /identities/{id}`) keeps its clients linked, because deactivation can be undone. Step 3 works on a deactivated identity too.
A hard delete of an identity also deletes the clients linked to it (`ON DELETE CASCADE`, migration 061), which frees their client ids. Two paths hard-delete an identity: purging a discovery source (`POST /identities/discovered/purge-source`), and the rollback of a registration that failed part-way.
Clients that an older release left unlinked when their identity was hard-deleted are not covered here; see #453.

## Migration ordering

The tables are migration 056. The first-contact columns and their CHECK constraint are migration 069; `first_contact_updated_by`, `first_contact_updated_at` and the binding index the rate limit reads are migration 070; `first_contact_credential_policy_id`, the CHECK that allows it on `adopt` rows only, and its place in the issuer audit documents are migration 075.
Migration 055 (the refresh-token family, PRs #421 to #423) must be applied before it: golang-migrate never applies a version below the database's current one, so a database that reached 056 first would silently skip 055.
If this change merges before 055, renumber it at merge.

## Audit

Every insert, update and delete of a row or binding writes `identity_audit_logs` (`table_name` `external_issuers` or `external_issuer_bindings`, actions `INSERT_EXTERNAL_ISSUER`, `UPDATE_EXTERNAL_ISSUER`, `DELETE_EXTERNAL_ISSUER`, `INSERT_ISSUER_BINDING`, ...), with the actor from `X-User-ID` and the binding's identity as `identity_id`.
An issuer row's audit documents include `first_contact`, `first_contact_project_id` and `first_contact_owner_user_id` (migration 069) and `first_contact_credential_policy_id` (migration 075), so who set `adopt`, and with which mapping, is kept.
The row also carries the last of those changes as `first_contact_updated_by` and `first_contact_updated_at`.
What first contact writes names `system:first_contact` as the actor: a registration's identity and binding, and a standing adoption's `discovered → active` transition and binding enable. The transition's audit row carries `metadata.first_contact_adoption`, naming the row, the credential policy it assigned and who last set its mapping, and the identity's new `credential_policy_id`.

## Running it locally

`cmd/zeroid-mockidp` serves an Entra-shaped tenant, an Okta org and a Kubernetes issuer and mints every token shape above; see its [README](../cmd/zeroid-mockidp/README.md).
`tests/integration/trusted_issuers_test.go` drives both person paths and every INV-IDN-014 refusal against it.

## Not yet

- Every issuer row needs OpenID discovery at `{issuer}/.well-known/openid-configuration` (Entra, Okta, Google, GitHub Actions, AWS STS and Kubernetes service-account issuer discovery all serve it). An issuer without it, such as a bare SPIFFE trust-domain bundle endpoint, cannot be a row yet.
- The connector "Trust for agent access" toggle (ADR 0042 open question 7) is not built; `source: connector` rows can be written through the API.
- Proof of issuer control (open question 8): the first account to add a customer-unique issuer holds it. For `person` rows the deployer gates person resolution on an ownership proof (`/discovery` and `/verify-id-token` above); for `workload` rows, including a shared issuer's pinning value, it enables a row only after a challenge token verifies under it (`/verify-workload-token` above). ZeroID does not enforce either itself: a row written enabled through this API mints.
- Account lifecycle (D4a follow-up a): deleting an account in Admin does not yet remove its rows.
- First contact maps a row to one project, one owner and, optionally, one credential policy. Labels or tags from the mapping are not built, and changing a row's policy does not reach agents it adopted before. Nor is first contact on the ID-token exchange, or an inventory sync naming a subject by anything but `metadata.issuer_binding`. A standing adoption adopts only into the row's own project, and enables only the binding the credential arrived through.
- JWKS refreshes on an unknown `kid` are rate-limited per key set (one every 10 seconds), and rows that share a `jwks_uri` share the key set. Tokens with made-up `kid`s, presented on the ID-token exchange or on `/verify-id-token`, can hold that slot, so a real key rotation at the IdP is picked up up to 10 seconds late for every account on the key set.
