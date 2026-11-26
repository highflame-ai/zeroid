# Scope ceilings: the identity's allowed_scopes and credential policies

**Decision.** An identity's `allowed_scopes` is the absolute ceiling of the
scopes any token for that identity can carry. Credential policies are reusable
bundles that only narrow within it. Every layer narrows, none widens, and the
scopes a token gets are the request intersected with every layer that
restricts. The field is not deprecated.

## What the scopes are

`allowed_scopes` holds ZeroID scope strings: the vocabulary of the resource
servers that accept ZeroID tokens, such as `tools:execute`, `nhi:manage` or
`session:dispatch`. It is chosen by whoever registers the identity (an admin, a
platform that mints agents at runtime, or a developer through the SDK) and is
not derived from any user or downstream provider.

It says nothing about a downstream provider's own scopes. When an agent reaches
GitHub through a gateway, the GitHub token's scopes are decided by GitHub's
authorization server when the user consented; ZeroID can neither see nor
narrow them. Restricting what an agent does there is done at the gateway: the
agent presents its ZeroID token, the gateway decides each tool call (see
"Where scopes are checked") and attaches the provider token only if allowed.
Where a provider supports down-scoping (GitHub App installation tokens limited
to chosen permissions and repositories, or STS-style down-scoping), the
gateway can also hand it a narrower token per agent.

## Why a per-identity ceiling is correct

- **RFC 7591 §2** gives every registered client a `scope` metadata value: "the
  scope values that the client can use when requesting access tokens". A
  per-identity ceiling fixed at registration is the standard shape;
  `allowed_scopes` is ZeroID's equivalent.
- **RFC 6749 §3.3** lets the authorization server issue fewer scopes than
  requested, by its own policy. Applying the ceiling and then policy bundles is
  such a policy.
- **RFC 8693** bounds a delegated token by its subject token. That is one more
  narrowing layer for delegation, applied together with the actor's own
  ceiling, never instead of it.
- **RFC 9068 §2.2.3.1** keeps `scope` (what was delegated) apart from
  `roles`, `groups` and `entitlements` (who the subject is). A person's roles
  belong in those claims; they do not replace an identity's ceiling.

The same layering is how established authorization servers work:

| System | Per-identity ceiling | Reusable bundle | Effective scopes |
|---|---|---|---|
| Auth0 | client grant (scopes per client, per API) | roles with permissions | intersection |
| Okta | granted scopes per service app | access-policy rules | intersection |
| Keycloak | the client's assigned scopes, with "full scope allowed" off | client scopes, realm roles | client scopes ∩ the user's role mappings |
| Microsoft Entra | app-role assignment per service principal | app roles | the assigned set |

Earlier releases marked the field deprecated because the grants disagreed
about it: some read it only when the policy set no scopes, while issuance and
CIBA enforced it unconditionally, so one check could approve what another
refused. The defect was the inconsistency, not the field. The layers are now
composed in one place (`grantScopes`), and token issuance re-checks the
ceiling.

## The model

Layers, each optional; an empty layer places no restriction, except an
identity's own `allowed_scopes` when the identity was registered by another
identity (it has a parent): there an empty list means the identity holds no
scope ([identity-tree.md](identity-tree.md#empty-means-no-scope)):

| Layer | Applies to |
|---|---|
| The identity's `allowed_scopes` | every token for the identity: the absolute ceiling. Empty on an identity with a parent: no scope |
| The identity's credential policy `allowed_scopes` | every token for the identity, except a chain acting for a person |
| The credential policy's `user_grant_scopes` | a token-exchange hop whose chain acts for a person, in place of the policy's `allowed_scopes` (empty: no extra cap from the policy) |
| The API key's scopes and its own credential policy | `api_key` tokens |
| The OAuth client's registered scopes | `client_credentials` and `authorization_code` |
| The subject token's scopes | token exchange: a child never exceeds its parent |
| The person's grant (resolver, IdP, consent) | tokens minted for a person |
| The person's ceiling (`PersonGrantResolver`, below) | a person's own token, when the deployer installs one |

Rules:

- A token's scopes are the request intersected with every restricting layer.
- A request that names no scope defaults to the first restricting layer,
  narrowed by the rest. Token exchange has no default: the scopes to delegate
  must be named. A child whose `allowed_scopes` is empty has no default: an
  omitted request is issued a token with no `scopes` claim, since it holds
  no scope.
- A grant whose layers leave nothing is refused with `invalid_scope`. A token
  is never minted without a `scopes` claim because the layers were disjoint.
  The one scopeless token a restricting layer allows is the one above: an
  omitted request from a child that holds no scope.
- No token ever carries a scope outside the identity's `allowed_scopes`.

A deployment can make the default, the empty layer and narrowing stricter,
counting what that would change before enforcing it; see
[Stricter scope rules](#stricter-scope-rules).

## Where scopes are checked

- **The issuer bounds.** ZeroID enforces the layers above when it mints:
  once when the grant computes its scopes, and again in the issuance
  chokepoint, so the two cannot disagree.
- **The resource server decides.** Whether a token's scopes suffice for a
  request is the resource server's call (RFC 6750 §3.1, `insufficient_scope`;
  RFC 9068 §4). A service that accepts ZeroID tokens directly checks the scope
  its own endpoint needs.
- **The gateway decides through policy.** For calls a gateway forwards to a
  third party, the token's scopes are available to the policy decision point as
  `context.principal.scopes` (Cedar), together with the actor chain and the target, so
  a tenant can condition a tool call on them. A hardcoded table mapping actions
  to scopes is not used: a request does not reveal which scope it "needs".
  Resource binding (RFC 8707: a token bound to one server cannot be used at
  another) stays a hard check before policy.

## Scenarios

| Scenario | Behaviour |
|---|---|
| Registration (`POST /identities`, `PATCH /identities/{id}`, `POST /agents/register`) | Stores the ceiling. No check that it is a subset of the policy, or the reverse: the intersection at issuance makes either order safe |
| Registration by an identity acting as itself (a child), and changes to a child's ceiling | Where the request names none, the child takes the scopes both its parent's ceiling and the parent's token hold (possibly none), and the parent's credential policy (or the narrower of it and the presented API key's). Its ceilings must stay within the parent's and the token's, and a named policy must be a subset of the parent's, and of the presented key's, on every axis: anything else is refused with `400`. Clearing a child's `allowed_scopes` narrows it to no scope and is accepted ([identity-tree.md](identity-tree.md)) |
| A child whose `allowed_scopes` is empty | Holds no scope on every grant and in every `token.scope_rules` mode: a named scope is refused as an unlisted one is, an omitted request is issued a token with no `scopes` claim, a token exchange delegates it none, and an API key for it cannot list a scope (`400`) |
| API key with its own policy | The key's policy must be a subset of the identity's policy; the identity ceiling then applies on top. A key for a child may list only scopes the child's `allowed_scopes` lists |
| `client_credentials`, `jwt_bearer`, `api_key` | Scopes = request ∩ client or key scopes ∩ key policy ∩ identity policy ∩ identity ceiling; an omitted request gets the narrowest layer; nothing left is refused |
| `client_credentials` with a federated client assertion | No client or key scopes, so: request ∩ identity policy ∩ identity ceiling. An agent with neither set is refused with `invalid_scope` ([external-issuers.md](external-issuers.md)) |
| Token exchange (agent to sub-agent) | Scopes = request ∩ the subject token's scopes ∩ the actor's policy ∩ the actor's ceiling; every hop narrows; a denial names the layer that excluded each scope. When the chain acts for a person, the actor's policy term is its `user_grant_scopes`; the actor's ceiling still binds |
| `authorization_code`, refresh, ID-JAG, ID-token exchange, broker exchange, CIBA | Scopes come from the person's grant and the client; when an identity is linked, a requested scope outside its ceiling or policy is refused at issuance rather than narrowed. With a person-grant resolver in enforce mode they are also narrowed to the person's ceiling |
| A person's role is reduced | The next refresh is narrowed to the new ceiling, or refused with `invalid_grant` without consuming the refresh token; restoring the role restores the family's scopes |
| CIBA step-up into a requesting chain (`requesting_token`) | Scopes = the requesting token's scopes: `openid` or no scope keeps them, other named scopes narrow to those, and a named scope the chain does not hold is refused. The requesting identity's ceiling and policy are re-checked against the current layers (its `user_grant_scopes` when the chain acts for a person), and a scope now outside them is refused. A requesting token with no identity is bounded by the polling client's bound identity instead |
| Refresh after a ceiling or policy changed | The refreshed token is re-checked against the current layers; a scope now outside them fails the refresh |
| Ceiling or policy changed with tokens outstanding | Issued tokens keep their scopes until they expire; new grants and new delegations use the current layers |
| No layer restricts | An omitted request mints a token without a `scopes` claim, as before. A child's empty `allowed_scopes` is a layer that restricts (to nothing), so this row never applies to a child |

## A person's ceiling

ZeroID does not know a deployer's roles, so it cannot decide which scopes a
person may hold. A deployer that can supplies a `PersonGrantResolver` with
`Server.SetPersonGrantResolver(fn, mode)`. Highflame's deployment uses it to
apply each role's scopes (ADR 0041 D15).

**Which tokens.** Every grant that mints for a person consults it:
`authorization_code`, `refresh_token`, a root CIBA grant, ID-JAG, ID-token
exchange and the trusted external-principal exchange. These are the tokens
whose `principal_type` ZeroID derives as `user` itself. Token exchange and a
CIBA step-up into an existing chain carry that chain's principal; they are
bounded by the chain (RFC 8693) and never consult the resolver.

**What it returns.** For each mint the resolver gets the grant type, tenant,
person (`sub` and the issuer that vouched for them), client, audience, the
requested scopes (after every other layer narrowed them, or their default)
and, on the external-principal exchange only, the role the trusted service
asserted. It returns a ceiling and the person's roles.

On ID-JAG and the ID-token exchange, when a federated person resolver is
installed (`Server.SetFederatedPersonResolver`, ADR 0042 D5a), it runs first:
the person this resolver sees is the deployer's user it returned, not the IdP
subject, which the token carries as `user_idp_iss`/`user_idp_sub`
([external-issuers.md](external-issuers.md#person-resolution)).

The resolver runs on the token request's path, under its context. It must
honour the context's deadline and cancellation, and should cache role
lookups: a slow resolver slows every person mint, and in enforce mode one
that fails or times out refuses them.

`GrantType` is one of these constants. The two token exchanges share a grant
type, so they are named by the value of their tokens' `token_exchange` claim.

| Grant | Constant | Value |
|---|---|---|
| `authorization_code` | `PersonGrantAuthorizationCode` | `authorization_code` |
| `refresh_token` | `PersonGrantRefreshToken` | `refresh_token` |
| Root CIBA | `PersonGrantCIBA` | `urn:openid:params:grant-type:ciba` |
| ID-JAG | `PersonGrantIDJAG` | `jwt_bearer` |
| Trusted external-principal exchange | `PersonGrantExternalPrincipal` | `external_principal` |
| ID-token exchange | `PersonGrantExternalIDToken` | `external_id_token` |

**Modes.**

| Mode | Scopes issued | A request the ceiling leaves empty | Resolver error |
|---|---|---|---|
| `off` (default) | unchanged; the resolver is not called | issued | — |
| `shadow` | unchanged | issued | issued |
| `enforce` | request ∩ ceiling | refused | refused (`server_error`) |

`SetPersonGrantResolver` rejects a nil resolver with shadow or enforce, and
an empty or unknown mode, leaving the hook as it was; only an explicit `off`
removes it, so a wiring mistake cannot turn the ceiling off unnoticed.

In shadow and enforce, a narrowing, a refusal and a resolver error are
counted in `zeroid_person_scope_ceiling_total` (by mode and outcome) and
logged as `person_scope_ceiling_violation`. The metric counts decisions, not
tokens: in enforce mode an `authorization_code` is decided at
`/oauth2/authorize` and again at the token endpoint, and a refused request
that is retried is decided again. Shadow lets a deployer see who
enforcement would affect before turning it on.

**Rules.**

- An empty ceiling grants nothing. This differs from `Principal.Scopes` and
  the other layers, where empty means no restriction (except a child
  identity's own `allowed_scopes`, which also grants nothing when empty): a
  person with no role holds no scopes.
- `openid` asks for authentication, not authority, so the ceiling never
  removes it, and a request for `openid` alone is never refused.
- Refusals, by where they happen:

  | Grant | The ceiling leaves nothing | The resolver fails (enforce) |
  |---|---|---|
  | `/oauth2/authorize` (enforce only) | `invalid_scope` (RFC 6749 §4.1.2.1) | `server_error` |
  | `authorization_code`, `refresh_token` at the token endpoint | `invalid_grant`: the grant's authority changed after consent, so the client should re-authorize | `server_error` |
  | Root CIBA, ID-JAG, ID-token exchange, external-principal exchange | `invalid_scope` (RFC 6749 §5.2) | `server_error` |

  Every grant decides before consuming its single-use credential (the code,
  the refresh token, the approved `auth_req_id`, the ID-JAG `jti`), so a
  refused request can be retried once the role is restored. A CIBA push-mode
  client cannot poll, so it is sent the refusal at its notification endpoint
  as a CIBA Core §12 error: `access_denied`, or `transaction_failed` when the
  resolver fails (§12 defines no other codes).
- A refresh family keeps the scopes the person consented to. Each refresh
  applies the current ceiling, so a role change takes effect at the next
  refresh. Outstanding access tokens keep their scopes until they expire.
- An enforced ceiling bounds a person's root for the ceiling rule, so such a
  root is no longer counted in `zeroid_workload_unbounded_scope_total`.
- The resolver's roles are stamped as the RFC 9068 §2.2.3.1 `roles` claim on
  the person's own token, in shadow and enforce. Tokens delegated from it do
  not inherit them, and no caller can set `roles`.

## Stricter scope rules

Four rules make issuance stricter: scopes someone chose, listed by a ceiling
the deployer controls, issued whole or not at all, and refused with one error
code. They are selected with `token.scope_rules` (env `ZEROID_SCOPE_RULES`), or
at runtime with `Server.SetScopeRulesMode`:

| Mode | Evaluated | Tokens and responses |
|---|---|---|
| `off` (default) | no rule; nothing is logged or counted | unchanged |
| `shadow` | every grant, against each rule below; each change is recorded | unchanged |
| `enforce` | the same evaluation, applied; each change is recorded | as the rules below say |

An empty value means `off`. Any other value is refused, by config validation
at startup and by `SetScopeRulesMode` (which also refuses an empty mode), so a
typo never runs as `off` unnoticed. A request keeps the mode it started with.

**Rollout.** Go from `off` to `shadow`, and read what is recorded: every
record is a request that `enforce` would answer differently, with the outcome
it would get. List the scopes that should keep working (on the identity's
`allowed_scopes`, its credential policy, the API key, or a client created
through the admin API), make clients name the scopes they need, and switch to
`enforce` once shadow records only what should change. `enforce` can be
switched back to `shadow` or `off` at runtime without a restart.

**The rules.** Each rule is judged on its own against what today's rules did
with the request.

| Rule | Recorded as | In `enforce` | Today (`off` and `shadow`) |
|---|---|---|---|
| A, omitted request | `omitted_request` | A request that names no scope is issued only the scopes stored on the API key it exchanges (`api_key`) or an audience profile's scopes (the trusted external-principal exchange), and otherwise none. A request refused today stays refused. | An omitted request gets the client's registered scopes on `authorization_code` (for a client identified by a metadata document, the scopes the document publishes) and the first restricting ceiling on the self-mint grants. |
| B, listing | `listing` | A scope is issued only when at least one ceiling the deployer controls lists it: the API key's scopes or the key's own credential policy, the identity's `allowed_scopes`, the governing credential policy's ceiling (`allowed_scopes`, or `user_grant_scopes` for a chain bounded by a person's grant), or the registered scopes of a client created through the admin API. A client's own metadata (a metadata document's `scope`, or a dynamically registered client's `scope`) is a request, never a listing. An empty ceiling neither lists nor excludes, except a child identity's empty `allowed_scopes`, which lists nothing and excludes everything; issuance applies that itself, so the rule never counts it as a change. | An empty ceiling places no restriction, so a scope nothing lists is granted. |
| C, all or nothing | `all_or_nothing` | A request is issued every scope it names, or refused whole with `invalid_scope`. A delegation (RFC 8693) that names no scope is issued none. | A named scope is dropped silently where a layer narrows (delegation, the self-mint grants, an enforced person ceiling). A delegation that names no scope is refused. |
| D, one code | `one_code` | Every scope refusal at the token endpoint answers `invalid_scope`. | A scope refusal answers `invalid_scope`, `insufficient_scope` (outside the identity's `allowed_scopes`), `policy_violation` (outside a credential policy), `invalid_grant` (a person ceiling at the token endpoint) or `access_denied` (a CIBA policy refusal, or a person ceiling sent to a push client). |

`openid` asks for authentication, not authority. It is never counted as a
scope that was dropped, unlisted or issued by default.

**What each grant asks for.**

| Grant | The request | Notes |
|---|---|---|
| `authorization_code` | The authorization request's `scope` | Rules A and C are judged when `/oauth2/authorize` issues the code, where an omitted or narrowed request is visible. Rule C is judged again at redemption when a person ceiling narrows the code's scopes. Rules B and D are judged when the code is redeemed, where the code's scopes are the request. |
| `refresh_token` | The family's scopes | An omitted scope repeats the grant (RFC 6749 §6), so rule A does not apply. Rule C applies when a person ceiling narrows the family's scopes. An audience-profile family's scopes are server-defined and so listed. |
| `api_key` | `scope` | Rule A keeps the key's stored scopes as the default. |
| `client_credentials`, self-signed `jwt_bearer` | `scope` | |
| Token exchange (delegation) | `scope` | Rule C, not rule A, covers a delegation that names no scope. |
| Trusted external-principal exchange | `scope`, or the audience profile | A profiled audience's scopes are the request, kept by rule A and listed for rule B. |
| ID-token exchange | `scope` | |
| ID-JAG | The ID-JAG's `scope` claim | The IdP's grant is a request to ZeroID, not a listing it controls. |
| CIBA | The bc-authorize request's `scope` | A step-up into a requesting chain that names no scope beside `openid` keeps the chain's scopes today; rule A treats it as a request that names none. Push-mode mints are judged too; their recorded code is the one the token endpoint would answer, and a push client is sent a callback only for a person-ceiling refusal. |

Grants registered with `RegisterGrant` are not evaluated, nor is issuance that
is not an OAuth grant: the admin issue and rotate endpoints and attestation.

The internal service grants (the on-behalf exchange and the asserted-tenant
grant) record nothing. Only the deployment's own services can use them, they
refuse a `scope` parameter with `invalid_scope`, and their tokens carry no
scopes, so no client chooses a scope there and every rule would answer as
today. A session broker's external-principal exchange and a
`client_credentials` request into the service tenant are evaluated like any
other request on those grants.

**Reserved scopes.** A scope under a prefix reserved with
`Server.SetReservedScopes` is governed by the reserved-scope rules and the
deployer's authorizer, not by ceilings. For rule A it is one of the API key's
own scopes, which the rule keeps. Rules B and C do not judge it: it is never
counted as unlisted, nor as dropped from a request. A request the
reserved-scope rules refuse (the key does not list the scope or names no
creator, the authorizer refuses or fails, or another grant asks for a
reserved scope) records nothing.

**Enforcement.** With `enforce`, the evaluation shadow mode records decides
the outcome, so the two modes never disagree about a request: a request shadow
records nothing for is answered exactly as with `off`, and every request
`enforce` answers differently is recorded. The rules' changes combine as
follows:

- A request that names no scope loses the default it was given (rule A). It
  keeps `openid`, the API key's own scopes (reserved scopes included) and an
  audience profile's scopes, and still succeeds; with nothing left, its token
  has no `scopes` claim. A refresh repeats its family's scopes.
- A request today's rules refuse stays refused. Enforcement never turns a
  refusal into a token without a `scopes` claim. The one exception is rule
  C's: a delegation that names no scope is issued with no `scopes` claim.
- Otherwise the request is refused whole when a scope it would be issued is
  one no deployer-controlled ceiling lists (rule B), or when a scope it named
  would be dropped (rule C). In a delegation the subject token's scopes are one
  more ceiling. Nothing is narrowed silently, and no rule adds a scope.
- Every scope refusal at the token endpoint answers `invalid_scope` (RFC 6749
  §5.2), as does a refusal at `/oauth2/authorize` (RFC 6749 §4.1.2.1). The
  `error_description` names the first offending scope, in the order the
  request named them, and the ceiling that must list it, without quotes
  (RFC 6749 §5.2 keeps `"` out of the description):

  | Cause | `error_description` |
  |---|---|
  | A ceiling left the scope out (rule C, or a refusal a ceiling explains) | `scope tools:write is not granted: the identity's allowed_scopes must list it` |
  | No ceiling lists it (rule B) | `scope tools:write is not granted: no scope ceiling an administrator controls lists it; list it in the API key's scopes or the identity's allowed_scopes` |
  | No deployer-controlled ceiling applies (rule B) | `scope tools:write is not granted: no scope ceiling an administrator controls applies to this request, so none lists it` |

  The ceilings a description names are the client's registered scopes (or
  the client metadata document's scope), the identity's `allowed_scopes`, a
  credential policy's `allowed_scopes` or `user_grant_scopes` (the
  identity's, the tenant's default, the API key's, the actor's, a requesting
  or bound identity's), the API key's scopes, the subject token's scopes, a
  requesting token's scopes, the person's scope ceiling and the authenticated
  principal's scopes. A scope refusal no recorded ceiling explains (a scope
  never issued to an identity type, for one) keeps its own description, under
  `invalid_scope`.
- `insufficient_scope` stays where a resource server refuses a token for the
  scope it lacks (RFC 6750 §3.1). Refusals that are not about scopes (grant
  type, trust level, lifetime, an unusable identity or a stopped identity
  tree, client authentication) keep their codes.

Where the outcome is decided:

| Where | What enforcement does |
|---|---|
| `/oauth2/authorize` | Rules A and C decide the code's scopes before the code is built: an omitted request's code carries no default, a narrowed request is refused with `invalid_scope`. Rule B is judged when the code is redeemed. |
| The issuance chokepoint | After every check today's rules make and before anything is signed or stored, rules A, B and C decide the token's scopes. A refused refresh puts the presented refresh token back, as any failed refresh does. A CIBA approval is judged after the approval is consumed, like the chokepoint's other checks. |
| Token exchange | A delegation that names no scope is issued none instead of refused. |
| The token endpoint | Rule D's code and description. |

A CIBA push client is sent CIBA Core §12 codes, which do not include
`invalid_scope`, so rule D is not applied to it: a refusal by the person
ceiling keeps `access_denied`, and that change is not recorded in `enforce`. A
push-mode mint the stricter rules refuse is sent as `access_denied`, with the
description above.

**Exemptions.** In `enforce` exactly as in `shadow`: reserved scopes stay
under the reserved-scope rules (below), and the internal service grants are
not evaluated, so their answers are unchanged.

**What is recorded.** Each rule that would change a request is counted in
`zeroid_scope_rule_would_change_total` (OpenTelemetry
`zeroid.scope.rule_would_change`) by `mode`, `rule`, `grant_type`,
`account_id` and `project_id`, and logged at info as
`scope_rule_would_change`:

| Field | Value |
|---|---|
| `mode` | `shadow`, or `enforce` for a change enforcement made |
| `rule` | `omitted_request`, `listing`, `all_or_nothing` or `one_code` |
| `grant_type` | `authorization_code`, `refresh_token`, `api_key`, `client_credentials`, `jwt_bearer`, `id_jag`, `token_exchange`, `external_principal`, `external_id_token` or `urn:openid:params:grant-type:ciba` |
| `client_id`, `identity_id`, `account_id`, `project_id` | The client and identity the token is for and their tenant, empty when the grant has none or failed before resolving it |
| `requested_scopes` | What the request named |
| `today` | `issued`, with `today_scopes`; or `refused`, with `today_code` |
| `would` | `issued`, with `would_scopes`; or `refused`, with `would_code` (always `invalid_scope`). In `enforce`, the outcome the request was given |
| `unlisted_scopes` | Rule B only: the issued scopes no ceiling lists |

One request can record several rules. A request that fails for a reason other
than its scopes (client authentication, an unusable identity, a policy's TTL
or grant-type axis) records nothing. No token, secret, e-mail address or user
id is logged. `client_id` is in the log and not the metric: a client
identified by a metadata document has a URL as its id, which anyone can
choose, so it would make the metric's cardinality unbounded. Like
`zeroid_person_scope_ceiling_total`, the metric counts decisions: an
authorization request and the code's redemption are judged separately.
