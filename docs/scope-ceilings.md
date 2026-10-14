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

Layers, each optional; an empty layer places no restriction:

| Layer | Applies to |
|---|---|
| The identity's `allowed_scopes` | every token for the identity: the absolute ceiling |
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
  must be named.
- A grant whose layers leave nothing is refused with `invalid_scope`. A token
  is never minted without a `scopes` claim because the layers were disjoint.
- No token ever carries a scope outside the identity's `allowed_scopes`.

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
| API key with its own policy | The key's policy must be a subset of the identity's policy; the identity ceiling then applies on top |
| `client_credentials`, `jwt_bearer`, `api_key` | Scopes = request ∩ client or key scopes ∩ key policy ∩ identity policy ∩ identity ceiling; an omitted request gets the narrowest layer; nothing left is refused |
| Token exchange (agent to sub-agent) | Scopes = request ∩ the subject token's scopes ∩ the actor's policy ∩ the actor's ceiling; every hop narrows; a denial names the layer that excluded each scope. When the chain acts for a person, the actor's policy term is its `user_grant_scopes`; the actor's ceiling still binds |
| `authorization_code`, refresh, ID-JAG, ID-token exchange, broker exchange, CIBA | Scopes come from the person's grant and the client; when an identity is linked, a requested scope outside its ceiling or policy is refused at issuance rather than narrowed. With a person-grant resolver in enforce mode they are also narrowed to the person's ceiling |
| A person's role is reduced | The next refresh is narrowed to the new ceiling, or refused with `invalid_grant` without consuming the refresh token; restoring the role restores the family's scopes |
| CIBA step-up into a requesting chain (`requesting_token`) | Scopes = the requesting token's scopes: `openid` or no scope keeps them, other named scopes narrow to those, and a named scope the chain does not hold is refused. The requesting identity's ceiling and policy are re-checked against the current layers (its `user_grant_scopes` when the chain acts for a person), and a scope now outside them is refused. A requesting token with no identity is bounded by the polling client's bound identity instead |
| Refresh after a ceiling or policy changed | The refreshed token is re-checked against the current layers; a scope now outside them fails the refresh |
| Ceiling or policy changed with tokens outstanding | Issued tokens keep their scopes until they expire; new grants and new delegations use the current layers |
| No layer restricts | An omitted request mints a token without a `scopes` claim, as before |

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
logged as `person_scope_ceiling_violation`. Shadow lets a deployer see who
enforcement would affect before turning it on.

**Rules.**

- An empty ceiling grants nothing. This differs from `Principal.Scopes` and
  the other layers, where empty means no restriction: a person with no role
  holds no scopes.
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
  refused request can be retried once the role is restored.
- A refresh family keeps the scopes the person consented to. Each refresh
  applies the current ceiling, so a role change takes effect at the next
  refresh. Outstanding access tokens keep their scopes until they expire.
- An enforced ceiling bounds a person's root for the ceiling rule, so such a
  root is no longer counted in `zeroid_workload_unbounded_scope_total`.
- The resolver's roles are stamped as the RFC 9068 §2.2.3.1 `roles` claim on
  the person's own token, in shadow and enforce. Tokens delegated from it do
  not inherit them, and no caller can set `roles`.
