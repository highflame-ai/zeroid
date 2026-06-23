# Identity Lifecycle: Discovered → Established → Active → Suspended → Archived

> ZeroID owns the identity model, schema, and lifecycle for every non-human identity on
> the platform — native (we registered it) and discovered (we observed it in a corporate
> IdP). This document defines the lifecycle state machine, **why** it is shaped this way,
> and the standards it derives from. It is the authoritative reference for the
> `IdentityStatus` enum and the `origin` provenance discriminator.

## Summary

There is **one identity registry**. A discovered agent (e.g. an Okta or Entra agent we
enumerate via a connector) is **not** a separate inventory — it is an identity record in
the same store as a native agent, distinguished by two orthogonal fields:

- **`origin`** — provenance: `native` (we issued it) vs an external ecosystem
  (`okta` / `entra` / `google_workspace` / …). ADR 0009 D2.
- **`status`** — lifecycle state, extending the existing `IdentityStatus` machine with one
  new state, `discovered`, that sits *below* the existing states.

```
                          (no SDO state — ITIL/CMDB · CSA "Discovery" · Okta "Discover")
   observed in IdP ──discover──▶  discovered
                                  origin=external, owner OPTIONAL, no credential, NOT usable
                                      │
              adopt = assign a human owner (+ attach policy)
              (CSA "Ownership Assignment" · ISO 24760 "Enrolment→Established")
                                      ▼
                                   pending  ◀── (ISO "Established": owned, governed,
                                   │             not yet granted rights → IsUsable=false)
              activate = credential enrolled (CAP-IDN-012) OR first EMA/ID-JAG mint
              (ISO "Activation" · SCIM create+active=true)
                                      ▼
                                   active ──maintenance/rotation──┐
                                   │  (ISO "Active" = SCIM active=true: IsUsable=true)
                       suspend ────┤◀─── reactivate
                                   ▼
                                suspended   (ISO "Suspended" = SCIM active=false; reversible)
                                   │
            decommission / offboard (CSA "Decommissioning" · OWASP NHI1 ·
            SCIM DELETE SHALL · NIST 800-63B "SHALL invalidate")
                                   ▼
                           deactivated / expired   (ISO "Archived": soft-deleted,
                                                     audit-retained, never hard-deleted)
```

`ownerless` is a **cross-cutting flag** (any owned state can become orphaned when its owner
leaves), not a primary state — matching CSA / IGA "orphaned" and Entra's auto-transfer-to-
manager model. It is the headline posture signal for `discovered`.

## Why one registry (not a separate discovered store)

The alternative — discovered identities in a separate table, merged with native at read
time (the original in-`highflame-admin` `discovered_agents` design) — was rejected on
**standards** and **production** grounds, independent of any ADR:

- **Standards.** ISO/IEC 24760-1 §7.2 models *one identity that changes state*, not two
  registries. ITIL/CMDB — the only framework with a discovered *staging* area —
  reconciles staging **into a single authoritative CMDB** (its Identification &
  Reconciliation Engine); it never keeps two authoritative stores. The standards endpoint
  is **one record + a lifecycle**, with staging permitted only as a transient ingestion
  buffer inside the discovery service.
- **Single source of truth.** One tenancy-scoped surface (the `account_id`+`project_id`
  invariant has one place to enforce, not two), one audit/retention surface, one shape for
  every consumer (Cedar, Studio, SDK). A two-store design pushes a read-time merge into
  every consumer — which is what Studio does today and what this work removes.
- **Reconciliation is structural, not bolted on.** A ZeroID identity is already keyed by
  `(account_id, project_id, external_id)` with a stable WIMSE URI
  (`spiffe://{domain}/{account_id}/{project_id}/{identity_type}/{external_id}`). A
  discovered agent's `external_id` is its IdP object id; the **same** agent arriving later
  through EMA / ID-JAG reconciles to the **same** row on that key. A separate store would
  have to re-implement this key and merge on every read, forever — the duplicate/
  inconsistency bug class we are explicitly avoiding.
- **Safety is already enforced by status, not by table separation.** `IsUsable()` is true
  **only for `active`** — a `discovered` or `pending` identity cannot authenticate or
  receive a token. The "keep untrusted external data away from crown-jewel credentialed
  identities" instinct is satisfied by (i) discovery writing through **validated ZeroID
  identity APIs**, never raw DB, (ii) `origin`+`status` partitioning, and (iii) discovered
  rows being **credential-less and non-usable** — a poisoned discovered row is a posture
  data-quality issue, never an auth bypass.
- **Atomic transitions.** `discovered → pending → active` and offboarding are status
  updates on one row (atomic, audit-logged), not cross-store migrations with partial-
  failure risk.

## The state machine

We **extend** the existing, tested `IdentityStatus` machine (`domain/identity.go`) rather
than introduce a parallel field — the current enum already *is* an ISO-24760-shaped
lifecycle. We add exactly one state and the transitions into it; we **keep the existing
value names** and document the ISO mapping here (renaming the enum would break the Studio /
SDK / Cedar / DB contract for no functional gain).

| Our `status` | ISO/IEC 24760 | `IsUsable()` | Meaning |
| --- | --- | --- | --- |
| **`discovered`** *(new)* | *(below "Established" — no SDO models a pre-authoritative identity)* | **false** | Observed in an external IdP. `origin` external, `external_id` set, owner **optional**, no Highflame credential. |
| `pending` | **Established** | false | Registered & **owned**, governable, not yet granted rights. The "adopted" state. |
| `active` | **Active** | **true** | Granted rights: credential enrolled (CAP-IDN-012) or reconciled via EMA. The "managed" state. |
| `suspended` | **Suspended** | false | Reversible halt. |
| `deactivated` / `expired` | **Archived** | false | Terminal, soft-deleted, audit-retained. The offboarded state. |

**Transitions** (extending `CanTransitionTo`):

- `discovered → pending` — **adopt**: a human owner is assigned (CSA "Ownership
  Assignment" / ISO "Enrolment").
- `discovered → deactivated` — **dismiss**: an operator marks a discovered agent
  out-of-scope (kept as an archived record for audit, never hard-deleted).
- `discovered → active` — **direct activation**, permitted only when adoption *and*
  activation happen together: the first EMA / ID-JAG mint for the agent both assigns the
  reconciled identity and grants it rights. (Otherwise go `discovered → pending → active`.)
- All existing transitions (`pending→active`, `active→suspended|deactivated|expired`,
  `suspended→active`, …) are unchanged.

## Ownership: relaxed for `discovered` only

The platform invariant "every NHI must have a human owner accountable for its lifecycle"
([cross-cutting/non-human-identity.md](https://github.com/highflame-ai/highflame-architecture/blob/main/cross-cutting/non-human-identity.md)) is **relaxed for `discovered` only**:
ownerless is the *posture signal* discovery exists to surface, not a validation error.
**Owner becomes mandatory at `pending` (adoption) onward** — adoption *is* the act of
making an external agent accountable. This matches CSA's explicit "Ownership Assignment"
phase and Entra Agent ID's "there is always a human accountable" model (with
auto-transfer-to-manager when an owner leaves).

## Offboarding is the #1 obligation

OWASP ranks **improper offboarding NHI1** — the single highest NHI risk. SCIM (RFC 7644
§3.6) makes delete `SHALL`/`MUST`; NIST SP 800-63B-4 requires a CSP to **`SHALL` promptly
invalidate** authenticators when the subscriber account ceases to exist. We honor this via
the `deactivated`/`expired` (ISO "Archived") terminal states: identities are **soft-deleted
and audit-retained** (consistent with the platform `is_active` convention), **never
hard-deleted**, and the `IsUsable()==active` gate guarantees an archived identity can never
authenticate.

## Standards basis (synthesis)

| State / concept | Primary standard | Reinforced by |
| --- | --- | --- |
| `discovered` | ITIL/CMDB (discovered CI → reconcile) | CSA "Discovery", Okta "Discover unknown agents", CIEM "Account & Entitlements Discovery" |
| adopt (`→pending`) | **ISO/IEC 24760-1** "Enrolment→Established" | CSA **"Ownership Assignment"**, Entra owner/sponsor |
| `pending` / Established | **ISO/IEC 24760-1 "Established"** | "registered, not yet granted rights" |
| `active` / Active | **ISO/IEC 24760-1 "Active"** = **SCIM `active=true`** | SPIFFE SVID-issued, NIST 800-63B "binding", CAP-IDN-012 key enrollment |
| `suspended` | **ISO/IEC 24760-1 "Suspended"** = **SCIM `active=false`** | NIST SP 800-63B-4 authenticator suspension (reversible) |
| `deactivated`/`expired` / Archived | **ISO/IEC 24760-1 "Archived"** | CSA "Decommissioning", **OWASP NHI1**, SCIM `DELETE SHALL`, NIST 800-63B "SHALL invalidate" |
| `ownerless` (flag) | CSA / IGA "orphaned" | Entra auto-transfer-to-manager, OWASP NHI1 |

**Why ISO/IEC 24760-1 is the backbone:** it is the only formal SDO with a true identity
*state* lifecycle, and `Established` ("registered, not yet granted rights") vs `Active`
("granted rights") maps exactly onto our `pending`/`IsUsable=false` vs `active`/`IsUsable=true`
split. NIST SP 800-63-4 defines proofing/authenticator *events*, not account states; SP
800-207 is per-request and stateless; SCIM and SPIFFE/SPIRE assume the identity is already
authoritative and so model no pre-authoritative "discovered" state — that state is genuine
prior art from ITIL/CMDB and CSPM/CIEM, not ours to invent. CSA NHI Management contributes
the NHI-specific phase vocabulary, notably the explicit "Ownership Assignment" = adopt.

## Out of scope (here)

- **Source write-back** (revoke/disable a discovered agent in its home IdP) — requires its
  own ADR + security review (ADR 0009 D7).
- **In-path enforcement** of a discovered agent's traffic — firehog's domain, not the
  identity layer (ADR 0009 D5).
- **Connector mechanics** (per-IdP adapters, credential custody) — the discovery service,
  not ZeroID (ADR 0009 D1/D4). ZeroID only owns the *inventory* and its lifecycle.

## References

Standards & frameworks:
- ISO/IEC 24760-1:2025 — A framework for identity management (Clause 7.2, identity lifecycle): https://www.iso.org/standard/24760-1
- NIST SP 800-63-4 (Digital Identity Guidelines): https://csrc.nist.gov/pubs/sp/800/63/4/final · 800-63B-4 Authenticator Event Management: https://pages.nist.gov/800-63-4/sp800-63b/events/
- NIST/NCCoE — Accelerating the Adoption of Software and AI Agent Identity and Authorization (draft, Feb 2026): https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization
- SCIM — RFC 7643: https://www.rfc-editor.org/rfc/rfc7643.html · RFC 7644: https://www.rfc-editor.org/rfc/rfc7644.html
- CSA Non-Human Identity Management (8-phase lifecycle): https://cloudsecurityalliance.org/blog/2024/07/15/non-human-identity-management · Decommissioning orphaned/stale NHIs: https://cloudsecurityalliance.org/blog/2024/06/03/decommissioning-orphaned-and-stale-non-human-identities
- OWASP Non-Human Identities Top 10 (2025), NHI1 Improper Offboarding: https://owasp.org/www-project-non-human-identities-top-10/2025/1-improper-offboarding/
- ITIL/CMDB Identification & Reconciliation (discovered → authoritative): https://www.servicenow.com/community/cmdb-articles/cmdb-identification-reconciliation/ta-p/2301712
- IETF WIMSE architecture (workload identity provisioning/lifecycle): https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch-07 · SPIFFE/SPIRE concepts: https://spiffe.io/docs/latest/spire-about/spire-concepts/
- Microsoft Entra Agent ID (owner/sponsor, lifecycle): https://learn.microsoft.com/en-us/entra/agent-id/what-are-agent-identities
- Okta for AI Agents (Discover → Onboard → Protect → Govern): https://www.okta.com/products/govern-ai-agent-identity/

Internal:
- ADR 0009 — Agent discovery connectors in a dedicated integration service; inventory in the identity domain (highflame-architecture, `adrs/0009-agent-discovery-integration-service.md`)
- CAP-IDN-012 (actor keys enrollable after registration), CAP-IDN-013 (registry callable on AuthN with a tenant service credential), INV-IDN-002 (tenant from validated claims, never headers)
- `cross-cutting/non-human-identity.md` — the platform NHI lifecycle (Register → Authenticate → Operate → Govern → Retire); this doc is the ZeroID-owned state model underneath it.
