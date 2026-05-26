# Rich Authorization Requests (RFC 9396) — Reference

ZeroID implements [RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396) on the CIBA bc-authorize endpoint so agents can request per-action approval with typed payloads instead of the coarse-grained `scope` string. Two motivating examples:

- **Scope** says: *"this agent may call `payments:write`."* Coarse. The end user sees a checkbox.
- **RAR** says: *"this agent wants to call `tool_call` `transfer_funds` for amount `50000` from account `acct_X`."* The end user sees a per-action prompt with bound parameters they can verify before approving.

For the wire-level CIBA flow that RAR rides on, see the README's [CIBA section](../README.md#pattern-6-agent-pauses-for-out-of-band-user-approval-ciba). This document covers what RAR adds on top.

---

## What RAR adds to CIBA

A CIBA `bc-authorize` request normally carries:

```json
{
  "client_id": "agent-1",
  "account_id": "acct_X",
  "project_id": "proj_Y",
  "login_hint": "alice@example.com",
  "scope": "payments:write",
  "binding_message": "Transfer to vendor Z"
}
```

With RAR you add an `authorization_details` array of typed objects describing the actual operation:

```json
{
  "client_id": "agent-1",
  "account_id": "acct_X",
  "project_id": "proj_Y",
  "login_hint": "alice@example.com",
  "scope": "payments:write",
  "binding_message": "Transfer to vendor Z",
  "authorization_details": [
    {
      "type": "tool_call",
      "tool": "transfer_funds",
      "amount": 50000,
      "currency": "USD",
      "destination": "acct_Vendor_Z"
    }
  ]
}
```

The deployer-supplied `BackchannelNotifier` then receives the parsed typed slice and renders an approval prompt that shows the actual operation — `tool`, `amount`, `destination` — rather than just the scope name.

### Multiple actions per request

A single bc-authorize call can carry several actions; the approver UX can render them as a combined prompt the user approves or denies as a unit:

```json
"authorization_details": [
  { "type": "tool_call", "tool": "transfer_funds", "amount": 50000 },
  { "type": "audit_entry", "trace": "txn-2025-05-26-001", "actions": ["log"] }
]
```

ZeroID preserves declaration order so the approver UX renders entries in the sequence the client supplied.

---

## Validation model — permissive by default, opt-in strict per-type

### What ZeroID validates unconditionally

ZeroID enforces only the RFC 9396 outer-shape contract:

1. The top-level value MUST be a JSON array.
2. Every element MUST be a JSON object.
3. Every object MUST have a `type` field whose value is a non-empty string.

Any violation returns the RFC 9396 OAuth error code:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_authorization_details",
  "error_description": "authorization_details[0] must be a JSON object with a string `type` field"
}
```

This matches how Auth0 and Okta handle CIBA RAR — the library accepts the shape, the deployer layers strict per-type validation on top.

### How a deployer adds strict per-type validation

Register a validator against a specific `type`:

```go
srv := zeroid.NewServer(cfg)

srv.RegisterAuthorizationDetailValidator(
    "tool_call",
    func(raw json.RawMessage) error {
        var payload struct {
            Tool     string `json:"tool"`
            Amount   int    `json:"amount"`
            Currency string `json:"currency"`
        }
        if err := json.Unmarshal(raw, &payload); err != nil {
            return err
        }
        if _, ok := allowedTools[payload.Tool]; !ok {
            return fmt.Errorf("tool %q is not in the deployer's allow-list", payload.Tool)
        }
        if payload.Amount <= 0 {
            return errors.New("amount must be positive")
        }
        return nil
    },
)
```

Semantics:

- The validator runs at `bc-authorize` time, after outer-shape validation and before the row is persisted. A rejection fails the entire request — partial accept is intentionally not supported.
- The validator's error message is surfaced in `error_description` so clients see *why* their request was rejected. The OAuth error code is always `invalid_authorization_details`.
- Validators MUST be fast (no network calls, no DB queries beyond in-process caches). They run synchronously on the request path.
- Validators that panic are caught — a buggy deployer registration cannot trip the request into an HTTP 500. The panic message is surfaced as `validator panicked: ...` in `error_description`.
- Pass `nil` to `RegisterAuthorizationDetailValidator(typ, nil)` to unregister.
- Unregistered types pass through with outer-shape validation only. There is no catch-all / fallback hook in this release. A strict type allow-list (reject the request when `type` is not in a known set) is NOT expressible via the validator registry alone — the notifier fires after the bc-authorize response is sent, so a notifier-side rejection records `last_notify_error` on the row but does not surface to the client as a 400. Deployers that need strict allow-listing today must front zeroid with a thin shim that screens `authorization_details` before forwarding. A future zeroid release may add a built-in strict-allowlist option / fallback validator hook.

---

## Notifier integration

The `BackchannelNotifier` hook receives the parsed typed slice through the `AuthorizationDetails` field on `BackchannelNotification`:

```go
srv.SetBackchannelNotifier(func(ctx context.Context, n zeroid.BackchannelNotification) error {
    for i, ad := range n.AuthorizationDetails {
        log.Printf("approval %s: detail[%d] type=%s raw=%s",
            n.AuthReqID, i, ad.Type, string(ad.Raw))
    }
    // Render a typed approval prompt via your push/email/Slack provider.
    return notify.Send(ctx, n)
})
```

Each `AuthorizationDetail` carries:

- `Type` — the type discriminator string, already validated as non-empty.
- `Raw` — the full original JSON object for this element, preserved verbatim. Notifiers can decode it into their own typed struct for rendering, or forward the bytes unchanged to a downstream system.

When the client does not supply `authorization_details` (legacy CIBA), `n.AuthorizationDetails` is an empty slice — notifiers can branch on `len(n.AuthorizationDetails) == 0` and fall back to the legacy scope-plus-binding-message render path.

---

## Content types

Per RFC 9396 §3 (and the underlying RFC 6749 request-body conventions), `authorization_details` is accepted both as part of a JSON request body and as a URL-encoded form parameter whose value is the JSON-array string.

**JSON body** — `application/json`:

```http
POST /oauth2/bc-authorize HTTP/1.1
Content-Type: application/json

{
  "client_id": "agent-1",
  ...
  "authorization_details": [{ "type": "tool_call", "tool": "transfer_funds" }]
}
```

**Form-encoded** — `application/x-www-form-urlencoded`:

```http
POST /oauth2/bc-authorize HTTP/1.1
Content-Type: application/x-www-form-urlencoded

client_id=agent-1&...&authorization_details=%5B%7B%22type%22%3A%22tool_call%22%2C%22tool%22%3A%22transfer_funds%22%7D%5D
```

ZeroID's form-compat middleware detects JSON-shaped fields (currently `authorization_details`) and passes them through as raw JSON so the downstream binder sees the original array shape.

---

## Persistence

`authorization_details` is stored verbatim as a `JSONB` column on `backchannel_auth_requests` (migration `027_rar_authorization_details.up.sql`):

```sql
ALTER TABLE backchannel_auth_requests
    ADD COLUMN authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb;
```

- Pre-RAR rows read as `[]`, not `NULL` — consumer code stays branch-free.
- Bytes are preserved verbatim (no normalization, no re-marshalling) so per-type validators and approver UX see exactly what the client supplied.
- The per-request payload is capped at 64 KiB (`domain.MaxAuthorizationDetailsBytes`); oversized payloads are rejected with `invalid_authorization_details` before persistence.
- No GIN index ships in v1 — nothing today queries by `authorization_details` content. Add one if usage emerges.

---

## Error code mapping

| Failure                                            | HTTP | `error`                          | Notes                                                                                |
| -------------------------------------------------- | ---- | -------------------------------- | ------------------------------------------------------------------------------------ |
| `authorization_details` is not a JSON array        | 400  | `invalid_authorization_details`  | RFC 9396 §5 outer-shape                                                              |
| Any element missing / non-string / empty `type`    | 400  | `invalid_authorization_details`  | RFC 9396 §2.1                                                                        |
| Payload exceeds 64 KiB                             | 400  | `invalid_authorization_details`  | Size cap is ZeroID policy (RFC 9396 leaves this unbounded)                            |
| Per-type validator returned an error               | 400  | `invalid_authorization_details`  | Validator's error message surfaces in `error_description`                            |
| Per-type validator panicked                        | 400  | `invalid_authorization_details`  | Panic recovered and reported as `validator panicked: ...`                            |

`error_description` always carries the offending element index when the failure is per-element so operators can pinpoint the bad entry in a multi-element payload.

---

## What's NOT in this PR (follow-up)

The bc-authorize side is everything a deployer needs to start using RAR for approval prompts. The token-side wiring — RFC 9396 §5 token response, §6.1 access-token JWT claim, §7 introspection response — is intentionally deferred to a follow-up so resource servers can read approved `authorization_details` for receipt-chain commitment.

In the meantime, an approved request stores the original `authorization_details` JSON on the `backchannel_auth_requests` row; downstream code that has the `auth_req_id` can read it directly from Postgres if it needs the typed payload before the token-side ships.

---

## Compliance suite

RFC 9396 normative MUSTs are pinned by [`tests/integration/rar_compliance_test.go`](../tests/integration/rar_compliance_test.go) following the conventions in [`tests/integration/COMPLIANCE.md`](../tests/integration/COMPLIANCE.md) — one MUST per test, `TestRFC9396_S<section>_<descriptor>` naming, the test's first body line cites the spec clause. Token-side clauses will extend that file in lockstep with the token-embed PR.

---

## Related

- ZeroID CIBA reference: README → [Pattern 6: Agent pauses for out-of-band user approval](../README.md#pattern-6-agent-pauses-for-out-of-band-user-approval-ciba)
- Highflame ADR 0002 — AARM STEP_UP via CIBA + RAR: [`highflame-architecture/adrs/0002-aarm-stepup-defer-protocol.md`](https://github.com/highflame-ai/highflame-architecture/blob/main/adrs/0002-aarm-stepup-defer-protocol.md)
- RFC 9396 — Rich Authorization Requests: https://datatracker.ietf.org/doc/html/rfc9396
