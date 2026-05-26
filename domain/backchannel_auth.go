package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// BackchannelStatus is the lifecycle state of a CIBA authentication request.
type BackchannelStatus string

const (
	// BackchannelStatusPending — created, awaiting user approval/denial.
	BackchannelStatusPending BackchannelStatus = "pending"
	// BackchannelStatusApproved — user approved; token issuance permitted on next poll.
	BackchannelStatusApproved BackchannelStatus = "approved"
	// BackchannelStatusIssued — token has been issued for this request; further polls are denied.
	BackchannelStatusIssued BackchannelStatus = "issued"
	// BackchannelStatusDenied — user explicitly denied.
	BackchannelStatusDenied BackchannelStatus = "denied"
	// BackchannelStatusExpired — request passed its expires_at without resolution.
	BackchannelStatusExpired BackchannelStatus = "expired"
)

// BackchannelNotificationMode is how the server informs the client that the
// request has been resolved.
type BackchannelNotificationMode string

const (
	// BackchannelNotificationPoll — client polls /oauth2/token with the auth_req_id.
	BackchannelNotificationPoll BackchannelNotificationMode = "poll"
	// BackchannelNotificationPing — server POSTs to client_notification_endpoint when the
	// status transitions to approved/denied; client then polls.
	BackchannelNotificationPing BackchannelNotificationMode = "ping"
	// BackchannelNotificationPush — server POSTs the full token response to
	// client_notification_endpoint on approval (or the OAuth error body on
	// denial); the client never polls. Implemented in PR 3.
	BackchannelNotificationPush BackchannelNotificationMode = "push"
)

// IsValidBackchannelDeliveryMode reports whether the given string is a
// recognised CIBA delivery mode. Empty is treated as the implicit default
// ("poll") and accepted.
func IsValidBackchannelDeliveryMode(mode string) bool {
	switch BackchannelNotificationMode(mode) {
	case "", BackchannelNotificationPoll, BackchannelNotificationPing, BackchannelNotificationPush:
		return true
	}
	return false
}

// GrantTypeCIBA is the OpenID CIBA Core 1.0 grant type identifier (§10.1).
// Clients submit this at /oauth2/token along with auth_req_id to poll for a token.
const GrantTypeCIBA GrantType = "urn:openid:params:grant-type:ciba"

// ─── RFC 9396 OAuth 2.0 Rich Authorization Requests (RAR) ───────────────────
//
// RAR extends a CIBA bc-authorize request with an `authorization_details`
// parameter — a JSON array of objects, each with a `type` discriminator,
// describing exactly what is being authorized (vs the coarse `scope`
// string). ZeroID stores the array verbatim and exposes it through the
// BackchannelNotifier hook so the deployer's approver UX can render a
// typed approval prompt. Per-type schema validation is opt-in via
// Server.RegisterAuthorizationDetailValidator — zeroid itself validates
// only the outer shape so any application-specific `type` namespace ships
// without a library-level schema commitment.

// MaxAuthorizationDetailsBytes caps the total RAR payload at request time
// to prevent unbounded JSON blobs in a persisted Postgres row. RFC 9396 §2
// is silent on a cap; 64 KB is generous for realistic transactional
// approvals (a typical entry is a few hundred bytes) and small enough that
// a malicious oversized payload is rejected before persistence.
const MaxAuthorizationDetailsBytes = 64 * 1024

// ErrAuthorizationDetailsOversized is returned when the raw JSON exceeds
// MaxAuthorizationDetailsBytes.
var ErrAuthorizationDetailsOversized = errors.New(
	"authorization_details exceeds the per-request size cap",
)

// ErrAuthorizationDetailsMalformed is returned when the raw JSON is not a
// valid array of objects each carrying a non-empty string `type`.
var ErrAuthorizationDetailsMalformed = errors.New(
	"authorization_details is not a valid RFC 9396 array of typed objects",
)

// AuthorizationDetail is one entry in the RAR `authorization_details` array.
//
// Type is the RFC 9396 type discriminator (required, non-empty string) — the
// only field zeroid validates. Raw is the full original JSON object preserved
// verbatim so consumers (per-type validators, the BackchannelNotifier, the
// future token-side JWT-embed) can decode their own typed shapes without
// re-stringifying or normalising the bytes.
type AuthorizationDetail struct {
	Type string          `json:"type"`
	Raw  json.RawMessage `json:"-"`
}

// AuthorizationDetails is the parsed slice form, used by service code and
// the BackchannelNotifier hook. On the bun model the column is stored as a
// json.RawMessage (the array as a whole); ParseAuthorizationDetails decodes
// it into this typed slice. Round-trip preserves bytes: marshalling the
// slice back produces equivalent JSON (key order may differ; element order
// is preserved).
type AuthorizationDetails []AuthorizationDetail

// ParseAuthorizationDetails decodes raw JSON into a typed slice, enforcing
// the outer-shape contract: top-level is a JSON array, each element is a
// JSON object, each object has a non-empty string `type` field. An empty
// or null input returns (nil, nil) — backward-compatible with pre-RAR
// rows / clients that omit the parameter.
//
// Returns ErrAuthorizationDetailsMalformed on any structural failure
// (wrapped with a descriptive index/reason for operator-facing logs).
// Does NOT invoke per-type validators — that is the service layer's
// responsibility after this parse succeeds.
func ParseAuthorizationDetails(raw []byte) (AuthorizationDetails, error) {
	// Treat empty, whitespace-only, and the literal JSON null as "no RAR
	// supplied" — backward compatible with clients that omit the parameter.
	// Trim first so the contract matches what the doc comment promises; the
	// whitespace case is unreachable from the HTTP path today (Huma's JSON
	// decode would never hand us bare whitespace bytes) but the explicit
	// trim removes a code/doc mismatch for any future direct caller of
	// this function.
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}

	// Outer must be an array.
	var elements []json.RawMessage
	if err := json.Unmarshal(trimmed, &elements); err != nil {
		return nil, fmt.Errorf("%w: outer must be a JSON array: %w",
			ErrAuthorizationDetailsMalformed, err)
	}

	if len(elements) == 0 {
		return nil, nil
	}

	out := make(AuthorizationDetails, 0, len(elements))

	for i, el := range elements {
		// Each element must be a JSON object (not array/string/number/null).
		// Decode the `type` discriminator to enforce the contract; preserve
		// the full raw bytes for downstream consumers.
		var probe struct {
			Type *string `json:"type"`
		}

		if err := json.Unmarshal(el, &probe); err != nil {
			return nil, fmt.Errorf(
				"%w: element[%d] must be a JSON object with a string `type` field: %w",
				ErrAuthorizationDetailsMalformed, i, err,
			)
		}

		if probe.Type == nil {
			return nil, fmt.Errorf(
				"%w: element[%d] is missing the required `type` field",
				ErrAuthorizationDetailsMalformed, i,
			)
		}

		if *probe.Type == "" {
			return nil, fmt.Errorf(
				"%w: element[%d] has an empty `type` (must be a non-empty string)",
				ErrAuthorizationDetailsMalformed, i,
			)
		}

		out = append(out, AuthorizationDetail{
			Type: *probe.Type,
			Raw:  el,
		})
	}

	return out, nil
}

// BackchannelAuthRequest is a persisted CIBA authentication request.
//
// The row is created on POST /oauth2/bc-authorize. The auth_req_id is the
// client-visible handle and is also the primary key — it must be unguessable
// (the service layer mints it from crypto/rand). The request transitions
// pending → approved → issued on the happy path; pending → denied / expired
// on the failure paths. expires_at is enforced by both the cleanup worker
// (sweep) and the grant handler (per-request check), so a stale row cannot
// silently mint a token.
type BackchannelAuthRequest struct {
	bun.BaseModel `bun:"table:backchannel_auth_requests,alias:bcr"`

	AuthReqID      string `bun:"auth_req_id,pk,type:varchar(255)"             json:"auth_req_id"`
	AccountID      string `bun:"account_id,type:varchar(255)"                 json:"account_id"`
	ProjectID      string `bun:"project_id,type:varchar(255)"                 json:"project_id"`
	ClientID       string `bun:"client_id,type:varchar(255)"                  json:"client_id"`
	LoginHint      string `bun:"login_hint,type:text"                         json:"login_hint,omitempty"`
	Scope          string `bun:"scope,type:text"                              json:"scope,omitempty"`
	BindingMessage string `bun:"binding_message,type:text"                    json:"binding_message,omitempty"`
	// AuthorizationDetailsRaw is the RFC 9396 `authorization_details` JSON
	// array as supplied on bc-authorize, preserved verbatim. Stored as a
	// JSONB column (per-row size capped at MaxAuthorizationDetailsBytes by
	// the service layer at insert time). Decoded into the typed
	// AuthorizationDetails slice by ParseAuthorizationDetails for use by
	// validators, the BackchannelNotifier hook, and the future token-embed
	// path (PR 2). Defaults to '[]'::jsonb in Postgres so pre-RAR rows
	// read as an empty array; consumers can branch on len(parsed) == 0.
	AuthorizationDetailsRaw    json.RawMessage             `bun:"authorization_details,type:jsonb"             json:"authorization_details,omitempty"`
	NotificationMode           BackchannelNotificationMode `bun:"notification_mode,type:varchar(16)"           json:"notification_mode"`
	ClientNotificationEndpoint string                      `bun:"client_notification_endpoint,type:text"       json:"client_notification_endpoint,omitempty"`
	ClientNotificationToken    string                      `bun:"client_notification_token,type:varchar(1024)" json:"-"`
	Status                     BackchannelStatus           `bun:"status,type:varchar(16)"                      json:"status"`
	ApprovedSubjectID          string                      `bun:"approved_subject_id,type:varchar(255)"        json:"approved_subject_id,omitempty"`
	ApprovedSubjectEmail       string                      `bun:"approved_subject_email,type:varchar(255)"     json:"approved_subject_email,omitempty"`
	ApprovedSubjectName        string                      `bun:"approved_subject_name,type:varchar(255)"      json:"approved_subject_name,omitempty"`
	IntervalSeconds            int                         `bun:"interval_seconds,notnull,default:5"           json:"interval"`
	LastPolledAt               *time.Time                  `bun:"last_polled_at"                               json:"last_polled_at,omitempty"`
	LastNotifyError            string                      `bun:"last_notify_error,type:text"                  json:"last_notify_error,omitempty"`
	ExpiresAt                  time.Time                   `bun:"expires_at,notnull"                           json:"expires_at"`
	CreatedAt                  time.Time                   `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	ApprovedAt                 *time.Time                  `bun:"approved_at"                                  json:"approved_at,omitempty"`
}
