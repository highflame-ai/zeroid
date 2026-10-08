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

// ScopeCIBAApprove is the scope carried by approval-channel credentials that
// resolve CIBA requests on behalf of a user. It is never issued to an agent
// identity (enforced at the CredentialService.IssueCredential chokepoint).
const ScopeCIBAApprove = "ciba:approve"

// MaxRequesterOwnerChars caps the requester_owner bc-authorize extension
// parameter, matching MaxGroupHintChars.
const MaxRequesterOwnerChars = 255

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

// MaxAuthorizationDetailsBytes caps the total RAR payload at request time.
// RFC 9396 §2 is silent on a cap; zeroid's choice is driven by two
// downstream consumers:
//
//  1. Postgres persistence — the JSONB column has no schema-side cap; the
//     library-side limit prevents a malicious caller writing an unbounded
//     blob to the row.
//  2. JWT embed (RFC 9396 §6.1, wired by the CIBA token-side path) — the
//     payload is base64-embedded into the access-token JWT and carried in
//     `Authorization: Bearer <jwt>` headers. With base64 expansion (~33 %)
//     plus the rest of the JWT (header + signature + ZeroID's standard
//     claims ~500 bytes), a 64 KB RAR pushes total header size well past
//     common reverse-proxy limits (nginx defaults ~8 KB; ALB ~16 KB).
//     4 KB caps the JWT header at roughly 6.5 KB end-to-end, safe for
//     every proxy in the path.
//
// Realistic per-action authorization_details entries (type + tool + amount
// + currency + destination ≈ 100–200 bytes) easily fit 10+ entries under
// the 4 KB ceiling. Deployers needing larger payloads should rely on the
// /oauth2/token/introspect surface (which can carry any size of granted
// authorization_details) or reference an out-of-band record by ID in the
// `authorization_details` payload.
const MaxAuthorizationDetailsBytes = 4 * 1024

// ErrAuthorizationDetailsOversized is returned when the raw JSON exceeds
// MaxAuthorizationDetailsBytes.
var ErrAuthorizationDetailsOversized = errors.New(
	"authorization_details exceeds the per-request size cap",
)

// MaxGroupHintChars caps the CIBA group_hint extension parameter. zeroid
// treats group_hint as opaque (the deployer's namespace convention owns
// interpretation), so the only library-level concern is bounding write
// size against the persisted VARCHAR(255) column. 255 chars is generous
// for any reasonable namespace scheme — "highflame:role:finance_lead"
// is 27 chars, "pd:schedule:P12345" is 18 — and small enough that abuse
// (a megabyte-long pseudo-hint) is rejected before persistence.
const MaxGroupHintChars = 255

// ErrInvalidGroupHint is the sentinel returned when group_hint exceeds
// MaxGroupHintChars. Wrapped via %w so handlers can use errors.Is to
// map to 400 Bad Request consistently — see the convention used for
// ErrInvalidBindingMessage.
var ErrInvalidGroupHint = errors.New(
	"group_hint exceeds the per-request size cap",
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

	AuthReqID string `bun:"auth_req_id,pk,type:varchar(255)"             json:"auth_req_id"`
	AccountID string `bun:"account_id,type:varchar(255)"                 json:"account_id"`
	ProjectID string `bun:"project_id,type:varchar(255)"                 json:"project_id"`
	ClientID  string `bun:"client_id,type:varchar(255)"                  json:"client_id"`
	LoginHint string `bun:"login_hint,type:text"                         json:"login_hint,omitempty"`
	// GroupHint is the CIBA extension parameter for role-targeted /
	// group-targeted approval (see Server.RegisterAuthorizationDetailValidator
	// and BackchannelNotification.GroupHint for the deployer surface).
	// Opaque to zeroid; the deployer's namespace convention determines
	// what string content means (e.g. "highflame:role:finance_lead",
	// "pd:schedule:P12345"). Capped at MaxGroupHintChars by the service
	// layer; defaults to '' in Postgres so pre-extension rows surface
	// as no-group_hint without a NULL check in consumer code.
	GroupHint      string `bun:"group_hint,type:varchar(255)"                 json:"group_hint,omitempty"`
	Scope          string `bun:"scope,type:text"                              json:"scope,omitempty"`
	BindingMessage string `bun:"binding_message,type:text"                    json:"binding_message,omitempty"`
	// AuthorizationDetailsRaw is the RFC 9396 `authorization_details` JSON
	// array as supplied on bc-authorize, preserved verbatim. Stored as a
	// JSONB column (per-row size capped at MaxAuthorizationDetailsBytes by
	// the service layer at insert time). Decoded into the typed
	// AuthorizationDetails slice by ParseAuthorizationDetails for use by
	// validators, the BackchannelNotifier hook, and the token-side embed
	// at issuance (RFC 9396 §5.2 / §6.1 / §7). Defaults to '[]'::jsonb
	// in Postgres so pre-RAR rows read as an empty array; consumers can
	// branch on len(parsed) == 0.
	AuthorizationDetailsRaw    json.RawMessage             `bun:"authorization_details,type:jsonb"             json:"authorization_details,omitempty"`
	NotificationMode           BackchannelNotificationMode `bun:"notification_mode,type:varchar(16)"           json:"notification_mode"`
	ClientNotificationEndpoint string                      `bun:"client_notification_endpoint,type:text"       json:"client_notification_endpoint,omitempty"`
	ClientNotificationToken    string                      `bun:"client_notification_token,type:varchar(1024)" json:"-"`
	Status                     BackchannelStatus           `bun:"status,type:varchar(16)"                      json:"status"`
	ApprovedSubjectID          string                      `bun:"approved_subject_id,type:varchar(255)"        json:"approved_subject_id,omitempty"`
	ApprovedSubjectEmail       string                      `bun:"approved_subject_email,type:varchar(255)"     json:"approved_subject_email,omitempty"`
	ApprovedSubjectName        string                      `bun:"approved_subject_name,type:varchar(255)"      json:"approved_subject_name,omitempty"`
	// FourEyes and RequesterOwner are bc-authorize extension parameters.
	// When FourEyes is set, the user named by RequesterOwner may not resolve
	// the request (enforced under backchannel.enforce_hints).
	FourEyes       bool   `bun:"four_eyes,notnull,default:false"              json:"four_eyes,omitempty"`
	RequesterOwner string `bun:"requester_owner,type:text"                    json:"requester_owner,omitempty"`
	// Requesting chain, from the bc-authorize requesting_token extension
	// parameter (the access token of the request the approval is for). When
	// set, the token minted on approval keeps that chain's sub and act; the
	// approver is recorded only on this row.
	//
	//   RequesterSub     the requesting token's sub (on whose behalf)
	//   RequesterActor   who made the request: its act.sub, else its client_id,
	//                    else its sub
	//   RequestingJTI    the requesting token's jti
	//   RequesterActSub  the requesting token's act.sub ("" when it had none)
	RequesterSub    string `bun:"requester_sub,type:text"                     json:"requester_sub,omitempty"`
	RequesterActor  string `bun:"requester_actor,type:text"                   json:"requester_actor,omitempty"`
	RequestingJTI   string `bun:"requesting_jti,type:text"                    json:"-"`
	RequesterActSub string `bun:"requester_act_sub,type:text"                 json:"-"`
	// Approval record. ApprovedSubject* name the user who resolved the
	// request (approved or denied); the fields below record how that user
	// was authenticated and which binding check they satisfied.
	//
	//   ApproverIss      issuer that authenticated the approver
	//   ApproverAuth     "session" | "channel_attested" ("" when the approver
	//                    came from the request body, not the request context)
	//   ChannelClientID  approval channel that attested the approver
	//   HintSatisfied    "login_hint" | "group_hint" | "" (checks off or not met)
	//   ShadowWouldDeny  enforce_hints=shadow: the approver would have been
	//                    refused under enforce_hints=on; ShadowReason says why
	ApproverIss     string     `bun:"approver_iss,type:text"                      json:"approver_iss,omitempty"`
	ApproverAuth    string     `bun:"approver_auth,type:text"                     json:"approver_auth,omitempty"`
	ChannelClientID string     `bun:"channel_client_id,type:text"                 json:"channel_client_id,omitempty"`
	HintSatisfied   string     `bun:"hint_satisfied,type:text"                    json:"hint_satisfied,omitempty"`
	ShadowWouldDeny bool       `bun:"shadow_would_deny,notnull,default:false"     json:"shadow_would_deny,omitempty"`
	ShadowReason    string     `bun:"shadow_reason,type:text"                     json:"shadow_reason,omitempty"`
	IntervalSeconds int        `bun:"interval_seconds,notnull,default:5"           json:"interval"`
	LastPolledAt    *time.Time `bun:"last_polled_at"                               json:"last_polled_at,omitempty"`
	LastNotifyError string     `bun:"last_notify_error,type:text"                  json:"last_notify_error,omitempty"`
	ExpiresAt       time.Time  `bun:"expires_at,notnull"                           json:"expires_at"`
	CreatedAt       time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	ApprovedAt      *time.Time `bun:"approved_at"                                  json:"approved_at,omitempty"`
}

// BackchannelResolution is what an approve or deny records on the row: the
// resolving user and the approval-record fields of BackchannelAuthRequest.
type BackchannelResolution struct {
	SubjectID       string
	SubjectEmail    string
	SubjectName     string
	ApproverIss     string
	ApproverAuth    string
	ChannelClientID string
	HintSatisfied   string
	ShadowWouldDeny bool
	ShadowReason    string
}
