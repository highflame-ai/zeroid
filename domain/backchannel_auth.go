package domain

import (
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
// request has been resolved. PR 1 only implements "poll".
type BackchannelNotificationMode string

const (
	// BackchannelNotificationPoll — client polls /oauth2/token with the auth_req_id.
	BackchannelNotificationPoll BackchannelNotificationMode = "poll"
	// BackchannelNotificationPing — server POSTs to client_notification_endpoint when the
	// status transitions to approved/denied; client then polls. Implemented in PR 2.
	BackchannelNotificationPing BackchannelNotificationMode = "ping"
)

// GrantTypeCIBA is the OpenID CIBA Core 1.0 grant type identifier (§10.1).
// Clients submit this at /oauth2/token along with auth_req_id to poll for a token.
const GrantTypeCIBA GrantType = "urn:openid:params:grant-type:ciba"

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

	AuthReqID                  string                      `bun:"auth_req_id,pk,type:varchar(255)"             json:"auth_req_id"`
	AccountID                  string                      `bun:"account_id,type:varchar(255)"                 json:"account_id"`
	ProjectID                  string                      `bun:"project_id,type:varchar(255)"                 json:"project_id"`
	ClientID                   string                      `bun:"client_id,type:varchar(255)"                  json:"client_id"`
	LoginHint                  string                      `bun:"login_hint,type:text"                         json:"login_hint,omitempty"`
	Scope                      string                      `bun:"scope,type:text"                              json:"scope,omitempty"`
	BindingMessage             string                      `bun:"binding_message,type:text"                    json:"binding_message,omitempty"`
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
