package domain

import (
	"time"

	"github.com/uptrace/bun"
)

// SignalType represents the type of a CAE (Continuous Access Evaluation) signal.
type SignalType string

const (
	SignalTypeCredentialChange  SignalType = "credential_change"
	SignalTypeSessionRevoked    SignalType = "session_revoked"
	SignalTypeIPChange          SignalType = "ip_change"
	SignalTypeAnomalousBehavior SignalType = "anomalous_behavior"
	SignalTypePolicyViolation   SignalType = "policy_violation"
	SignalTypeRetirement        SignalType = "retirement"
	SignalTypeOwnerChange       SignalType = "owner_change"
	// SignalTypeIdentityExpired fires when the cleanup worker deactivates
	// an identity whose expires_at has passed. Kept distinct from
	// SignalTypeRetirement (admin-initiated deactivation) so subscribers
	// can filter the indexed signal_type column directly instead of
	// destructuring the payload.
	SignalTypeIdentityExpired SignalType = "identity_expired"
)

// SignalSeverity indicates the severity level of a CAE signal.
type SignalSeverity string

const (
	SignalSeverityLow      SignalSeverity = "low"
	SignalSeverityMedium   SignalSeverity = "medium"
	SignalSeverityHigh     SignalSeverity = "high"
	SignalSeverityCritical SignalSeverity = "critical"
)

// Valid reports whether s is a recognised SignalSeverity constant.
func (s SignalSeverity) Valid() bool {
	switch s {
	case SignalSeverityLow, SignalSeverityMedium, SignalSeverityHigh, SignalSeverityCritical:
		return true
	}
	return false
}

// Valid reports whether t is a recognised SignalType constant.
func (t SignalType) Valid() bool {
	switch t {
	case SignalTypeCredentialChange, SignalTypeSessionRevoked, SignalTypeIPChange,
		SignalTypeAnomalousBehavior, SignalTypePolicyViolation, SignalTypeRetirement,
		SignalTypeOwnerChange, SignalTypeIdentityExpired:
		return true
	}
	return false
}

// CAESignal represents a Continuous Access Evaluation risk signal.
type CAESignal struct {
	bun.BaseModel `bun:"table:cae_signals,alias:cs"`

	ID          string         `bun:"id,pk,type:uuid" json:"id"`
	AccountID   string         `bun:"account_id,type:varchar(255)" json:"account_id"`
	ProjectID   string         `bun:"project_id,type:varchar(255)" json:"project_id"`
	IdentityID  string         `bun:"identity_id,type:uuid" json:"identity_id"`
	SignalType  SignalType     `bun:"signal_type,type:varchar(50)" json:"signal_type"`
	Severity    SignalSeverity `bun:"severity,type:varchar(20)" json:"severity"`
	Source      string         `bun:"source,type:varchar(255)" json:"source"`
	Payload     map[string]any `bun:"payload,type:jsonb" json:"payload,omitempty"`
	ProcessedAt *time.Time     `bun:"processed_at" json:"processed_at,omitempty"`
	CreatedAt   time.Time      `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
}
