package domain

import (
	"time"

	"github.com/uptrace/bun"
)

// AttestationLevel indicates the security level of the attestation proof.
type AttestationLevel string

const (
	AttestationLevelSoftware AttestationLevel = "software"
	AttestationLevelPlatform AttestationLevel = "platform"
	AttestationLevelHardware AttestationLevel = "hardware"
)

// ProofType indicates the type of attestation proof material.
type ProofType string

const (
	ProofTypeImageHash ProofType = "image_hash"
	ProofTypeOIDCToken ProofType = "oidc_token"
	ProofTypeTPM       ProofType = "tpm"
)

// Valid reports whether l is a recognised AttestationLevel constant.
func (l AttestationLevel) Valid() bool {
	switch l {
	case AttestationLevelSoftware, AttestationLevelPlatform, AttestationLevelHardware:
		return true
	}
	return false
}

// Valid reports whether p is a recognised ProofType constant.
func (p ProofType) Valid() bool {
	switch p {
	case ProofTypeImageHash, ProofTypeOIDCToken, ProofTypeTPM:
		return true
	}
	return false
}

// AttestationRecord stores a submitted and optionally verified attestation proof.
type AttestationRecord struct {
	bun.BaseModel `bun:"table:attestation_records,alias:ar"`

	ID           string           `bun:"id,pk,type:uuid"              json:"id"`
	IdentityID   string           `bun:"identity_id,type:uuid"        json:"identity_id"`
	AccountID    string           `bun:"account_id,type:varchar(255)" json:"account_id"`
	ProjectID    string           `bun:"project_id,type:varchar(255)" json:"project_id"`
	Level        AttestationLevel `bun:"level,type:varchar(50)"        json:"level"`
	ProofType    ProofType        `bun:"proof_type,type:varchar(50)"   json:"proof_type"`
	ProofValue   string           `bun:"proof_value,type:text"         json:"proof_value"`
	ProofHash    string           `bun:"proof_hash,type:varchar(64)"   json:"proof_hash"`
	VerifiedAt   *time.Time       `bun:"verified_at"                   json:"verified_at,omitempty"`
	IsVerified   bool             `bun:"is_verified"                   json:"is_verified"`
	ExpiresAt    *time.Time       `bun:"expires_at"                    json:"expires_at,omitempty"`
	IsExpired    bool             `bun:"is_expired"                    json:"is_expired"`
	CredentialID string           `bun:"credential_id,type:uuid,nullzero" json:"credential_id,omitempty"`
	CreatedAt    time.Time        `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
}
