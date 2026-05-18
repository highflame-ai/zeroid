package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrSigningCredInvalid is returned when an attestation request is
// malformed (bad key, unsupported alg/purpose).
var ErrSigningCredInvalid = errors.New("invalid signing-credential attestation request")

const (
	defaultSigningMaxTTL          = time.Hour
	defaultSigningRetentionWindow = 400 * 24 * time.Hour
	kidRandomBytes                = 8
	// defaultSigningJWKSName mirrors zeroid.DefaultSigningJWKSName for the
	// blank-name fallback (the root config package can't be imported here
	// without an import cycle; the config layer normally supplies it).
	defaultSigningJWKSName = "signing-keys"
)

// SigningCredentialService attests workload-supplied Ed25519 public keys,
// publishes the verification JWKS, and revokes via CAE. The private key
// never reaches ZeroID — only the public half is ever submitted/stored.
type SigningCredentialService struct {
	repo            *postgres.SigningCredentialRepository
	maxTTL          time.Duration
	retentionWindow time.Duration
	allowedPurposes map[string]bool
	jwksPurpose     string
	wellKnownName   string
}

// NewSigningCredentialService builds the service. ttlSeconds /
// retentionDays / allowedPurposes / jwksPurpose / wellKnownName all come
// from zeroid.Config (deployer-supplied). ZeroID is product-agnostic:
// allowedPurposes is empty unless the deployment opts in, so a default
// ZeroID accepts no attestations until configured. wellKnownName
// defaults to DefaultSigningJWKSName when blank.
func NewSigningCredentialService(repo *postgres.SigningCredentialRepository, ttlSeconds, retentionDays int, allowedPurposes []string, jwksPurpose, wellKnownName string) *SigningCredentialService {
	maxTTL := time.Duration(ttlSeconds) * time.Second
	if maxTTL <= 0 {
		maxTTL = defaultSigningMaxTTL
	}

	retention := time.Duration(retentionDays) * 24 * time.Hour
	if retention <= 0 {
		retention = defaultSigningRetentionWindow
	}

	allow := make(map[string]bool, len(allowedPurposes))
	for _, p := range allowedPurposes {
		if p != "" {
			allow[p] = true
		}
	}

	if wellKnownName == "" {
		wellKnownName = defaultSigningJWKSName
	}

	return &SigningCredentialService{
		repo:            repo,
		maxTTL:          maxTTL,
		retentionWindow: retention,
		allowedPurposes: allow,
		jwksPurpose:     jwksPurpose,
		wellKnownName:   wellKnownName,
	}
}

// WellKnownPath is the public route the verification JWKS is served at.
func (s *SigningCredentialService) WellKnownPath() string {
	return "/.well-known/" + s.wellKnownName
}

// JWKSEnabled reports whether a verification JWKS purpose is configured;
// when false the public JWKS route is not registered (feature dormant).
func (s *SigningCredentialService) JWKSEnabled() bool {
	return s.jwksPurpose != ""
}

// AttestRequest is a workload's request to register an ephemeral public
// key. Workload is the authenticated trusted-service identity (resolved
// by the handler from the caller context, not client-supplied).
type AttestRequest struct {
	Workload   string
	AccountID  string
	ProjectID  string
	PublicKey  string // base64 raw-url Ed25519 public key (32 bytes)
	Algorithm  string // must be EdDSA
	Purpose    string // must be in the deployer's AllowedPurposes
	TTLSeconds int
}

// AttestResult is what the workload gets back: the minted kid and the
// operational expiry. No key material is returned (ZeroID never had the
// private half; the public half the caller already holds).
type AttestResult struct {
	KID      string    `json:"kid"`
	NotAfter time.Time `json:"not_after"`
}

// Attest validates and records an ephemeral public key. NotAfter bounds
// signing; AuditRetentionUntil (>> NotAfter) bounds verifiability so a
// rotated/expired key still verifies historical attestations.
func (s *SigningCredentialService) Attest(ctx context.Context, req AttestRequest) (*AttestResult, error) {
	if strings.TrimSpace(req.Workload) == "" {
		return nil, fmt.Errorf("%w: missing workload identity", ErrSigningCredInvalid)
	}

	if req.Algorithm != domain.SigningAlgorithmEdDSA {
		return nil, fmt.Errorf("%w: unsupported algorithm %q (only EdDSA)", ErrSigningCredInvalid, req.Algorithm)
	}

	if !s.allowedPurposes[req.Purpose] {
		return nil, fmt.Errorf("%w: purpose %q not permitted", ErrSigningCredInvalid, req.Purpose)
	}

	pub, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public_key must be base64url 32-byte Ed25519", ErrSigningCredInvalid)
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > s.maxTTL {
		ttl = s.maxTTL
	}

	kid, err := mintKID(req.Purpose, req.Workload)
	if err != nil {
		return nil, fmt.Errorf("minting kid: %w", err)
	}

	now := time.Now()
	cred := &domain.SigningCredential{
		AccountID:           req.AccountID,
		ProjectID:           req.ProjectID,
		KID:                 kid,
		Workload:            req.Workload,
		Purpose:             req.Purpose,
		Algorithm:           domain.SigningAlgorithmEdDSA,
		PublicKey:           req.PublicKey,
		NotAfter:            now.Add(ttl),
		AuditRetentionUntil: now.Add(s.retentionWindow),
	}

	if err := s.repo.Create(ctx, cred); err != nil {
		return nil, err
	}

	log.Info().
		Str("workload", req.Workload).
		Str("purpose", req.Purpose).
		Str("kid", kid).
		Time("not_after", cred.NotAfter).
		Time("audit_retention_until", cred.AuditRetentionUntil).
		Msg("signing credential attested")

	return &AttestResult{KID: kid, NotAfter: cred.NotAfter}, nil
}

// JWK is one RFC 7517 / RFC 8037 OKP Ed25519 public key. Emitted as a
// plain struct (not jwk.Set) because the public key is already stored
// base64url — re-importing it through jwx would be lossy churn, and the
// verifier contract only needs these fields.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// JWKS is the verification key set served at the well-known path.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// VerificationJWKS returns every key that may currently VERIFY an
// attestation for the configured JWKS purpose: non-revoked AND inside the
// audit-retention window — deliberately including operationally-expired
// keys so attestations signed before a rotation still verify. Kid-sorted
// for a stable doc.
func (s *SigningCredentialService) VerificationJWKS(ctx context.Context) (*JWKS, error) {
	creds, err := s.repo.ListVerifiable(ctx, s.jwksPurpose, time.Now())
	if err != nil {
		return nil, err
	}

	out := &JWKS{Keys: make([]JWK, 0, len(creds))}
	for _, c := range creds {
		out.Keys = append(out.Keys, JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   c.PublicKey,
			Use: "sig",
			Alg: domain.SigningAlgorithmEdDSA,
			Kid: c.KID,
		})
	}

	sort.Slice(out.Keys, func(i, j int) bool { return out.Keys[i].Kid < out.Keys[j].Kid })

	return out, nil
}

// RevokeKID revokes one credential within the caller's tenant, scoped to
// the attesting workload. A revoked key fails verification immediately,
// regardless of retention.
func (s *SigningCredentialService) RevokeKID(ctx context.Context, kid, workload, accountID, projectID, reason string) (bool, error) {
	n, err := s.repo.RevokeKID(ctx, kid, workload, accountID, projectID, reason, time.Now())
	if err != nil {
		return false, err
	}

	return n > 0, nil
}

// RevokeWorkload revokes every active key for a workload within a tenant
// — the CAE entry point (call on a credential_compromise /
// trust_level_downgrade signal).
func (s *SigningCredentialService) RevokeWorkload(ctx context.Context, workload, accountID, projectID, reason string) (int64, error) {
	return s.repo.RevokeWorkload(ctx, workload, accountID, projectID, reason, time.Now())
}

// mintKID returns a collision-safe, sanitized, informative key id.
// Opaque to verifiers (they only match it); encoding purpose+workload
// aids audit. Hostile workload/purpose strings are neutralized — the kid
// is echoed into signed artifacts and the JWKS.
func mintKID(purpose, workload string) (string, error) {
	var b [kidRandomBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}

	clean := func(in string) string {
		return strings.Map(func(r rune) rune {
			if r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}

			return '-'
		}, strings.ToLower(in))
	}

	return fmt.Sprintf("%s-%s-%s", clean(purpose), clean(workload), hex.EncodeToString(b[:])), nil
}
