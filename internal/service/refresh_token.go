package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// RefreshTokenService handles refresh token issuance and rotation.
type RefreshTokenService struct {
	repo *postgres.RefreshTokenRepository
	// db is needed to wrap claim+insert in a transaction during rotation so a
	// failed successor insert rolls back the claim, avoiding spurious reuse
	// detection on a client retry after a transient DB error.
	db *bun.DB
	// revocationDispatcher fans out a RevocationEvent per revoked refresh token
	// when reuse detection (or auth-code replay) nukes a family. Shared with
	// CredentialService so one Server.SetRevocationNotifier wires every path.
	// Nil-safe: unset ⇒ no events.
	revocationDispatcher *RevocationDispatcher
}

// NewRefreshTokenService creates a new refresh token service.
func NewRefreshTokenService(repo *postgres.RefreshTokenRepository, db *bun.DB) *RefreshTokenService {
	return &RefreshTokenService{repo: repo, db: db}
}

// RefreshTokenParams contains the data needed to issue a refresh token.
type RefreshTokenParams struct {
	ClientID   string
	AccountID  string
	ProjectID  string
	UserID     string
	IdentityID *string
	Scopes     string
	TTL        int // seconds, 0 = use default (90 days)
	// DPoPKeyThumbprint binds the refresh token to a DPoP key (RFC 9449 §5).
	// Set non-empty when the issuing /oauth2/token call carried a valid DPoP
	// proof; every later rotation must present a proof signed by the same
	// key. Empty ⇒ unbound (Bearer).
	DPoPKeyThumbprint string
	// MissionID is the delegation-tree identifier (issue #81) of the access
	// token issued alongside this refresh token. Persisted on the family so
	// every rotation can re-emit it, keeping a refreshing session inside one
	// mission. Empty ⇒ no mission to carry (refresh falls back to re-rooting).
	MissionID string
}

// ErrDPoPBindingMismatch is returned when a refresh-token rotation presents a
// DPoP proof whose key thumbprint differs from the one persisted with the
// token. Callers MUST map this to invalid_dpop_proof / 4xx — it is the proof
// that failed, not the refresh token. The token itself is NOT consumed.
var ErrDPoPBindingMismatch = errors.New("refresh token's DPoP binding does not match the presented proof")

// RefreshTokenResult contains both the raw token (returned to client) and stored metadata.
type RefreshTokenResult struct {
	RawToken  string // Returned to client once — never stored.
	FamilyID  string // For audit/debugging.
	ExpiresAt time.Time
}

// IssueRefreshToken generates a new refresh token and starts a new token family.
func (s *RefreshTokenService) IssueRefreshToken(ctx context.Context, params *RefreshTokenParams) (*RefreshTokenResult, error) {
	rawToken, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	tokenHash := hashRefreshToken(rawToken)
	familyID := uuid.New().String()
	expiresAt := time.Now().Add(refreshTokenTTL(params.TTL))

	record := &domain.RefreshToken{
		TokenHash:         tokenHash,
		ClientID:          params.ClientID,
		AccountID:         params.AccountID,
		ProjectID:         params.ProjectID,
		UserID:            params.UserID,
		IdentityID:        params.IdentityID,
		Scopes:            params.Scopes,
		FamilyID:          familyID,
		State:             domain.RefreshTokenStateActive,
		ExpiresAt:         expiresAt,
		DPoPKeyThumbprint: params.DPoPKeyThumbprint,
		MissionID:         params.MissionID,
	}

	if err := s.repo.Create(ctx, s.db, record); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &RefreshTokenResult{
		RawToken:  rawToken,
		FamilyID:  familyID,
		ExpiresAt: expiresAt,
	}, nil
}

// PeekRefreshToken returns the active, non-expired refresh-token row for the
// presented raw token WITHOUT consuming (revoking) it. It is the non-mutating
// counterpart to RotateRefreshToken's claim step: the caller can read binding
// metadata (ClientID, IdentityID, tenant scalars) and run pre-rotation gates
// (client_id binding, identity status/expiry) before committing the rotation.
//
// Crucially, a gate that fails AFTER a Peek leaves the token UNTOUCHED — the
// client can retry with the same token once the transient condition clears.
// This avoids the session-bricking failure mode where the rotation committed
// (old token revoked, successor inserted) before a post-claim gate ran, then
// discarded the successor on error: the client would then retry with a
// now-revoked token and trip reuse detection, nuking the whole family over a
// transient mistake (RFC 6749 §10.4).
//
// Returns an error if no active, non-expired token matches (expired, revoked,
// or unknown). The caller maps this to invalid_grant; it does NOT trigger
// reuse detection (that only fires inside RotateRefreshToken's claim path,
// which distinguishes the grace window).
func (s *RefreshTokenService) PeekRefreshToken(ctx context.Context, rawToken string) (*domain.RefreshToken, error) {
	return s.repo.GetByTokenHash(ctx, hashRefreshToken(rawToken))
}

// RotateRefreshToken validates the presented token, revokes it, and issues a new one.
// Implements reuse detection: if a revoked token is presented, the entire family is revoked.
//
// Atomicity has two layers:
//  1. Concurrent rotations on the same token: the claim-and-revoke step is a
//     single UPDATE ... WHERE state='active' RETURNING. Postgres row-level
//     locking guarantees exactly one concurrent caller wins, so two rotations
//     racing on the same input cannot both produce successor tokens.
//  2. Claim + successor insert: both run inside a single transaction. If the
//     insert fails (transient DB error, disk, etc.), the claim rolls back and
//     the original token remains active. Without this, a failed insert would
//     leave the original token revoked with no successor, and the client's
//     retry would trip reuse detection and nuke the whole family — turning a
//     transient glitch into a forced re-auth across all sessions.
func (s *RefreshTokenService) RotateRefreshToken(ctx context.Context, rawToken string, ttl int, presentedDPoPThumbprint string) (*domain.RefreshToken, *RefreshTokenResult, error) {
	tokenHash := hashRefreshToken(rawToken)

	newRawToken, err := generateRefreshToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}
	newTokenHash := hashRefreshToken(newRawToken)
	expiresAt := time.Now().Add(refreshTokenTTL(ttl))

	var claimed *domain.RefreshToken
	txErr := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		c, err := s.repo.ClaimByTokenHash(ctx, tx, tokenHash)
		if err != nil {
			return err
		}
		// DPoP binding check (RFC 9449 §5). A refresh token issued under
		// DPoP must rotate only when the presented proof carries the same
		// public key. Mismatch rolls back the transaction — the original
		// row stays active, so a failed-proof attempt does NOT consume
		// the token (no DoS via spamming bad proofs).
		if c.DPoPKeyThumbprint != "" && c.DPoPKeyThumbprint != presentedDPoPThumbprint {
			return ErrDPoPBindingMismatch
		}
		claimed = c

		successor := &domain.RefreshToken{
			TokenHash:  newTokenHash,
			ClientID:   c.ClientID,
			AccountID:  c.AccountID,
			ProjectID:  c.ProjectID,
			UserID:     c.UserID,
			IdentityID: c.IdentityID,
			Scopes:     c.Scopes,
			FamilyID:   c.FamilyID, // Same family — rotation chain.
			State:      domain.RefreshTokenStateActive,
			ExpiresAt:  expiresAt,
			// Bound tokens stay bound; UNBOUND tokens stay unbound, even if
			// the new rotation request carried a DPoP proof. Retroactive
			// binding-on-first-proof is a deliberate non-decision today —
			// the consequence is that a stolen unbound refresh can be
			// rotated with any DPoP key, but binding requires explicit
			// opt-in at original issuance. See docs/dpop-and-dcr.md
			// "Refresh-token binding" for the full rationale.
			DPoPKeyThumbprint: c.DPoPKeyThumbprint,
			// Carry the delegation tree forward (issue #81). Without this the
			// mission would survive the first refresh (seeded on the family at
			// issuance) but be lost on the second rotation, re-fragmenting the
			// tree. Copied verbatim like the DPoP thumbprint above.
			MissionID: c.MissionID,
		}
		return s.repo.Create(ctx, tx, successor)
	})
	if txErr != nil {
		if errors.Is(txErr, ErrDPoPBindingMismatch) {
			return nil, nil, ErrDPoPBindingMismatch
		}
		if errors.Is(txErr, sql.ErrNoRows) {
			return nil, nil, s.handleFailedClaim(ctx, tokenHash)
		}
		return nil, nil, fmt.Errorf("refresh token rotation failed: %w", txErr)
	}

	return claimed, &RefreshTokenResult{
		RawToken:  newRawToken,
		FamilyID:  claimed.FamilyID,
		ExpiresAt: expiresAt,
	}, nil
}

// handleFailedClaim runs when ClaimByTokenHash found no matching active,
// non-expired row. It disambiguates among four possibilities:
//
//  1. Revoked within the reuse grace window — treated as a legitimate concurrent
//     retry. Returns "already rotated" without revoking the family.
//  2. Revoked outside the grace window — genuine RFC 6749 §10.4 reuse signal.
//     Revokes the entire family and returns "reuse detected".
//  3. Expired — normal TTL expiry. Returns "expired".
//  4. Should-be-unreachable state (active and non-expired but claim still
//     missed). Logs at Error level and returns a generic error.
func (s *RefreshTokenService) handleFailedClaim(ctx context.Context, tokenHash string) error {
	existing, err := s.repo.GetByTokenHashIncludingRevoked(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("refresh token not found: %w", err)
	}

	if existing.State == domain.RefreshTokenStateRevoked {
		// Grace period: if the token was revoked very recently, treat the
		// second presentation as a concurrent retry (multiple tabs, a client
		// retry loop, a load balancer replay) rather than a replay attack.
		// The concurrent request gets a benign error but the freshly issued
		// successor — and therefore the user's session — survives.
		//
		// Outside the window, this is a genuine reuse signal (RFC 6749 §10.4)
		// and the whole family is revoked.
		if existing.RevokedAt != nil && time.Since(*existing.RevokedAt) < domain.RefreshTokenReuseGraceWindow {
			log.Info().
				Str("family_id", existing.FamilyID).
				Str("user_id", existing.UserID).
				Str("client_id", existing.ClientID).
				Dur("age", time.Since(*existing.RevokedAt)).
				Msg("Refresh token presented within reuse grace window — treating as concurrent retry")
			return fmt.Errorf("refresh token already rotated")
		}

		revoked, revokeErr := s.repo.RevokeFamily(ctx, existing.FamilyID)
		log.Warn().
			Str("family_id", existing.FamilyID).
			Str("user_id", existing.UserID).
			Str("client_id", existing.ClientID).
			Int("revoked_count", len(revoked)).
			Err(revokeErr).
			Msg("Refresh token reuse detected — entire family revoked")
		// Fan out one revocation event per revoked token after the family
		// revocation commits (detached; never blocks reuse-detection's response).
		s.dispatchRefreshRevocations(ctx, revoked, "refresh_token_reuse")
		return fmt.Errorf("refresh token reuse detected — family revoked")
	}

	if time.Now().After(existing.ExpiresAt) {
		return fmt.Errorf("refresh token expired")
	}

	// Should be unreachable: state is active and not expired, but ClaimByTokenHash
	// returned no row. Indicates clock skew or a concurrent state transition we
	// did not anticipate. Log loudly.
	log.Error().
		Str("family_id", existing.FamilyID).
		Str("state", existing.State).
		Time("expires_at", existing.ExpiresAt).
		Msg("Refresh token claim failed but lookup shows active non-expired token")
	return fmt.Errorf("refresh token in unexpected state")
}

// SetRevocationDispatcher attaches the shared revocation-event dispatcher.
// Wired once at server construction; shares the dispatcher with
// CredentialService. Nil-safe.
func (s *RefreshTokenService) SetRevocationDispatcher(d *RevocationDispatcher) {
	s.revocationDispatcher = d
}

// RevokeFamily revokes all active tokens in a refresh token family and fires a
// RevocationNotifier event per revoked token. Used during refresh-token reuse
// detection (RFC 6749 §10.4) and auth-code replay detection (§4.1.2) — the
// caller passes the reason so each path is labelled correctly on the emitted
// events (e.g. "refresh_token_reuse" vs "auth_code_replay").
//
// Returns the number of tokens revoked. The revocation commits before the
// events are dispatched (on the shared dispatcher's detached goroutine), so a
// slow subscriber never blocks reuse-detection's response.
func (s *RefreshTokenService) RevokeFamily(ctx context.Context, familyID, reason string) (int64, error) {
	revoked, err := s.repo.RevokeFamily(ctx, familyID)
	if err != nil {
		return 0, err
	}
	s.dispatchRefreshRevocations(ctx, revoked, reason)
	return int64(len(revoked)), nil
}

// dispatchRefreshRevocations maps revoked refresh-token rows into
// RevocationEvents and hands them to the shared dispatcher. The refresh token's
// UUID is used as the JTI surrogate (refresh tokens are opaque and carry no JWT
// id), and ExpiresAt is the token's own expiry so subscribers can size their
// deny-set TTL. No-op when no dispatcher/notifier is attached.
func (s *RefreshTokenService) dispatchRefreshRevocations(ctx context.Context, revoked []*domain.RefreshToken, reason string) {
	// hasNotifier short-circuit keeps the default no-listener path allocation-free:
	// skip building the events slice + mapping loop when nobody is subscribed.
	if s.revocationDispatcher == nil || !s.revocationDispatcher.hasNotifier() || len(revoked) == 0 {
		return
	}
	events := make([]RevocationEvent, 0, len(revoked))
	for _, rt := range revoked {
		identityID := ""
		if rt.IdentityID != nil {
			identityID = *rt.IdentityID
		}
		events = append(events, RevocationEvent{
			JTI:        rt.ID, // refresh tokens have no jti; the row UUID is the stable handle
			IdentityID: identityID,
			AccountID:  rt.AccountID,
			ProjectID:  rt.ProjectID,
			ExpiresAt:  rt.ExpiresAt,
			Reason:     reason,
			RevokedAt:  time.Now(),
		})
	}
	s.revocationDispatcher.Dispatch(ctx, events)
}

// refreshTokenTTL resolves the effective token lifetime: a positive
// ttlSeconds overrides the default; zero falls back to RefreshTokenTTLDays.
func refreshTokenTTL(ttlSeconds int) time.Duration {
	if ttlSeconds > 0 {
		return time.Duration(ttlSeconds) * time.Second
	}
	return time.Duration(domain.RefreshTokenTTLDays) * 24 * time.Hour
}

// generateRefreshToken creates a cryptographically random refresh token.
// Format: zid_rt_<base64url(32 random bytes)>
func generateRefreshToken() (string, error) {
	b := make([]byte, domain.RefreshTokenByteLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return domain.RefreshTokenPrefix + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// hashRefreshToken computes the SHA256 hex digest of a raw token.
func hashRefreshToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}
