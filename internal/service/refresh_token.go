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
	"sync/atomic"
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
	// reuseGrace (nanoseconds) is how long after a rotation a second
	// presentation of the rotated-out token is refused as a concurrent retry
	// rather than treated as reuse (token.refresh_reuse_grace_seconds). 0 ⇒ no
	// grace. Atomic so Server.SetRefreshReuseGrace can change it at runtime.
	reuseGrace atomic.Int64
}

// NewRefreshTokenService creates a new refresh token service with the default
// reuse grace window (domain.RefreshTokenReuseGraceWindow); the server sets
// the configured one with SetReuseGrace.
func NewRefreshTokenService(repo *postgres.RefreshTokenRepository, db *bun.DB) *RefreshTokenService {
	s := &RefreshTokenService{repo: repo, db: db}
	s.reuseGrace.Store(int64(domain.RefreshTokenReuseGraceWindow))
	return s
}

// SetReuseGrace sets the refresh-token reuse grace window. A negative value
// is treated as 0 (no grace).
func (s *RefreshTokenService) SetReuseGrace(d time.Duration) {
	s.reuseGrace.Store(int64(max(d, 0)))
}

// ReuseGrace returns the current refresh-token reuse grace window.
func (s *RefreshTokenService) ReuseGrace() time.Duration {
	return time.Duration(s.reuseGrace.Load())
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
	// Audience is the server-recognized audience-profile name (e.g. "codeoid")
	// this refresh token was issued for by the external-principal exchange.
	// Persisted on the family so every rotation re-stamps the same `aud` claim
	// (and profile scopes) on the successor access token. Empty ⇒ a normal
	// (non-audience) refresh token whose rotation carries no `aud`.
	Audience string
	// Resources is the RFC 8707 resource CEILING this refresh token was issued
	// for (CAP-IDN-027). Persisted on the family so every rotation re-stamps
	// the same binding on the successor access token. Empty ⇒ an unbound
	// refresh token whose rotation carries no `resource` claim.
	Resources []string
	// PrincipalIss is the issuer of the family's user subject — the access
	// token's principal_iss. Persisted so a person's refresh families are
	// revoked by the RFC 9493 (issuer, subject) pair, and so the refreshed
	// token keeps the same principal.
	PrincipalIss string
	// FamilyID optionally fixes the id of the family this token starts, for a
	// caller that must stamp it on the access token it issues BEFORE the
	// refresh token exists (so the access token is revoked with the family).
	// Must be a fresh UUID; empty ⇒ one is generated here.
	FamilyID string
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

// RefreshTokenReuseError is returned by RotateRefreshToken when the presented
// refresh token had already been rotated, longer ago than the reuse grace
// window, or its family was revoked — the reuse signal of RFC 9700 §4.14.2. By the time it is returned, every refresh token
// in the family has been revoked. FamilyID lets the caller revoke the access
// tokens issued under the family as well. Callers MUST answer it with the
// same invalid_grant as any other unusable refresh token, so the response
// does not tell the presenter that reuse was detected.
type RefreshTokenReuseError struct {
	FamilyID string
}

func (e *RefreshTokenReuseError) Error() string {
	return "refresh token reuse detected — family revoked"
}

// NewRefreshFamilyID returns a fresh family id for RefreshTokenParams.FamilyID.
func NewRefreshFamilyID() string {
	return uuid.New().String()
}

// IssueRefreshToken generates a new refresh token and starts a new token family.
func (s *RefreshTokenService) IssueRefreshToken(ctx context.Context, params *RefreshTokenParams) (*RefreshTokenResult, error) {
	rawToken, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	tokenHash := hashRefreshToken(rawToken)
	familyID := params.FamilyID
	if familyID == "" {
		familyID = NewRefreshFamilyID()
	}
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
		Audience:          params.Audience,
		Resources:         params.Resources,
		PrincipalIss:      params.PrincipalIss,
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
// reuse detection (that only fires inside RotateRefreshToken's claim path).
func (s *RefreshTokenService) PeekRefreshToken(ctx context.Context, rawToken string) (*domain.RefreshToken, error) {
	return s.repo.GetByTokenHash(ctx, hashRefreshToken(rawToken))
}

// PeekRefreshTokenIncludingRevoked returns the refresh-token row for the
// presented raw token REGARDLESS of state (active, revoked, or expired),
// without consuming it. It exists for reading STATE-INDEPENDENT binding
// metadata — specifically the audience-profile name — so the refresh grant can
// route an already-rotated audience-profile token down the same audience path
// (where RotateRefreshToken's claim step then fires the correct reuse
// detection) instead of misrouting it to the OAuth-client path, which has no
// client for a client-less audience token and would 401 before reuse detection
// ran. It MUST NOT be used for authorization decisions — an active-only
// PeekRefreshToken / the rotation claim remains the security gate. Returns an
// error only when no row matches (genuinely unknown token).
func (s *RefreshTokenService) PeekRefreshTokenIncludingRevoked(ctx context.Context, rawToken string) (*domain.RefreshToken, error) {
	return s.repo.GetByTokenHashIncludingRevoked(ctx, hashRefreshToken(rawToken))
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
			// Carry the audience-profile forward so every rotation re-stamps the
			// same `aud` claim on its access token. Without this the audience
			// would survive the first refresh (seeded at issuance) but be lost on
			// the second rotation, and the harness daemon would reject the token.
			Audience: c.Audience,
			// Carry the RFC 8707 resource ceiling forward, for the same reason and
			// with a worse failure mode (CAP-IDN-027). Lose it here and the
			// binding survives the first refresh but vanishes on the second — and
			// an access token with no `resource` claim is not rejected, it is
			// honoured EVERYWHERE: INV-IDN-006 keys on the claim's presence and
			// passes the request through untouched when it is absent. So the
			// symptom of dropping this line is not a broken session but a silent
			// loss of enforcement. TestResourceCeiling_SurvivesTwoRotations
			// rotates twice to pin exactly this.
			Resources: c.Resources,
			// Carry the principal's issuer forward. Lose it and the family
			// drops out of per-user revocation after its first rotation,
			// because the (issuer, subject) match no longer finds it, and the
			// refreshed token falls back to ZeroID's own issuer for a user an
			// external IdP vouched for.
			PrincipalIss: c.PrincipalIss,
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

// ErrRefreshTokenAlreadyRotated is returned by RotateRefreshToken when the
// presented token was rotated out within the reuse grace window and its family
// is still live: a concurrent retry, refused without revoking anything. The
// refresh grant answers it with the same invalid_grant as any other unusable
// refresh token.
var ErrRefreshTokenAlreadyRotated = errors.New("refresh token already rotated")

// handleFailedClaim runs when ClaimByTokenHash found no matching active,
// non-expired row. It disambiguates among four possibilities:
//
//  1. Rotated out within the reuse grace window (ReuseGrace) — treated as a
//     concurrent retry: several tabs or processes sharing one refresh token,
//     or a client retry loop. Returns ErrRefreshTokenAlreadyRotated and
//     revokes nothing, so the successor and the session survive.
//  2. Revoked otherwise — rotated out longer ago than the window, or revoked
//     by anything other than rotation (its family revoked by reuse detection,
//     RFC 7009 revocation, authorization-code replay). The reuse signal of RFC
//     9700 §4.14.2: revoke every refresh token in the family and return a
//     *RefreshTokenReuseError so the caller revokes the family's access tokens.
//  3. Expired — normal TTL expiry. Returns "expired".
//  4. Should-be-unreachable state (active and non-expired but claim still
//     missed). Logs at Error level and returns a generic error.
//
// Telling rotation from other revocations: refresh tokens are revoked in only
// two ways — the rotation claim, which inserts an active successor in the
// same transaction, and RevokeFamily, which revokes every active token in the
// family. So a revoked token whose family still has an active token was
// rotated out (the active token is its successor, or a later one), and a
// revoked token whose family has none was revoked with its family and gets no
// grace. RestoreRotation does not break this: it swaps the active successor
// for the reactivated predecessor in one transaction, so the family is never
// seen without an active token while a restore runs, and it never reactivates
// anything in a family RevokeFamily has revoked.
//
// The grace window trades strictness for availability. Within it a replay of
// a stolen rotated-out token is refused without revoking the family, so
// whichever party rotated first keeps the session; 0 disables it.
//
// The one retry that would otherwise be punished for no reason outside the
// window — the server consumed the token and then failed before answering —
// is handled where it happens: RestoreRotation puts the presented token back,
// so the client's retry rotates normally.
func (s *RefreshTokenService) handleFailedClaim(ctx context.Context, tokenHash string) error {
	existing, err := s.repo.GetByTokenHashIncludingRevoked(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("refresh token not found: %w", err)
	}

	if existing.State == domain.RefreshTokenStateRevoked {
		if grace := s.ReuseGrace(); grace > 0 && existing.RevokedAt != nil && time.Since(*existing.RevokedAt) < grace {
			live, liveErr := s.repo.FamilyHasActiveToken(ctx, existing.FamilyID)
			if liveErr != nil {
				// Refuse without revoking: the token is not usable either way,
				// and a lookup failure must not decide to end the session.
				return fmt.Errorf("refresh token reuse check failed: %w", liveErr)
			}
			if live {
				log.Info().
					Str("family_id", existing.FamilyID).
					Str("user_id", existing.UserID).
					Str("client_id", existing.ClientID).
					Dur("age", time.Since(*existing.RevokedAt)).
					Dur("grace", grace).
					Msg("Rotated-out refresh token presented within the reuse grace window — treating as a concurrent retry")
				return ErrRefreshTokenAlreadyRotated
			}
		}

		revoked, revokeErr := s.repo.RevokeFamily(ctx, existing.FamilyID)
		log.Warn().
			Str("family_id", existing.FamilyID).
			Str("user_id", existing.UserID).
			Str("client_id", existing.ClientID).
			Int("revoked_count", len(revoked)).
			Err(revokeErr).
			Msg("Refresh token reuse detected — entire family revoked")
		if revokeErr != nil {
			// The presented token is still refused (it is revoked), but the
			// family could not be: surface a server-side failure rather than a
			// reuse error whose contract is "the family is already revoked".
			return fmt.Errorf("refresh token reuse detected, family revocation failed: %w", revokeErr)
		}
		// Fan out one revocation event per revoked token after the family
		// revocation commits (detached; never blocks reuse-detection's response).
		s.dispatchRefreshRevocations(ctx, revoked, "refresh_token_reuse")
		return &RefreshTokenReuseError{FamilyID: existing.FamilyID}
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

// RestoreRotation undoes a rotation whose response the client never received
// because the server failed after RotateRefreshToken committed (access-token
// issuance failed, or a post-claim gate rejected the request). It deletes the
// successor and reactivates the presented token, so the client's retry with
// the token it still holds rotates normally instead of being treated as reuse
// and revoking the family.
//
// It only ever undoes an UNUSED successor: the successor must still be active,
// which it is not if it has since been rotated itself or if a replay of the
// presented token already revoked the family. In those cases nothing changes
// and RestoreRotation reports false. Both statements run in one transaction
// with guarded WHERE clauses, so a family that reuse detection revoked first
// is never brought back.
func (s *RefreshTokenService) RestoreRotation(ctx context.Context, claimed *domain.RefreshToken, successor *RefreshTokenResult) (bool, error) {
	if claimed == nil || successor == nil {
		return false, nil
	}
	restored := false
	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		ok, err := s.repo.RestoreClaimed(ctx, tx, claimed.ID, claimed.FamilyID, hashRefreshToken(successor.RawToken))
		restored = ok
		return err
	})
	if err != nil {
		return false, fmt.Errorf("failed to restore refresh token rotation: %w", err)
	}
	return restored, nil
}

// IsRefreshTokenActive reports whether the raw refresh token is still active
// and unexpired. A DB error is returned as an error, not as "inactive".
func (s *RefreshTokenService) IsRefreshTokenActive(ctx context.Context, rawToken string) (bool, error) {
	_, err := s.repo.GetByTokenHash(ctx, hashRefreshToken(rawToken))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
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
