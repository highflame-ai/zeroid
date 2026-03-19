package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// SignalSubscriber is a channel that receives CAE signals for real-time streaming.
type SignalSubscriber chan *domain.CAESignal

// SignalService handles CAE signal ingestion and fan-out to subscribers.
type SignalService struct {
	repo        *postgres.SignalRepository
	credRepo    *postgres.CredentialRepository
	mu          sync.RWMutex
	subscribers map[string]SignalSubscriber
}

// NewSignalService creates a new SignalService.
func NewSignalService(repo *postgres.SignalRepository, credRepo *postgres.CredentialRepository) *SignalService {
	return &SignalService{
		repo:        repo,
		credRepo:    credRepo,
		subscribers: make(map[string]SignalSubscriber),
	}
}

// IngestSignal records a new CAE signal and fans it out to subscribers.
func (s *SignalService) IngestSignal(ctx context.Context, accountID, projectID, identityID string, signalType domain.SignalType, severity domain.SignalSeverity, source string, payload map[string]any) (*domain.CAESignal, error) {
	signal := &domain.CAESignal{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		ProjectID:  projectID,
		IdentityID: identityID,
		SignalType: signalType,
		Severity:   severity,
		Source:     source,
		Payload:    payload,
		CreatedAt:  time.Now(),
	}

	if err := s.repo.Create(ctx, signal); err != nil {
		return nil, fmt.Errorf("failed to ingest signal: %w", err)
	}

	log.Info().
		Str("signal_id", signal.ID).
		Str("signal_type", string(signalType)).
		Str("severity", string(severity)).
		Str("identity_id", identityID).
		Msg("CAE signal ingested")

	// Auto-revoke all active credentials for high/critical severity signals.
	if identityID != "" && (severity == domain.SignalSeverityHigh || severity == domain.SignalSeverityCritical) {
		reason := fmt.Sprintf("auto-revoked by CAE signal %s (severity: %s)", signal.ID, severity)
		n, err := s.credRepo.RevokeAllActiveForIdentity(ctx, identityID, reason)
		if err != nil {
			log.Error().Err(err).Str("identity_id", identityID).Msg("Failed to auto-revoke credentials on high/critical signal")
		} else if n > 0 {
			log.Info().
				Int64("revoked_count", n).
				Str("identity_id", identityID).
				Str("signal_id", signal.ID).
				Msg("Auto-revoked credentials due to high/critical CAE signal")
		}
	}

	// Fan out only to subscribers for this tenant (keyed as "{accountID}:{projectID}:{uuid}").
	tenantPrefix := fmt.Sprintf("%s:%s:", accountID, projectID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for subID, ch := range s.subscribers {
		if !strings.HasPrefix(subID, tenantPrefix) {
			continue
		}
		select {
		case ch <- signal:
		default:
			log.Warn().Str("subscriber_id", subID).Msg("Signal subscriber channel full, dropping signal")
		}
	}

	return signal, nil
}

// Subscribe registers a new real-time subscriber for CAE signals.
func (s *SignalService) Subscribe(subscriberID string) SignalSubscriber {
	ch := make(SignalSubscriber, 100)
	s.mu.Lock()
	s.subscribers[subscriberID] = ch
	s.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber.
func (s *SignalService) Unsubscribe(subscriberID string) {
	s.mu.Lock()
	if ch, ok := s.subscribers[subscriberID]; ok {
		close(ch)
		delete(s.subscribers, subscriberID)
	}
	s.mu.Unlock()
}

// ListSignals returns recent signals for a tenant.
func (s *SignalService) ListSignals(ctx context.Context, accountID, projectID string, limit int) ([]*domain.CAESignal, error) {
	return s.repo.List(ctx, accountID, projectID, limit)
}
