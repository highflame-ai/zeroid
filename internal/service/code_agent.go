package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
)

// ErrCodeAgentAlreadyBootstrapped is returned when a re-bootstrap targets a
// machine whose code-agent identity is still active AND already has a custody
// key enrolled. Silently replacing that key from a bootstrap token would let a
// stolen developer session hijack an established identity (INV-IDN-004); the
// key may only rotate via the proof-of-possession path, or the machine must be
// revoked (which lets re-bootstrap mint a fresh identity). Handlers map this
// to 409.
var ErrCodeAgentAlreadyBootstrapped = errors.New("code_agent_already_bootstrapped")

// Code-agent bootstrap (highflame-architecture#136, epic #132 slice S3).
//
// A code agent (Claude Code, Cursor, ...) running on a developer machine
// bootstraps its identity with a zeroid:bootstrap-scoped developer token:
// it generates an EC P-256 custody keypair locally, registers the PUBLIC key
// here, and receives its identity plus a first access token in one call.
// Subsequent tokens are self-served via the jwt_bearer grant (assertion
// signed with the custody key) — no shared secret ever leaves the machine.
// The machine id recorded at bootstrap enables revoke-by-machine when a
// laptop is lost or compromised.

// codeAgentSubTypes is the set of sub-types a bootstrapped code agent may
// take. Narrower than agentSubTypes on purpose: a code agent is either the
// coordinating session (orchestrator) or a spawned single-purpose worker
// (tool_agent) — the human-proxy/evaluator/autonomous roles are not
// bootstrap-from-a-laptop shapes.
var codeAgentSubTypes = map[domain.SubType]bool{
	domain.SubTypeOrchestrator: true,
	domain.SubTypeToolAgent:    true,
}

// CodeAgentBootstrapRequest carries a code-agent bootstrap registration.
// Tenant + owner come from the validated bootstrap-token claims (never from
// the request body).
type CodeAgentBootstrapRequest struct {
	AccountID   string
	ProjectID   string
	OwnerUserID string
	// Framework identifies the code-agent runtime (e.g. claude-code, cursor).
	Framework string
	// MachineID is a stable identifier for the developer machine the custody
	// key lives on. Ends up in the WIMSE URI path, so it must be SPIFFE-clean.
	MachineID string
	// SubType defaults to orchestrator; only orchestrator and tool_agent are
	// valid for a bootstrapped code agent.
	SubType domain.SubType
	// PublicKeyPEM is the SPKI EC P-256 custody public key (required) —
	// verifies the agent's jwt_bearer assertions from the first token on.
	PublicKeyPEM string
	// Name is optional; defaults to "<framework>-<machineID short>".
	Name string
}

// CodeAgentBootstrapResponse is the result of a bootstrap registration:
// the registered identity plus its first access token, so the agent leaves
// the call already able to authenticate.
type CodeAgentBootstrapResponse struct {
	Identity    AgentResponse       `json:"identity"`
	WIMSEURI    string              `json:"wimse_uri"`
	AccessToken *domain.AccessToken `json:"access_token"`
}

// codeAgentExternalID derives the deterministic external_id for a
// (framework, machine) pair. Deterministic on purpose: identities are unique
// on (account_id, project_id, external_id), so a re-bootstrap from the same
// machine collides with its own previous registration. That collision is how
// we DETECT a re-bootstrap and refuse to silently swap a live key (see
// RegisterCodeAgentFromBootstrap). SPIFFE path segments forbid ":", so the
// joiner is "-".
func codeAgentExternalID(framework, machineID string) string {
	return fmt.Sprintf("code-agent-%s-%s", framework, machineID)
}

// randomExternalIDSuffix returns a short random hex token appended to the
// deterministic external_id when re-bootstrapping a machine whose previous
// identity was REVOKED — so recovery mints a fresh identity instead of
// colliding with (or resurrecting) the dead row. crypto/rand so it cannot
// collide predictably.
func randomExternalIDSuffix() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read failing is near-impossible; fall back to a timestamp so we
		// never return an empty (colliding) suffix.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// shortMachineID truncates a machine id for use in a human-readable name.
func shortMachineID(machineID string) string {
	if len(machineID) <= 8 {
		return machineID
	}
	return machineID[:8]
}

// RegisterCodeAgentFromBootstrap registers a code-agent identity from a
// developer machine and mints its first access token.
//
//   - TrustLevel is verified_third_party: the registration was authorized by
//     an authenticated developer's bootstrap token, but the runtime itself has
//     not attested — first_party stays reserved for attestation-backed trust.
//   - The identity is registered through RegisterAgent, which also creates a
//     linked API key. Code agents authenticate via jwt_bearer with the custody
//     key, not the API key; the key is accepted as harmless bootstrap baggage
//     because RegisterAgent has no skip flag (it is revoked with everything
//     else on deactivation).
//   - Re-bootstrap from the same (framework, machine): the deterministic
//     external_id collides; when the existing identity is ACTIVE and owned by
//     the SAME developer it is refreshed in place (custody key force-set to
//     the newly generated one — the bootstrap token is the authorization,
//     mirroring the admin recovery path) and a fresh first token is minted.
//     A different owner or a deactivated (revoked) identity is a 409-shaped
//     error: revoked machines stay revoked until an operator acts.
func (s *AgentService) RegisterCodeAgentFromBootstrap(ctx context.Context, req CodeAgentBootstrapRequest) (*CodeAgentBootstrapResponse, error) {
	if req.OwnerUserID == "" {
		return nil, fmt.Errorf("%w: owner user id is required", ErrInvalidIdentityField)
	}
	// framework + machine_id land in the WIMSE URI path via the derived
	// external_id — validate them as SPIFFE path segments up front so the
	// error names the offending field instead of the derived value.
	if err := domain.ValidateSPIFFEPathSegment("framework", req.Framework); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIdentityField, err)
	}
	if err := domain.ValidateSPIFFEPathSegment("machine_id", req.MachineID); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIdentityField, err)
	}

	subType := req.SubType
	if subType == "" {
		subType = domain.SubTypeOrchestrator
	}
	if !codeAgentSubTypes[subType] {
		return nil, fmt.Errorf("%w: invalid sub_type for a code agent: %q (allowed: %s, %s)",
			ErrInvalidIdentityField, subType, domain.SubTypeOrchestrator, domain.SubTypeToolAgent)
	}

	// The custody public key is the whole point of bootstrap — without it the
	// agent could never self-serve a jwt_bearer token.
	if req.PublicKeyPEM == "" {
		return nil, fmt.Errorf("%w: public_key_pem is required", ErrInvalidIdentityField)
	}
	if _, err := parseECPublicKeyPEM(req.PublicKeyPEM); err != nil {
		return nil, fmt.Errorf("%w: public_key_pem: %v", ErrInvalidIdentityField, err)
	}

	name := req.Name
	if name == "" {
		name = fmt.Sprintf("%s-%s", req.Framework, shortMachineID(req.MachineID))
	}

	baseExternalID := codeAgentExternalID(req.Framework, req.MachineID)

	register := func(externalID string) (*AgentRegistrationResponse, error) {
		return s.RegisterAgent(ctx, RegisterAgentRequest{
			AccountID:    req.AccountID,
			ProjectID:    req.ProjectID,
			Name:         name,
			ExternalID:   externalID,
			IdentityType: domain.IdentityTypeAgent,
			SubType:      subType,
			TrustLevel:   domain.TrustLevelVerifiedThirdParty,
			Framework:    req.Framework,
			CreatedBy:    req.OwnerUserID, // becomes OwnerUserID in RegisterIdentity
			PublicKeyPEM: req.PublicKeyPEM,
		})
	}

	var identity *domain.Identity
	var deactErr *IdentityDeactivatedConflictError
	reg, err := register(baseExternalID)
	switch {
	case err == nil:
		identity, err = s.identitySvc.GetIdentity(ctx, reg.Identity.ID, req.AccountID, req.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("failed to load registered code agent: %w", err)
		}
	case errors.Is(err, ErrIdentityAlreadyExists):
		// The deterministic external_id is held by an ACTIVE (usable) identity:
		// a re-bootstrap from a machine whose agent still exists.
		existing, gerr := s.identitySvc.GetIdentityByExternalID(ctx, baseExternalID, req.AccountID, req.ProjectID)
		if gerr != nil {
			return nil, fmt.Errorf("failed to load existing code agent for re-bootstrap: %w", gerr)
		}
		if existing.OwnerUserID != req.OwnerUserID {
			// Not this developer's agent — surface the original conflict (409).
			return nil, err
		}
		if !existing.Status.IsUsable() {
			// Suspended (not deactivated — that path is handled below). Fail
			// closed: an operator must resolve the suspension.
			return nil, fmt.Errorf("%w (status: %s)", domain.ErrIdentityNotUsable, existing.Status)
		}
		if existing.PublicKeyPEM != "" {
			// A custody key is already enrolled. Overwriting it from a bootstrap
			// token would let a stolen developer session swap the key of an
			// ESTABLISHED identity and impersonate the agent — the escalation
			// INV-IDN-004 forbids (an enrolled key rotates only via
			// proof-of-possession or admin authority, never a bearer token).
			// Refuse. Recovery: rotate via the countersigned PoP flow, or
			// revoke-by-machine then re-bootstrap (mints a fresh identity below).
			return nil, ErrCodeAgentAlreadyBootstrapped
		}
		// No key was ever enrolled — the trust-on-first-use window is still
		// open, so first-set is legitimate (this is enrolment, not rotation).
		identity, gerr = s.identitySvc.SetPublicKey(ctx, existing.ID, req.AccountID, req.ProjectID, req.PublicKeyPEM)
		if gerr != nil {
			return nil, fmt.Errorf("failed to set code agent custody key: %w", gerr)
		}
	case errors.As(err, &deactErr):
		// The deterministic external_id belongs to a DEACTIVATED identity — its
		// machine was revoked (lost/decommissioned laptop). Recovery mints a
		// BRAND-NEW identity under a fresh external_id; the revoked row stays
		// revoked so the retired agent's audit lineage is preserved and nothing
		// resurrects it.
		freshExternalID := baseExternalID + "-" + randomExternalIDSuffix()
		reg, err = register(freshExternalID)
		if err != nil {
			return nil, fmt.Errorf("re-bootstrap after machine revoke: %w", err)
		}
		identity, err = s.identitySvc.GetIdentity(ctx, reg.Identity.ID, req.AccountID, req.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("failed to load re-bootstrapped code agent: %w", err)
		}
		log.Info().
			Str("identity_id", identity.ID).
			Str("external_id", freshExternalID).
			Str("machine_id", req.MachineID).
			Msg("Code agent re-bootstrapped after revoke (fresh identity)")
	default:
		return nil, err
	}

	// Stamp the bootstrap columns. Bootstrap counts as the first attestation
	// (the developer token vouches for the machine at this instant).
	now := time.Now()
	if err := s.identitySvc.repo.SetBootstrapInfo(ctx, identity.ID, req.AccountID, req.ProjectID, req.MachineID, now); err != nil {
		return nil, fmt.Errorf("failed to record bootstrap machine: %w", err)
	}
	identity.BootstrapMachineID = req.MachineID
	identity.LastAttestedAt = &now

	// Mint the first access token. GrantType jwt_bearer: that is the grant
	// this agent will use for every subsequent self-served token, so the
	// first token is governed by the same policy axis (and the identity
	// policy is resolved + enforced at the chokepoint).
	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:              identity,
		GrantType:             domain.GrantTypeJWTBearer,
		ResolveIdentityPolicy: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to issue first code-agent token: %w", err)
	}

	log.Info().
		Str("identity_id", identity.ID).
		Str("external_id", identity.ExternalID).
		Str("machine_id", req.MachineID).
		Str("owner_user_id", req.OwnerUserID).
		Str("framework", req.Framework).
		Msg("Code agent bootstrapped")

	return &CodeAgentBootstrapResponse{
		Identity:    identityToAgentResponse(identity, s.getKeyPrefix(ctx, identity.ID)),
		WIMSEURI:    identity.WIMSEURI,
		AccessToken: accessToken,
	}, nil
}

// RecordCodeAgentAttestation refreshes the agent's attestation state:
// last_attested_at = now plus the caller-supplied evidence document (opaque
// JSON). Tenant-scoped. Returns the attestation timestamp.
func (s *AgentService) RecordCodeAgentAttestation(ctx context.Context, identityID, accountID, projectID string, evidence json.RawMessage) (time.Time, error) {
	if len(evidence) == 0 {
		evidence = json.RawMessage("{}")
	}
	now := time.Now()
	if err := s.identitySvc.repo.RecordAttestation(ctx, identityID, accountID, projectID, evidence, now); err != nil {
		return time.Time{}, err
	}
	return now, nil
}

// RevokeCodeAgentsByMachine deactivates every ACTIVE code agent bootstrapped
// from the given machine (optionally narrowed to one owner) — the
// lost/compromised-laptop response. Each agent goes through
// DeactivateIdentity, so the full cascade runs per agent: API keys swept,
// active credentials revoked, retirement CAE signal emitted. Returns the
// number of agents revoked; on a mid-sweep failure the count reflects the
// agents already revoked before the error.
func (s *AgentService) RevokeCodeAgentsByMachine(ctx context.Context, accountID, projectID, machineID, ownerUserID string) (int, error) {
	identities, err := s.identitySvc.repo.ListActiveByBootstrapMachine(ctx, accountID, projectID, machineID, ownerUserID)
	if err != nil {
		return 0, err
	}
	revoked := 0
	for _, identity := range identities {
		if _, err := s.identitySvc.DeactivateIdentity(ctx, identity.ID, accountID, projectID); err != nil {
			return revoked, fmt.Errorf("failed to revoke code agent %s: %w", identity.ID, err)
		}
		revoked++
	}
	log.Info().
		Str("machine_id", machineID).
		Str("owner_user_id", ownerUserID).
		Int("revoked", revoked).
		Msg("Code agents revoked by machine")
	return revoked, nil
}

// ListCodeAgentsByDeveloper returns every bootstrapped code agent owned by
// the given developer (all statuses — revoked agents stay visible in the
// developer's history).
func (s *AgentService) ListCodeAgentsByDeveloper(ctx context.Context, accountID, projectID, userID string) ([]AgentResponse, error) {
	identities, err := s.identitySvc.repo.ListBootstrappedByOwner(ctx, accountID, projectID, userID)
	if err != nil {
		return nil, err
	}
	agents := make([]AgentResponse, len(identities))
	for i, identity := range identities {
		agents[i] = identityToAgentResponse(identity, s.getKeyPrefix(ctx, identity.ID))
	}
	return agents, nil
}
