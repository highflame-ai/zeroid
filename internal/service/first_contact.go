package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// First contact (docs/external-issuers.md, "First contact"): a credential
// that verified in full under an enabled issuer row, and names an agent no
// enabled binding maps, is handled as the row's first_contact says.
//
// With no binding at all, discover registers the agent unadopted and refuses
// the request; adopt registers it adopted under the row's mapping and serves
// the request. With only a disabled binding, adopt applies the same mapping
// to the agent's existing identity (standing adoption) when that identity is
// still discovered, sits in the mapped project, is no approval channel, and
// no person disabled the binding; discover leaves it as it is, already in
// the adoption queue.
//
// It never creates a person or a membership, never trusts an issuer that is
// not already a row, never acts on a disabled row, and never overrides a
// person's decision: an explicitly disabled binding, an identity a person has
// taken on (pending), activated, suspended or dismissed, or an identity in
// another project keeps today's behaviour.

// FirstContactActor is the audit actor of every row first contact writes,
// and the created_by or updated_by it leaves on them. The system: prefix is
// reserved, so no admin caller can claim it.
const FirstContactActor = middleware.SystemCallerPrefix + "first_contact"

// Defaults for the first-contact bounds.
const (
	DefaultFirstContactRatePerMinute           = 10
	DefaultFirstContactMaxDiscoveredPerAccount = 500
)

// FirstContactConfig bounds first contact. Past either bound nothing is
// written, the credential is refused as without first contact, and the
// reason is logged.
type FirstContactConfig struct {
	// RatePerMinute caps the registrations and standing adoptions under one
	// issuer row in any minute. Zero means DefaultFirstContactRatePerMinute.
	RatePerMinute int
	// MaxDiscoveredPerAccount caps an account's first-contact identities that
	// are still discovered (unadopted). Zero means
	// DefaultFirstContactMaxDiscoveredPerAccount. Adopt registers adopted
	// identities, which this does not count.
	MaxDiscoveredPerAccount int
}

// errFirstContactOriginReserved refuses the first_contact origin to every
// caller but first contact itself.
var errFirstContactOriginReserved = fmt.Errorf("%w: origin %q is reserved for identities registered on first contact",
	ErrInvalidIdentityField, domain.OriginFirstContact)

// errFirstContactExternalIDReserved refuses an external_id in first
// contact's namespace to every caller but first contact itself.
var errFirstContactExternalIDReserved = fmt.Errorf("%w: an external_id starting with %q is reserved for identities registered on first contact",
	ErrInvalidIdentityField, domain.FirstContactExternalIDPrefix)

// reservedFirstContactExternalID reports whether externalID is in first
// contact's namespace.
func reservedFirstContactExternalID(externalID string) bool {
	return strings.HasPrefix(externalID, domain.FirstContactExternalIDPrefix)
}

// FirstContactRegistrar registers agents on first contact, and applies an
// adopt row's standing adoption to agents that are bound already.
type FirstContactRegistrar struct {
	issuers    *postgres.ExternalIssuerRepository
	identities *IdentityService
	cfg        FirstContactConfig
}

// NewFirstContactRegistrar builds the registrar. Zero bounds take the
// defaults.
func NewFirstContactRegistrar(issuers *postgres.ExternalIssuerRepository, identities *IdentityService, cfg FirstContactConfig) *FirstContactRegistrar {
	if cfg.RatePerMinute <= 0 {
		cfg.RatePerMinute = DefaultFirstContactRatePerMinute
	}
	if cfg.MaxDiscoveredPerAccount <= 0 {
		cfg.MaxDiscoveredPerAccount = DefaultFirstContactMaxDiscoveredPerAccount
	}
	return &FirstContactRegistrar{issuers: issuers, identities: identities, cfg: cfg}
}

// SetFirstContact enables first-contact registration on the grants that
// support it (federated client assertions and ID-JAGs, with issuer rows).
// Nil leaves it off whatever the rows say.
func (s *OAuthService) SetFirstContact(r *FirstContactRegistrar) {
	s.firstContact = r
}

// firstContactOutcome is what a first-contact attempt did. It is the outcome
// attribute of the first-contact log line and metric.
type firstContactOutcome string

const (
	// firstContactRegistered: an identity and its binding were created.
	firstContactRegistered firstContactOutcome = "registered"
	// firstContactAdopted: an adopt row's standing mapping activated the
	// agent's existing discovered identity and enabled its binding.
	firstContactAdopted firstContactOutcome = "adopted"
	// firstContactAlreadyBound: the subject's bindings changed after the
	// request read them (a concurrent first contact or a person bound,
	// enabled or deleted one), or the agent is bound but unadopted under a
	// discover row; the grant reads them again and decides as usual.
	firstContactAlreadyBound firstContactOutcome = "already_bound"
	// firstContactRowChanged: the row was disabled, deleted, switched off or
	// re-mapped after the request read it.
	firstContactRowChanged firstContactOutcome = "row_changed"
	// firstContactRateLimited: the row's per-minute bound was reached.
	firstContactRateLimited firstContactOutcome = "rate_limited"
	// firstContactAccountCap: the account's cap on unadopted first-contact
	// identities was reached.
	firstContactAccountCap firstContactOutcome = "account_cap"
	// firstContactExternalIDTaken: the project already has an identity with
	// the external_id first contact would use, and no binding links it to
	// this subject. First contact never takes over an existing identity.
	firstContactExternalIDTaken firstContactOutcome = "external_id_taken"
	// firstContactSubjectTooLong: the subject key is longer than a binding
	// holds.
	firstContactSubjectTooLong firstContactOutcome = "subject_too_long"
	// firstContactRegisteredClient: an ID-JAG redeemed by a registered OAuth
	// client. Such a client must be linked to the agent it acts for, and first
	// contact neither creates nor links clients.
	firstContactRegisteredClient firstContactOutcome = "registered_client"

	// Why an adopt row's standing mapping left an agent that has only a
	// disabled binding as it is. The grant refuses as without first contact.

	// firstContactExplicitlyDisabled: a person disabled one of the subject's
	// bindings under the row, and that decision wins.
	firstContactExplicitlyDisabled firstContactOutcome = "explicitly_disabled"
	// firstContactAmbiguousBinding: more than one binding maps the subject
	// key, so which identity is the agent is for a person to decide.
	firstContactAmbiguousBinding firstContactOutcome = "ambiguous_binding"
	// firstContactNotDiscovered: the bound identity is not discovered: a
	// person has taken it on (pending), activated, suspended or dismissed it.
	firstContactNotDiscovered firstContactOutcome = "not_discovered"
	// firstContactOtherProject: the bound identity is not in the row's
	// account and first_contact_project_id.
	firstContactOtherProject firstContactOutcome = "other_project"
	// firstContactApprovalChannel: the bound identity is an approval channel,
	// which only a person activates.
	firstContactApprovalChannel firstContactOutcome = "approval_channel"
)

// rereads reports whether the grant reads the subject's bindings again after
// an attempt with this outcome.
func (o firstContactOutcome) rereads() bool {
	return o == firstContactRegistered || o == firstContactAdopted || o == firstContactAlreadyBound
}

// firstContactResult is what a first-contact attempt did.
type firstContactResult struct {
	outcome firstContactOutcome
	// identity is the identity registered or adopted, when there is one.
	identity *domain.Identity
	// candidate is the bound identity a standing adoption declined, when it
	// got as far as reading one.
	candidate string
}

// firstContactArrival is a credential that verified in full and named an
// agent no enabled binding maps.
type firstContactArrival struct {
	row        *domain.ExternalIssuer
	subjectKey string
	grant      string
	// claims are the credential's verified claims. Only an allowlisted subset
	// is kept (firstContactRecord).
	claims map[string]any
}

// firstContactFunc is the first-contact step bindAgent runs when no enabled
// binding maps the subject key. existing are the bindings bindAgent read:
// none, or only disabled ones. It reports whether a binding was created or
// enabled, here or concurrently, so the caller reads the bindings again.
type firstContactFunc func(ctx context.Context, existing []*domain.IssuerBinding) (bool, error)

// firstContactFor returns the first-contact step for a credential that
// verified under row, or nil when nothing would happen: no registrar, a
// static issuer, a disabled row, or first_contact off. prepare, when set,
// runs before anything is written and may decline with an outcome (nothing
// is written, the attempt is logged, and the grant refuses as without first
// contact) or refuse the request with an error.
func (s *OAuthService) firstContactFor(row *domain.ExternalIssuer, subjectKey, grant string, claims map[string]any,
	prepare func(ctx context.Context) (firstContactOutcome, error),
) firstContactFunc {
	if s.firstContact == nil || row == nil || !row.Enabled || !row.FirstContact.On() {
		return nil
	}
	return func(ctx context.Context, existing []*domain.IssuerBinding) (bool, error) {
		// An agent bound but not enabled is first contact's only under an
		// adopt row. Under discover it is in the adoption queue already, and
		// is refused as it always was, with nothing logged here.
		if len(existing) > 0 && row.FirstContact != domain.FirstContactAdopt {
			return false, nil
		}
		a := firstContactArrival{row: row, subjectKey: subjectKey, grant: grant, claims: claims}
		if prepare != nil {
			declined, err := prepare(ctx)
			if err != nil {
				return false, err
			}
			if declined != "" {
				recordFirstContact(ctx, a, row.FirstContact, firstContactResult{outcome: declined})
				return false, nil
			}
		}
		res, err := s.firstContact.arrive(ctx, a)
		if err != nil {
			return false, oauthServerError("failed to apply first contact to the agent", err)
		}
		recordFirstContact(ctx, a, row.FirstContact, res)
		return res.outcome.rereads(), nil
	}
}

// Sentinels that end the first-contact transaction after a failed write.
var (
	errFirstContactTaken = errors.New("first contact: external_id taken")
	errFirstContactRace  = errors.New("first contact: binding created or enabled concurrently")
)

// arrive applies first contact to a in one transaction under the account's
// first-contact lock. Under the lock it re-reads the row and the subject's
// bindings and decides on what it reads: with no binding it registers the
// agent, and with only a disabled one under an adopt row it applies the
// row's standing adoption. Every result but an error leaves the grant to
// read the bindings and decide as usual.
func (r *FirstContactRegistrar) arrive(ctx context.Context, a firstContactArrival) (firstContactResult, error) {
	row := a.row
	if len(a.subjectKey) > domain.MaxSubjectKeyBytes {
		return firstContactResult{outcome: firstContactSubjectTooLong}, nil
	}
	project := row.FirstContactProjectID
	// The project's default credential policy is ensured before the
	// transaction: created inside it, a concurrent creation would abort the
	// transaction instead of being read back.
	if _, err := r.identities.policySvc.EnsureDefaultPolicy(ctx, row.AccountID, project); err != nil {
		return firstContactResult{}, err
	}

	var res firstContactResult
	err := r.issuers.DB().RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		ctx = postgres.WithTx(ctx, tx)
		// The audit actor of every write, and the identity's modified_by.
		ctx = middleware.SetCallerName(ctx, FirstContactActor)
		if err := r.issuers.SetAuditActor(ctx, FirstContactActor); err != nil {
			return err
		}
		if err := r.issuers.LockFirstContact(ctx, row.AccountID); err != nil {
			return err
		}
		// The row as it is now, held against a concurrent delete: disabled,
		// switched off or re-mapped since the request read it, it writes
		// nothing.
		fresh, err := r.issuers.GetForShare(ctx, row.ID, row.AccountID)
		if errors.Is(err, sql.ErrNoRows) {
			res.outcome = firstContactRowChanged
			return nil
		}
		if err != nil {
			return err
		}
		if !fresh.Enabled || fresh.Kind != row.Kind || !fresh.FirstContact.On() || fresh.FirstContactProjectID != project {
			res.outcome = firstContactRowChanged
			return nil
		}
		// Under the lock, so two first contacts for one subject make one
		// identity or one activation: the second finds the first's binding.
		existing, err := r.issuers.BindingsFor(ctx, row.ID, a.subjectKey)
		if err != nil {
			return err
		}
		switch {
		case len(existing) == 0:
			res, err = r.registerLocked(ctx, a, fresh)
		case existing[0].Enabled || fresh.FirstContact != domain.FirstContactAdopt:
			res.outcome = firstContactAlreadyBound
		default:
			res, err = r.adoptLocked(ctx, a, fresh, existing)
		}
		return err
	})
	switch {
	case errors.Is(err, errFirstContactTaken):
		return firstContactResult{outcome: firstContactExternalIDTaken}, nil
	case errors.Is(err, errFirstContactRace):
		return firstContactResult{outcome: firstContactAlreadyBound}, nil
	case err != nil:
		return firstContactResult{}, err
	}
	return res, nil
}

// registerLocked creates the identity and binding for an agent no binding
// maps, in arrive's transaction. fresh is the row as read under the lock.
func (r *FirstContactRegistrar) registerLocked(ctx context.Context, a firstContactArrival, fresh *domain.ExternalIssuer) (firstContactResult, error) {
	row, project, mode := a.row, fresh.FirstContactProjectID, fresh.FirstContact
	recent, err := r.issuers.CountBindingsWrittenBySince(ctx, row.ID, FirstContactActor, time.Now().Add(-time.Minute))
	if err != nil {
		return firstContactResult{}, err
	}
	if recent >= r.cfg.RatePerMinute {
		return firstContactResult{outcome: firstContactRateLimited}, nil
	}
	if mode == domain.FirstContactDiscover {
		n, err := r.identities.repo.CountByOriginAndStatus(ctx, row.AccountID, domain.OriginFirstContact, domain.IdentityStatusDiscovered)
		if err != nil {
			return firstContactResult{}, err
		}
		if n >= r.cfg.MaxDiscoveredPerAccount {
			return firstContactResult{outcome: firstContactAccountCap}, nil
		}
	}

	externalID := firstContactExternalID(row.ID, a.subjectKey)
	if _, err := r.identities.repo.GetByExternalID(ctx, externalID, row.AccountID, project); err == nil {
		return firstContactResult{outcome: firstContactExternalIDTaken}, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return firstContactResult{}, err
	}

	labels, metadata, err := firstContactMarkers(a, fresh)
	if err != nil {
		return firstContactResult{}, err
	}
	req := RegisterIdentityRequest{
		AccountID:    row.AccountID,
		ProjectID:    project,
		ExternalID:   externalID,
		Name:         firstContactName(a.subjectKey),
		IdentityType: domain.IdentityTypeAgent,
		TrustLevel:   domain.TrustLevelUnverified,
		Origin:       domain.OriginFirstContact,
		OwnerUserID:  fresh.FirstContactOwnerUserID,
		Labels:       labels,
		Metadata:     metadata,
		CreatedBy:    FirstContactActor,
		firstContact: true,
	}
	if mode == domain.FirstContactAdopt {
		// The row's standing mapping is the adoption: the agent is adopted
		// into the mapped project, owned by the mapped user, and vouched for
		// by an issuer the account trusts.
		req.adopted = true
		req.TrustLevel = domain.TrustLevelVerifiedThirdParty
	}
	created, err := r.identities.RegisterIdentity(ctx, req)
	if err != nil {
		var deactivated *IdentityDeactivatedConflictError
		if errors.Is(err, ErrIdentityAlreadyExists) || errors.As(err, &deactivated) {
			return firstContactResult{}, errFirstContactTaken
		}
		return firstContactResult{}, err
	}
	binding := &domain.IssuerBinding{
		AccountID:  row.AccountID,
		IssuerID:   row.ID,
		SubjectKey: a.subjectKey,
		IdentityID: created.ID,
		// discover: disabled until the agent is adopted, as a binding for
		// any unadopted identity is. Not explicitly disabled, so adoption
		// enables it.
		Enabled:   mode == domain.FirstContactAdopt,
		CreatedBy: FirstContactActor,
		UpdatedBy: FirstContactActor,
	}
	if err := r.issuers.InsertBinding(ctx, binding); err != nil {
		if isDuplicateKeyError(err) {
			return firstContactResult{}, errFirstContactRace
		}
		return firstContactResult{}, err
	}
	return firstContactResult{outcome: firstContactRegistered, identity: created}, nil
}

// adoptLocked applies an adopt row's standing mapping to the agent the
// subject key already names through a disabled binding, in arrive's
// transaction: the identity goes discovered → active, owned by the mapped
// user, verified_third_party, with the project's default credential policy
// if it has none, and its binding is enabled. Through the identity service's
// lifecycle transition, so its owner rule and audit row apply.
//
// The identity's row is locked before the binding's, the order in which a
// purge's cascade takes them, and every guard is checked on the locked rows:
// a person's concurrent disable, adoption or dismissal either commits first
// and is seen here, or waits for this transaction.
func (r *FirstContactRegistrar) adoptLocked(ctx context.Context, a firstContactArrival, fresh *domain.ExternalIssuer,
	existing []*domain.IssuerBinding,
) (firstContactResult, error) {
	if fresh.FirstContactOwnerUserID == "" {
		return firstContactResult{outcome: firstContactRowChanged}, nil
	}
	candidate, outcome := standingAdoptionBinding(existing)
	if outcome != "" {
		return firstContactResult{outcome: outcome}, nil
	}
	res := firstContactResult{candidate: candidate.IdentityID}
	identity, err := r.identities.repo.GetByIDInAccountForUpdate(ctx, candidate.IdentityID, fresh.AccountID)
	if errors.Is(err, sql.ErrNoRows) {
		res.outcome = firstContactOtherProject
		return res, nil
	}
	if err != nil {
		return firstContactResult{}, err
	}
	binding, err := r.issuers.GetBindingForUpdate(ctx, candidate.ID, fresh.AccountID)
	if errors.Is(err, sql.ErrNoRows) {
		// Deleted since it was read: the grant reads the bindings again.
		res.outcome = firstContactAlreadyBound
		return res, nil
	}
	if err != nil {
		return firstContactResult{}, err
	}
	if res.outcome = standingAdoptionRefusal(fresh, binding, identity); res.outcome != "" {
		return res, nil
	}
	if channel, err := r.identities.IsApprovalChannel(ctx, identity); err != nil {
		return firstContactResult{}, err
	} else if channel {
		res.outcome = firstContactApprovalChannel
		return res, nil
	}
	recent, err := r.issuers.CountBindingsWrittenBySince(ctx, fresh.ID, FirstContactActor, time.Now().Add(-time.Minute))
	if err != nil {
		return firstContactResult{}, err
	}
	if recent >= r.cfg.RatePerMinute {
		res.outcome = firstContactRateLimited
		return res, nil
	}

	labels, metadata, err := standingAdoptionMarkers(identity, a, fresh)
	if err != nil {
		return firstContactResult{}, err
	}
	active := domain.IdentityStatusActive
	update := UpdateIdentityRequest{
		Status:      &active,
		OwnerUserID: fresh.FirstContactOwnerUserID,
		TrustLevel:  domain.TrustLevelVerifiedThirdParty,
		Labels:      labels,
		Metadata:    metadata,
	}
	if identity.CredentialPolicyID == "" {
		// No policy of its own: the project's default, as a registered agent
		// gets.
		projectDefault := ""
		update.CredentialPolicyID = &projectDefault
	}
	adopted, err := r.identities.UpdateIdentity(ctx, identity.ID, identity.AccountID, identity.ProjectID, update)
	if err != nil {
		return firstContactResult{}, err
	}
	binding.Enabled = true
	binding.ExplicitlyDisabled = false
	binding.UpdatedBy = FirstContactActor
	if err := r.issuers.UpdateBinding(ctx, binding, false); err != nil {
		if isDuplicateKeyError(err) {
			// Another of the subject's bindings was enabled meanwhile.
			return firstContactResult{}, errFirstContactRace
		}
		return firstContactResult{}, err
	}
	res.outcome, res.identity = firstContactAdopted, adopted
	return res, nil
}

// standingAdoptionBinding returns the one binding a standing adoption may act
// on among the subject's bindings under the row (all disabled), or why there
// is none. A person's explicit disable on any of them wins, and two or more
// leave the choice of identity to a person.
func standingAdoptionBinding(existing []*domain.IssuerBinding) (*domain.IssuerBinding, firstContactOutcome) {
	for _, b := range existing {
		if b.ExplicitlyDisabled {
			return nil, firstContactExplicitlyDisabled
		}
	}
	if len(existing) != 1 {
		return nil, firstContactAmbiguousBinding
	}
	return existing[0], ""
}

// standingAdoptionRefusal says why row's standing mapping does not adopt
// identity through binding, or "" when it does: the binding must still be
// disabled and not explicitly, and the identity discovered, in the row's
// account and first_contact_project_id. The approval-channel check, which
// reads the identity's policy, is left to the caller.
func standingAdoptionRefusal(row *domain.ExternalIssuer, binding *domain.IssuerBinding, identity *domain.Identity) firstContactOutcome {
	switch {
	case binding.Enabled:
		return firstContactAlreadyBound
	case binding.ExplicitlyDisabled:
		return firstContactExplicitlyDisabled
	case identity.Status != domain.IdentityStatusDiscovered:
		return firstContactNotDiscovered
	case identity.AccountID != row.AccountID || identity.ProjectID != row.FirstContactProjectID:
		return firstContactOtherProject
	}
	return ""
}

// standingAdoptionCandidate is what a standing adoption would do for the
// subject's bindings under an adopt row, read without locks: the identity it
// would activate, or why it would not. The ID-JAG grant reads it before it
// resolves the person and spends the jti; arrive decides again under the
// lock.
func (r *FirstContactRegistrar) standingAdoptionCandidate(ctx context.Context, row *domain.ExternalIssuer,
	existing []*domain.IssuerBinding,
) (string, firstContactOutcome, error) {
	binding, outcome := standingAdoptionBinding(existing)
	if outcome != "" {
		return "", outcome, nil
	}
	identity, err := r.identities.repo.GetByIDInAccounts(ctx, binding.IdentityID, []string{row.AccountID})
	if errors.Is(err, sql.ErrNoRows) {
		return binding.IdentityID, firstContactOtherProject, nil
	}
	if err != nil {
		return "", "", err
	}
	if outcome := standingAdoptionRefusal(row, binding, identity); outcome != "" {
		return identity.ID, outcome, nil
	}
	channel, err := r.identities.IsApprovalChannel(ctx, identity)
	if err != nil {
		return "", "", err
	}
	if channel {
		return identity.ID, firstContactApprovalChannel, nil
	}
	return identity.ID, "", nil
}

// firstContactExternalID is the external_id of the identity first contact
// registers for subjectKey under the issuer row issuerID, always in the
// reserved namespace domain.FirstContactExternalIDPrefix: an inventory sync
// may ingest another record under the subject key itself (an IdP app whose id
// is the agent's client id), and the two must never meet on one identity.
// After the prefix comes the subject key when that is a valid SPIFFE path
// segment of at most 128 bytes, as an opaque IdP client id is. Otherwise (an
// AWS role ARN, a Kubernetes service account, a SPIFFE ID or a URL), the
// external_id lands in the WIMSE URI and must be a path segment, so it is the
// key's last 160 bytes with every other byte replaced by '_', then '-' and 20
// hex digits of SHA-256(issuer row id, subject key), which keep two keys that
// map to the same readable part apart. At most 195 bytes. Deterministic, so a
// retry computes the same id.
func firstContactExternalID(issuerID, subjectKey string) string {
	if len(subjectKey) <= 128 && domain.ValidateSPIFFEPathSegment("external_id", subjectKey) == nil {
		return domain.FirstContactExternalIDPrefix + subjectKey
	}
	readable := subjectKey
	if len(readable) > 160 {
		readable = readable[len(readable)-160:]
	}
	b := []byte(readable)
	for i, c := range b {
		if !spiffeSegmentByte(c) {
			b[i] = '_'
		}
	}
	sum := sha256.Sum256([]byte(issuerID + "\x00" + subjectKey))
	return domain.FirstContactExternalIDPrefix + string(b) + "-" + hex.EncodeToString(sum[:10])
}

func spiffeSegmentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_'
}

// firstContactName is the registered identity's name: the subject key, cut
// to the column's 255 bytes on a character boundary.
func firstContactName(subjectKey string) string {
	if len(subjectKey) <= 255 {
		return subjectKey
	}
	cut := 255
	for cut > 0 && !utf8.RuneStart(subjectKey[cut]) {
		cut--
	}
	return subjectKey[:cut]
}

// firstContactRecord is the identity's metadata under first_contact: where
// and how the agent first arrived, from the verified credential only.
type firstContactRecord struct {
	Issuer      string    `json:"issuer"`
	IssuerID    string    `json:"issuer_id"`
	SubjectKey  string    `json:"subject_key"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	GrantType   string    `json:"grant_type"`
	Mode        string    `json:"mode"`
	// AWS is the AWS STS web identity token's account, organization,
	// organizational-unit paths and principal tags, when present.
	AWS map[string]any `json:"aws,omitempty"`
}

// standingAdoptionRecord is the metadata, under first_contact_adoption, of an
// identity an issuer row's standing mapping activated: the row, the subject
// and grant it was adopted on, and who last set the row's mapping, the person
// accountable for the adoption.
type standingAdoptionRecord struct {
	Issuer           string     `json:"issuer"`
	IssuerID         string     `json:"issuer_id"`
	SubjectKey       string     `json:"subject_key"`
	GrantType        string     `json:"grant_type"`
	MappingUpdatedBy string     `json:"mapping_updated_by"`
	MappingUpdatedAt *time.Time `json:"mapping_updated_at,omitempty"`
}

func newStandingAdoptionRecord(a firstContactArrival, fresh *domain.ExternalIssuer) standingAdoptionRecord {
	return standingAdoptionRecord{
		Issuer:           fresh.Issuer,
		IssuerID:         fresh.ID,
		SubjectKey:       a.subjectKey,
		GrantType:        a.grant,
		MappingUpdatedBy: fresh.FirstContactUpdatedBy,
		MappingUpdatedAt: fresh.FirstContactUpdatedAt,
	}
}

// firstContactMarkers returns the labels and metadata of an identity first
// contact registers under fresh, the row as read under the lock. An adopt
// row's identity also carries the standing-adoption markers.
func firstContactMarkers(a firstContactArrival, fresh *domain.ExternalIssuer) (json.RawMessage, json.RawMessage, error) {
	labelMap := map[string]string{domain.FirstContactLabelKey: domain.FirstContactLabelValue}
	metadataMap := map[string]any{domain.FirstContactMetadataKey: firstContactRecord{
		Issuer:      a.row.Issuer,
		IssuerID:    a.row.ID,
		SubjectKey:  a.subjectKey,
		FirstSeenAt: time.Now().UTC().Truncate(time.Second),
		GrantType:   a.grant,
		Mode:        string(fresh.FirstContact),
		AWS:         awsSTSClaims(a.claims),
	}}
	if fresh.FirstContact == domain.FirstContactAdopt {
		labelMap[domain.StandingAdoptionLabelKey] = domain.FirstContactLabelValue
		metadataMap[domain.StandingAdoptionMetadataKey] = newStandingAdoptionRecord(a, fresh)
	}
	labels, err := json.Marshal(labelMap)
	if err != nil {
		return nil, nil, err
	}
	metadata, err := json.Marshal(metadataMap)
	if err != nil {
		return nil, nil, err
	}
	return labels, metadata, nil
}

// standingAdoptionMarkers returns identity's labels and metadata with the
// standing-adoption markers added: the adopted_via label and the
// first_contact_adoption record. Labels or metadata that are not a JSON
// object are replaced by an object holding only the marker; the audit row of
// the adoption keeps what they were.
func standingAdoptionMarkers(identity *domain.Identity, a firstContactArrival, fresh *domain.ExternalIssuer) (json.RawMessage, json.RawMessage, error) {
	labelValue, err := json.Marshal(domain.FirstContactLabelValue)
	if err != nil {
		return nil, nil, err
	}
	record, err := json.Marshal(newStandingAdoptionRecord(a, fresh))
	if err != nil {
		return nil, nil, err
	}
	labels, _ := jsonObject(identity.Labels)
	labels[domain.StandingAdoptionLabelKey] = labelValue
	metadata, _ := jsonObject(identity.Metadata)
	metadata[domain.StandingAdoptionMetadataKey] = record
	rawLabels, err := json.Marshal(labels)
	if err != nil {
		return nil, nil, err
	}
	rawMetadata, err := json.Marshal(metadata)
	if err != nil {
		return nil, nil, err
	}
	return rawLabels, rawMetadata, nil
}

// awsSTSClaimNamespace holds the AWS claims of an STS web identity token
// (GetWebIdentityToken).
const awsSTSClaimNamespace = "https://sts.amazonaws.com/"

// Bounds on the AWS claims kept. AWS allows 50 tags of up to 128-byte keys
// and 256-byte values; the paths are a handful of short strings.
const (
	maxAWSOUPaths     = 20
	maxAWSOUPathBytes = 512
	maxAWSTags        = 50
	maxAWSTagKeyBytes = 128
	maxAWSTagValBytes = 256
	maxAWSIDBytes     = 64
)

// awsSTSClaims picks from a verified AWS STS token the claims that describe
// the agent: its account (aws_account), its organization (org_id), its
// organizational-unit paths (ou_path) and its principal tags. Request tags
// are left out: the caller of GetWebIdentityToken chooses them. Anything of
// an unexpected shape or size is dropped. Nil when there are none.
func awsSTSClaims(claims map[string]any) map[string]any {
	raw, ok := claims[awsSTSClaimNamespace]
	if !ok {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var ns map[string]json.RawMessage
	if json.Unmarshal(encoded, &ns) != nil {
		return nil
	}
	out := map[string]any{}
	var s string
	if json.Unmarshal(ns["aws_account"], &s) == nil && s != "" && len(s) <= maxAWSIDBytes {
		out["account"] = s
	}
	s = ""
	if json.Unmarshal(ns["org_id"], &s) == nil && s != "" && len(s) <= maxAWSIDBytes {
		out["org_id"] = s
	}
	var paths []any
	if json.Unmarshal(ns["ou_path"], &paths) == nil {
		kept := []string{}
		for _, p := range paths {
			if ps, ok := p.(string); ok && ps != "" && len(ps) <= maxAWSOUPathBytes && len(kept) < maxAWSOUPaths {
				kept = append(kept, ps)
			}
		}
		if len(kept) > 0 {
			out["ou_path"] = kept
		}
	}
	var tags map[string]any
	if json.Unmarshal(ns["principal_tags"], &tags) == nil && len(tags) > 0 && len(tags) <= maxAWSTags {
		kept := map[string]string{}
		for k, v := range tags {
			if vs, ok := v.(string); ok && k != "" && len(k) <= maxAWSTagKeyBytes && len(vs) <= maxAWSTagValBytes {
				kept[k] = vs
			}
		}
		if len(kept) > 0 {
			out["principal_tags"] = kept
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// recordFirstContact logs and counts a first-contact attempt. A discover
// registration also emits the unmatched-agent event, pointing at the
// identity it registered: the credential still maps to no adopted agent.
func recordFirstContact(ctx context.Context, a firstContactArrival, mode domain.FirstContactMode, res firstContactResult) {
	telemetry.FederationFirstContact.Add(ctx, 1, metric.WithAttributes(
		attribute.String("account_id", a.row.AccountID),
		attribute.String("grant_type", a.grant),
		attribute.String("mode", string(mode)),
		attribute.String("outcome", string(res.outcome)),
	))
	var ev *zerolog.Event
	switch res.outcome {
	case firstContactRateLimited, firstContactAccountCap, firstContactExternalIDTaken, firstContactSubjectTooLong,
		firstContactAmbiguousBinding, firstContactOtherProject, firstContactApprovalChannel:
		ev = log.Warn()
	default:
		ev = log.Info()
	}
	ev = ev.Str("account_id", a.row.AccountID).
		Str("issuer_id", a.row.ID).
		Str("issuer", a.row.Issuer).
		Str("subject_key", a.subjectKey).
		Str("grant_type", a.grant).
		Str("mode", string(mode)).
		Str("outcome", string(res.outcome))
	switch {
	case res.identity != nil:
		ev = ev.Str("identity_id", res.identity.ID).
			Str("project_id", res.identity.ProjectID).
			Str("status", string(res.identity.Status))
	case res.candidate != "":
		ev = ev.Str("identity_id", res.candidate)
	}
	ev.Msg("federation_first_contact")

	if res.identity != nil && res.identity.Status != domain.IdentityStatusActive {
		recordUnmatchedAgentIdentity(ctx, a.row, a.subjectKey, a.grant, "first_contact_registered", res.identity.ID)
	}
}

// keepFirstContactProvenance restores, on a first-contact identity, the
// discovered_via label and the first_contact metadata an update replaced:
// an inventory sync adds what it knows, and never rewrites how the agent
// first arrived. Labels or metadata that are not a JSON object are put back
// as they were.
func keepFirstContactProvenance(identity *domain.Identity, prevLabels, prevMetadata json.RawMessage) {
	if identity.Origin != domain.OriginFirstContact {
		return
	}
	labels, ok := jsonObject(identity.Labels)
	if !ok {
		labels, _ = jsonObject(prevLabels)
	}
	if v, err := json.Marshal(domain.FirstContactLabelValue); err == nil {
		labels[domain.FirstContactLabelKey] = v
	}
	if raw, err := json.Marshal(labels); err == nil {
		identity.Labels = raw
	}

	prev, _ := jsonObject(prevMetadata)
	record, had := prev[domain.FirstContactMetadataKey]
	metadata, ok := jsonObject(identity.Metadata)
	if !ok {
		metadata = maps.Clone(prev)
	}
	if had {
		metadata[domain.FirstContactMetadataKey] = record
	} else {
		delete(metadata, domain.FirstContactMetadataKey)
	}
	if raw, err := json.Marshal(metadata); err == nil {
		identity.Metadata = raw
	}
}

// keepStandingAdoptionMarkers makes the adopted_via label and the
// first_contact_adoption record, which only a standing adoption writes,
// follow the stored identity through a discovered ingest: kept, with their
// stored values, on an identity that has them, and dropped from an update or
// a new identity that would add them. prevLabels and prevMetadata are the
// stored values, nil for a new identity.
func keepStandingAdoptionMarkers(identity *domain.Identity, prevLabels, prevMetadata json.RawMessage) {
	identity.Labels = followMarker(identity.Labels, prevLabels, domain.StandingAdoptionLabelKey, isFirstContactLabelValue)
	identity.Metadata = followMarker(identity.Metadata, prevMetadata, domain.StandingAdoptionMetadataKey, nil)
}

func isFirstContactLabelValue(v json.RawMessage) bool {
	var s string
	return json.Unmarshal(v, &s) == nil && s == domain.FirstContactLabelValue
}

// followMarker returns next with the marker key as prev has it: set to
// prev's value when prev has it, absent when prev has not. A value counts as
// the marker only when match accepts it (nil accepts any). A next that is
// not a JSON object is replaced by prev when prev has the marker, and left
// alone otherwise.
func followMarker(next, prev json.RawMessage, key string, match func(json.RawMessage) bool) json.RawMessage {
	marker := func(obj map[string]json.RawMessage) (json.RawMessage, bool) {
		v, ok := obj[key]
		return v, ok && (match == nil || match(v))
	}
	prevObj, _ := jsonObject(prev)
	kept, had := marker(prevObj)
	nextObj, ok := jsonObject(next)
	if !ok {
		if had {
			return prev
		}
		return next
	}
	got, has := marker(nextObj)
	switch {
	case had && has && bytes.Equal(got, kept):
		return next
	case had:
		nextObj[key] = kept
	case has:
		delete(nextObj, key)
	default:
		return next
	}
	raw, err := json.Marshal(nextObj)
	if err != nil {
		return next
	}
	return raw
}

// jsonObject decodes raw as a JSON object, keeping each value's encoding.
// An empty or non-object value is an empty map and false.
func jsonObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	out := map[string]json.RawMessage{}
	if len(raw) == 0 {
		return out, false
	}
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return map[string]json.RawMessage{}, false
	}
	return out, true
}

// IssuerBindingMetadataKey is the metadata key a discovered-identity ingest
// uses to name the runtime subject an agent presents: an object with
// subject_key and the issuer row's issuer_id or its issuer URL. When no
// identity has the ingest's external_id, an identity first contact
// registered for the same subject in the same tenant is updated instead of a
// second one being created.
const IssuerBindingMetadataKey = "issuer_binding"

// firstContactMatch returns the first-contact identity in req's tenant that
// req's issuer_binding metadata names, or nil.
func (s *IdentityService) firstContactMatch(ctx context.Context, req DiscoveredIdentityRequest) (*domain.Identity, error) {
	top, _ := jsonObject(req.Metadata)
	raw, ok := top[IssuerBindingMetadataKey]
	if !ok {
		return nil, nil
	}
	var ref struct {
		IssuerID   string `json:"issuer_id"`
		Issuer     string `json:"issuer"`
		SubjectKey string `json:"subject_key"`
	}
	if json.Unmarshal(raw, &ref) != nil || ref.SubjectKey == "" || (ref.IssuerID == "" && ref.Issuer == "") {
		return nil, nil
	}
	record := map[string]any{"subject_key": ref.SubjectKey}
	if ref.IssuerID != "" {
		record["issuer_id"] = ref.IssuerID
	}
	if ref.Issuer != "" {
		record["issuer"] = ref.Issuer
	}
	identity, err := s.repo.GetByOriginAndMetadata(ctx, req.AccountID, req.ProjectID, domain.OriginFirstContact,
		map[string]any{domain.FirstContactMetadataKey: record})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return identity, nil
}
