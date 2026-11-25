package service

import (
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
// binding maps yet, registers that agent when the row's first_contact says
// so. discover registers it unadopted and refuses the request; adopt
// registers it adopted under the row's mapping and serves the request.
//
// It never creates a person or a membership, never trusts an issuer that is
// not already a row, never acts on a disabled row, and never touches an
// identity that already exists: a subject with any binding, enabled or not,
// keeps today's behaviour.

// FirstContactActor is the audit actor and created_by of every row first
// contact writes. The system: prefix is reserved, so no admin caller can
// claim it.
const FirstContactActor = middleware.SystemCallerPrefix + "first_contact"

// Defaults for the first-contact bounds.
const (
	DefaultFirstContactRatePerMinute           = 10
	DefaultFirstContactMaxDiscoveredPerAccount = 500
)

// FirstContactConfig bounds first-contact registration. Past either bound a
// credential gets the plain no-binding refusal, and the reason is logged.
type FirstContactConfig struct {
	// RatePerMinute caps the registrations under one issuer row in any
	// minute. Zero means DefaultFirstContactRatePerMinute.
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

// FirstContactRegistrar registers agents on first contact.
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
	// firstContactAlreadyBound: a binding for the subject exists now (a
	// concurrent first contact made it); the grant reads it as usual.
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
)

// firstContactArrival is a credential that verified in full and named an
// agent no binding maps.
type firstContactArrival struct {
	row        *domain.ExternalIssuer
	subjectKey string
	grant      string
	// claims are the credential's verified claims. Only an allowlisted subset
	// is kept (firstContactRecord).
	claims map[string]any
}

// firstContactFunc is the first-contact step bindAgent runs when no binding
// maps the subject key. It reports whether a binding now exists, so the
// caller reads the bindings again.
type firstContactFunc func(ctx context.Context) (bool, error)

// firstContactFor returns the first-contact step for a credential that
// verified under row, or nil when nothing would register: no registrar, a
// static issuer, a disabled row, or first_contact off. prepare, when set,
// runs before anything is registered and may decline with an outcome
// (nothing is registered, the attempt is logged, and the grant refuses as
// without first contact) or refuse the request with an error.
func (s *OAuthService) firstContactFor(row *domain.ExternalIssuer, subjectKey, grant string, claims map[string]any,
	prepare func(ctx context.Context) (firstContactOutcome, error),
) firstContactFunc {
	if s.firstContact == nil || row == nil || !row.Enabled || !row.FirstContact.On() {
		return nil
	}
	return func(ctx context.Context) (bool, error) {
		a := firstContactArrival{row: row, subjectKey: subjectKey, grant: grant, claims: claims}
		if prepare != nil {
			declined, err := prepare(ctx)
			if err != nil {
				return false, err
			}
			if declined != "" {
				recordFirstContact(ctx, a, row.FirstContact, declined, nil)
				return false, nil
			}
		}
		identity, outcome, err := s.firstContact.register(ctx, a)
		if err != nil {
			return false, oauthServerError("failed to register the agent on first contact", err)
		}
		recordFirstContact(ctx, a, row.FirstContact, outcome, identity)
		return outcome == firstContactRegistered || outcome == firstContactAlreadyBound, nil
	}
}

// Sentinels that end the registration transaction after a failed write.
var (
	errFirstContactTaken = errors.New("first contact: external_id taken")
	errFirstContactRace  = errors.New("first contact: binding created concurrently")
)

// register creates the identity and binding for a, in one transaction under
// the account's first-contact lock. It returns the identity only when it
// registered one. Every outcome but an error leaves the grant to read the
// bindings and decide as usual.
func (r *FirstContactRegistrar) register(ctx context.Context, a firstContactArrival) (*domain.Identity, firstContactOutcome, error) {
	row := a.row
	if len(a.subjectKey) > domain.MaxSubjectKeyBytes {
		return nil, firstContactSubjectTooLong, nil
	}
	project := row.FirstContactProjectID
	// The project's default credential policy is ensured before the
	// transaction: created inside it, a concurrent creation would abort the
	// transaction instead of being read back.
	if _, err := r.identities.policySvc.EnsureDefaultPolicy(ctx, row.AccountID, project); err != nil {
		return nil, "", err
	}

	var (
		identity *domain.Identity
		outcome  firstContactOutcome
	)
	err := r.issuers.DB().RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		ctx = postgres.WithTx(ctx, tx)
		if err := r.issuers.SetAuditActor(ctx, FirstContactActor); err != nil {
			return err
		}
		if err := r.issuers.LockFirstContact(ctx, row.AccountID); err != nil {
			return err
		}
		// The row as it is now, held against a concurrent delete: disabled,
		// switched off or re-mapped since the request read it, it registers
		// nothing.
		fresh, err := r.issuers.GetForShare(ctx, row.ID, row.AccountID)
		if errors.Is(err, sql.ErrNoRows) {
			outcome = firstContactRowChanged
			return nil
		}
		if err != nil {
			return err
		}
		if !fresh.Enabled || fresh.Kind != row.Kind || !fresh.FirstContact.On() || fresh.FirstContactProjectID != project {
			outcome = firstContactRowChanged
			return nil
		}
		mode := fresh.FirstContact

		// Under the lock, so two first contacts for one subject make one
		// identity: the second finds the first one's binding.
		existing, err := r.issuers.BindingsFor(ctx, row.ID, a.subjectKey)
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			outcome = firstContactAlreadyBound
			return nil
		}
		recent, err := r.issuers.CountBindingsCreatedBySince(ctx, row.ID, FirstContactActor, time.Now().Add(-time.Minute))
		if err != nil {
			return err
		}
		if recent >= r.cfg.RatePerMinute {
			outcome = firstContactRateLimited
			return nil
		}
		if mode == domain.FirstContactDiscover {
			n, err := r.identities.repo.CountByOriginAndStatus(ctx, row.AccountID, domain.OriginFirstContact, domain.IdentityStatusDiscovered)
			if err != nil {
				return err
			}
			if n >= r.cfg.MaxDiscoveredPerAccount {
				outcome = firstContactAccountCap
				return nil
			}
		}

		externalID := firstContactExternalID(row.ID, a.subjectKey)
		if _, err := r.identities.repo.GetByExternalID(ctx, externalID, row.AccountID, project); err == nil {
			outcome = firstContactExternalIDTaken
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		labels, metadata, err := firstContactMarkers(a, mode)
		if err != nil {
			return err
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
			// into the mapped project, owned by the mapped user, and vouched
			// for by an issuer the account trusts.
			req.adopted = true
			req.TrustLevel = domain.TrustLevelVerifiedThirdParty
		}
		created, err := r.identities.RegisterIdentity(ctx, req)
		if err != nil {
			var deactivated *IdentityDeactivatedConflictError
			if errors.Is(err, ErrIdentityAlreadyExists) || errors.As(err, &deactivated) {
				return errFirstContactTaken
			}
			return err
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
				return errFirstContactRace
			}
			return err
		}
		identity, outcome = created, firstContactRegistered
		return nil
	})
	switch {
	case errors.Is(err, errFirstContactTaken):
		return nil, firstContactExternalIDTaken, nil
	case errors.Is(err, errFirstContactRace):
		return nil, firstContactAlreadyBound, nil
	case err != nil:
		return nil, "", err
	}
	return identity, outcome, nil
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

// firstContactMarkers returns the labels and metadata of a first-contact
// identity.
func firstContactMarkers(a firstContactArrival, mode domain.FirstContactMode) (json.RawMessage, json.RawMessage, error) {
	labels, err := json.Marshal(map[string]string{domain.FirstContactLabelKey: domain.FirstContactLabelValue})
	if err != nil {
		return nil, nil, err
	}
	metadata, err := json.Marshal(map[string]any{domain.FirstContactMetadataKey: firstContactRecord{
		Issuer:      a.row.Issuer,
		IssuerID:    a.row.ID,
		SubjectKey:  a.subjectKey,
		FirstSeenAt: time.Now().UTC().Truncate(time.Second),
		GrantType:   a.grant,
		Mode:        string(mode),
		AWS:         awsSTSClaims(a.claims),
	}})
	if err != nil {
		return nil, nil, err
	}
	return labels, metadata, nil
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
func recordFirstContact(ctx context.Context, a firstContactArrival, mode domain.FirstContactMode,
	outcome firstContactOutcome, identity *domain.Identity,
) {
	telemetry.FederationFirstContact.Add(ctx, 1, metric.WithAttributes(
		attribute.String("account_id", a.row.AccountID),
		attribute.String("grant_type", a.grant),
		attribute.String("mode", string(mode)),
		attribute.String("outcome", string(outcome)),
	))
	var ev *zerolog.Event
	switch outcome {
	case firstContactRateLimited, firstContactAccountCap, firstContactExternalIDTaken, firstContactSubjectTooLong:
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
		Str("outcome", string(outcome))
	if identity != nil {
		ev = ev.Str("identity_id", identity.ID).
			Str("project_id", identity.ProjectID).
			Str("status", string(identity.Status))
	}
	ev.Msg("federation_first_contact")

	if identity != nil && identity.Status != domain.IdentityStatusActive {
		recordUnmatchedAgentIdentity(ctx, a.row, a.subjectKey, a.grant, "first_contact_registered", identity.ID)
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
