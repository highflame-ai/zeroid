package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/attestation"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// MaxExternalIssuersPerAccount caps an account's trusted issuers.
const MaxExternalIssuersPerAccount = 20

// maxJWKSProbeBytes bounds a JWKS probe's response body.
const maxJWKSProbeBytes = 1 << 20

// IssuerStore says where trusted issuers come from: static configuration
// (standalone) or account rows (ADR 0042 D4).
type IssuerStore string

const (
	IssuerStoreConfig IssuerStore = "config"
	IssuerStoreDB     IssuerStore = "db"
)

// IssuerAPIError is a refused admin request on issuers or bindings. Status
// is the HTTP status; Code is the stable reason in docs/external-issuers.md.
type IssuerAPIError struct {
	Status  int
	Code    string
	Message string
}

func (e *IssuerAPIError) Error() string { return e.Message }

func issuerErr(status int, code, msg string) error {
	return &IssuerAPIError{Status: status, Code: code, Message: msg}
}

var (
	errIssuerNotFound  = issuerErr(http.StatusNotFound, "not_found", "external issuer not found")
	errBindingNotFound = issuerErr(http.StatusNotFound, "not_found", "binding not found")
	// Deliberately generic: it never says which account holds the issuer.
	errIssuerAlreadyTrusted = issuerErr(http.StatusConflict, "issuer_already_trusted",
		"this issuer is already trusted and cannot be added again")
)

// JWKSCheck is the result of probing an issuer's JWKS. It never carries an
// upstream response body.
type JWKSCheck struct {
	// JWKSURI is the key set the issuer's discovery document names.
	JWKSURI   string    `json:"jwks_uri,omitempty"`
	Reachable bool      `json:"reachable"`
	KeyCount  int       `json:"key_count"`
	KIDs      []string  `json:"kids"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// ExternalIssuerServiceConfig is the deployment's federation settings.
type ExternalIssuerServiceConfig struct {
	Store IssuerStore
	// SelfIssuer is ZeroID's own issuer, which no row may trust.
	SelfIssuer string
	// SharedIssuers may appear in several accounts, each pinned on its claim.
	SharedIssuers []domain.SharedIssuer
	// AllowPrivateEndpoints admits private addresses and http URLs.
	AllowPrivateEndpoints bool
	// StaticIssuers are listed read-only in config mode.
	StaticIssuers []domain.ExternalIssuerConfig
	// HTTPClient fetches JWKS for probes. Nil means the SSRF-guarded client.
	HTTPClient *http.Client
}

// ExternalIssuerService manages trusted issuers and bindings for the admin
// API (ADR 0042 D4, D4a, D6).
type ExternalIssuerService struct {
	repo           *postgres.ExternalIssuerRepository
	identityLookup linkedIdentityLookup
	oauthClientSvc *OAuthClientService
	cfg            ExternalIssuerServiceConfig
	httpClient     *http.Client
}

// NewExternalIssuerService builds the service.
func NewExternalIssuerService(repo *postgres.ExternalIssuerRepository, identityLookup linkedIdentityLookup,
	oauthClientSvc *OAuthClientService, cfg ExternalIssuerServiceConfig,
) *ExternalIssuerService {
	if cfg.Store == "" {
		cfg.Store = IssuerStoreConfig
	}
	if cfg.SharedIssuers == nil {
		cfg.SharedIssuers = domain.DefaultSharedIssuers
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = attestation.NewSSRFGuardedHTTPClient(cfg.AllowPrivateEndpoints)
	}
	return &ExternalIssuerService{repo: repo, identityLookup: identityLookup, oauthClientSvc: oauthClientSvc, cfg: cfg, httpClient: hc}
}

// Store reports where this deployment reads issuers from.
func (s *ExternalIssuerService) Store() IssuerStore { return s.cfg.Store }

// sharedPin returns iss's pinning claim, or "" for a customer-unique issuer.
func (s *ExternalIssuerService) sharedPin(iss string) string {
	pin, _ := domain.SharedPin(s.cfg.SharedIssuers, iss)
	return pin
}

func (s *ExternalIssuerService) requireDB() error {
	if s.cfg.Store != IssuerStoreDB {
		return issuerErr(http.StatusConflict, "issuer_store_config",
			"this deployment reads trusted issuers from static configuration (federation.issuer_store=config); rows cannot be written")
	}
	return nil
}

// IssuerInput is a create request. Preset fills IdP-fixed fields first.
type IssuerInput struct {
	Preset           string
	Kind             domain.IssuerKind
	Issuer           string
	DisplayName      string
	Audiences        []string
	Algorithms       []string
	ClaimMapping     map[string]string
	PropagateClaims  []string
	ClaimConstraints map[string][]string
	MaxTokenAge      int
	JWKSCacheTTL     int
	Source           domain.IssuerSource
	SourceRef        string
	Enabled          *bool
}

// IssuerPatch is an update. Nil fields are unchanged; issuer, kind, source,
// account and jwks_uri (re-derived by Refresh) never change.
type IssuerPatch struct {
	DisplayName      *string
	Audiences        *[]string
	Algorithms       *[]string
	ClaimMapping     *map[string]string
	PropagateClaims  *[]string
	ClaimConstraints *map[string][]string
	MaxTokenAge      *int
	JWKSCacheTTL     *int
	Enabled          *bool
}

// Create adds a trusted issuer to accountID. The JWKS must be reachable and
// non-empty. Uniqueness (ADR 0042 D4) is checked under a per-issuer lock.
func (s *ExternalIssuerService) Create(ctx context.Context, accountID, actor string, in IssuerInput) (*domain.ExternalIssuer, *JWKSCheck, error) {
	if err := s.requireDB(); err != nil {
		return nil, nil, err
	}
	row := &domain.ExternalIssuer{
		AccountID:           accountID,
		Issuer:              in.Issuer,
		Kind:                in.Kind,
		DisplayName:         in.DisplayName,
		Audiences:           slices.Clone(in.Audiences),
		Algorithms:          slices.Clone(in.Algorithms),
		ClaimMapping:        cloneStringMap(in.ClaimMapping),
		PropagateClaims:     slices.Clone(in.PropagateClaims),
		ClaimConstraints:    cloneConstraints(in.ClaimConstraints),
		MaxTokenAgeSeconds:  in.MaxTokenAge,
		JWKSCacheTTLSeconds: in.JWKSCacheTTL,
		Source:              in.Source,
		SourceRef:           in.SourceRef,
		Enabled:             in.Enabled == nil || *in.Enabled,
		CreatedBy:           actor,
		UpdatedBy:           actor,
	}
	if err := domain.ApplyIssuerPreset(row, in.Preset); err != nil {
		return nil, nil, validationToAPIError(err)
	}
	row.Normalize()
	// Trusting ZeroID's own issuer would let its tokens (or ID-JAGs it might
	// be tricked into signing) federate back in as an external person.
	if s.cfg.SelfIssuer != "" && domain.CanonicalIssuer(row.Issuer) == domain.CanonicalIssuer(s.cfg.SelfIssuer) {
		return nil, nil, issuerErr(http.StatusUnprocessableEntity, "issuer_is_self",
			"this is ZeroID's own issuer; it cannot be trusted as an external issuer")
	}
	pin := s.sharedPin(row.Issuer)
	if err := row.Validate(domain.IssuerValidation{AllowHTTP: s.cfg.AllowPrivateEndpoints, PinClaim: pin, JWKSURIPending: true}); err != nil {
		return nil, nil, validationToAPIError(err)
	}
	row.ConstraintsKey = row.UniquenessKey(pin)

	// A conflict is answered before anything is fetched; the transaction
	// below re-checks under the lock.
	existing, err := s.repo.ListByCanonicalIssuer(ctx, domain.CanonicalIssuer(row.Issuer))
	if err != nil {
		return nil, nil, err
	}
	if uniquenessConflict(existing, row, pin) {
		return nil, nil, errIssuerAlreadyTrusted
	}

	// The keys come from the issuer's own discovery document, never from the
	// caller: a caller-chosen key set would let an admin sign tokens for any
	// person their IdP's issuer names (ADR 0042 D4).
	row.JWKSURI, err = s.discover(ctx, row.Issuer)
	if err != nil {
		return nil, nil, err
	}
	check, err := s.requireJWKS(ctx, row.JWKSURI)
	if err != nil {
		return nil, check, err
	}

	err = s.inTx(ctx, actor, func(ctx context.Context) error {
		if err := s.repo.LockAccount(ctx, accountID); err != nil {
			return err
		}
		if err := s.repo.LockIssuer(ctx, domain.CanonicalIssuer(row.Issuer)); err != nil {
			return err
		}
		existing, err := s.repo.ListByCanonicalIssuer(ctx, domain.CanonicalIssuer(row.Issuer))
		if err != nil {
			return err
		}
		if conflict := uniquenessConflict(existing, row, pin); conflict {
			return errIssuerAlreadyTrusted
		}
		n, err := s.repo.CountByAccount(ctx, accountID)
		if err != nil {
			return err
		}
		if n >= MaxExternalIssuersPerAccount {
			return issuerErr(http.StatusConflict, "issuer_limit_reached",
				fmt.Sprintf("an account may trust at most %d issuers", MaxExternalIssuersPerAccount))
		}
		if err := s.repo.Insert(ctx, row); err != nil {
			if isDuplicateKeyError(err) {
				return errIssuerAlreadyTrusted
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, check, err
	}
	log.Info().Str("account_id", accountID).Str("issuer", row.Issuer).Str("kind", string(row.Kind)).
		Str("id", row.ID).Str("actor", actor).Msg("external issuer trusted")
	return row, check, nil
}

// uniquenessConflict applies ADR 0042 D4 to a candidate row against the rows
// already stored for its issuer, compared canonically (other than itself).
// pin is the shared-issuer list's pinning claim, "" for a customer-unique
// issuer.
//
//   - A customer-unique issuer belongs to one account at most, whatever the
//     constraints, and has at most one row per kind.
//   - A shared issuer may repeat, in any account, but two rows of one kind
//     must never both match a token: their pinning-claim values must not
//     intersect. The token's pinning claim must be a single string, so
//     disjoint values cannot both match; other constraints only narrow a
//     row and play no part here.
func uniquenessConflict(existing []*domain.ExternalIssuer, row *domain.ExternalIssuer, pin string) bool {
	for _, e := range existing {
		if e.ID == row.ID {
			continue
		}
		if pin == "" && e.AccountID != row.AccountID {
			return true
		}
		if e.Kind != row.Kind {
			continue
		}
		if pin == "" || slices.ContainsFunc(e.ClaimConstraints[pin], func(v string) bool {
			return slices.Contains(row.ClaimConstraints[pin], v)
		}) {
			return true
		}
	}
	return false
}

// List returns accountID's issuers. In config mode it returns the static
// entries the account may use, read-only.
func (s *ExternalIssuerService) List(ctx context.Context, accountID string) ([]*domain.ExternalIssuer, error) {
	if s.cfg.Store != IssuerStoreDB {
		var out []*domain.ExternalIssuer
		for _, c := range s.cfg.StaticIssuers {
			if !c.AccountAllowed(accountID) {
				continue
			}
			out = append(out, staticIssuerView(c, accountID))
		}
		return out, nil
	}
	return s.repo.List(ctx, accountID)
}

func staticIssuerView(c domain.ExternalIssuerConfig, accountID string) *domain.ExternalIssuer {
	return &domain.ExternalIssuer{
		AccountID:           accountID,
		Issuer:              c.Issuer,
		Kind:                c.EffectiveKind(),
		JWKSURI:             c.JWKSURI,
		Audiences:           c.AudienceList(),
		Algorithms:          slices.Clone(c.Algorithms),
		ClaimMapping:        cloneStringMap(c.ClaimMapping),
		PropagateClaims:     slices.Clone(c.PropagateClaims),
		ClaimConstraints:    map[string][]string{},
		MaxTokenAgeSeconds:  int(c.MaxTokenAge / time.Second),
		JWKSCacheTTLSeconds: int(c.JWKSCacheTTL / time.Second),
		Source:              domain.IssuerSourceConfig,
		Enabled:             true,
	}
}

// Get returns one of accountID's issuers; another account's row is not found.
func (s *ExternalIssuerService) Get(ctx context.Context, accountID, id string) (*domain.ExternalIssuer, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if !validUUID(id) {
		return nil, errIssuerNotFound
	}
	row, err := s.repo.Get(ctx, id, accountID)
	if err != nil {
		return nil, notFoundOr(err, errIssuerNotFound)
	}
	return row, nil
}

// Update changes an issuer's mutable fields. A new jwks_uri is probed first.
func (s *ExternalIssuerService) Update(ctx context.Context, accountID, id, actor string, p IssuerPatch) (*domain.ExternalIssuer, *JWKSCheck, error) {
	if err := s.requireDB(); err != nil {
		return nil, nil, err
	}
	if !validUUID(id) {
		return nil, nil, errIssuerNotFound
	}
	var (
		row   *domain.ExternalIssuer
		check *JWKSCheck
	)
	current, err := s.repo.Get(ctx, id, accountID)
	if err != nil {
		return nil, nil, notFoundOr(err, errIssuerNotFound)
	}
	// The claims that say who a person is never change after create:
	// remapping the user key, or the email linking trusts, to a claim an IdP
	// user can set would let them take over existing links (nOAuth).
	if p.ClaimMapping != nil {
		for _, k := range domain.IdentityMappingKeys {
			if (*p.ClaimMapping)[k] != current.ClaimMapping[k] {
				return nil, nil, issuerErr(http.StatusUnprocessableEntity, "claim_mapping_immutable",
					"claim_mapping.user_id, email and email_verified are fixed when the issuer is created; delete and re-create it to change them")
			}
		}
	}
	err = s.inTx(ctx, actor, func(ctx context.Context) error {
		if err := s.repo.LockIssuer(ctx, domain.CanonicalIssuer(current.Issuer)); err != nil {
			return err
		}
		r, err := s.repo.Get(ctx, id, accountID)
		if err != nil {
			return notFoundOr(err, errIssuerNotFound)
		}
		applyIssuerPatch(r, p)
		r.UpdatedBy = actor
		r.Normalize()
		// A rename or a disable changes nothing uniqueness or validation
		// decide on. Skipping both keeps such rows manageable when the
		// deployment's rules moved under them (an issuer dropped from the
		// shared list leaves rows in several accounts).
		if !p.onlyNameOrDisable() {
			pin := s.sharedPin(r.Issuer)
			if err := r.Validate(domain.IssuerValidation{AllowHTTP: s.cfg.AllowPrivateEndpoints, PinClaim: pin}); err != nil {
				return validationToAPIError(err)
			}
			r.ConstraintsKey = r.UniquenessKey(pin)
			existing, err := s.repo.ListByCanonicalIssuer(ctx, domain.CanonicalIssuer(r.Issuer))
			if err != nil {
				return err
			}
			if uniquenessConflict(existing, r, pin) {
				return errIssuerAlreadyTrusted
			}
		} else if r.DisplayName = strings.TrimSpace(r.DisplayName); len(r.DisplayName) > 255 {
			return issuerErr(http.StatusBadRequest, "invalid_request", "display_name is at most 255 characters")
		}
		if err := s.repo.Update(ctx, r); err != nil {
			if isDuplicateKeyError(err) {
				return errIssuerAlreadyTrusted
			}
			return notFoundOr(err, errIssuerNotFound)
		}
		row = r
		return nil
	})
	if err != nil {
		return nil, check, err
	}
	return row, check, nil
}

// onlyNameOrDisable reports whether p changes nothing but display_name and,
// at most, disables the row. An enable is re-checked: re-enabling a row
// stranded in conflict would make grants for both accounts ambiguous.
func (p IssuerPatch) onlyNameOrDisable() bool {
	return p.Audiences == nil && p.Algorithms == nil && p.ClaimMapping == nil && p.PropagateClaims == nil &&
		p.ClaimConstraints == nil && p.MaxTokenAge == nil && p.JWKSCacheTTL == nil &&
		(p.Enabled == nil || !*p.Enabled)
}

func applyIssuerPatch(r *domain.ExternalIssuer, p IssuerPatch) {
	if p.DisplayName != nil {
		r.DisplayName = *p.DisplayName
	}
	if p.Audiences != nil {
		r.Audiences = slices.Clone(*p.Audiences)
	}
	if p.Algorithms != nil {
		r.Algorithms = slices.Clone(*p.Algorithms)
	}
	if p.ClaimMapping != nil {
		r.ClaimMapping = cloneStringMap(*p.ClaimMapping)
	}
	if p.PropagateClaims != nil {
		r.PropagateClaims = slices.Clone(*p.PropagateClaims)
	}
	if p.ClaimConstraints != nil {
		r.ClaimConstraints = cloneConstraints(*p.ClaimConstraints)
	}
	if p.MaxTokenAge != nil {
		r.MaxTokenAgeSeconds = *p.MaxTokenAge
	}
	if p.JWKSCacheTTL != nil {
		r.JWKSCacheTTLSeconds = *p.JWKSCacheTTL
	}
	if p.Enabled != nil {
		r.Enabled = *p.Enabled
	}
}

// Delete removes an issuer and its bindings. New mints stop at once; tokens
// already issued live out their 15 minutes (ADR 0042 open question 6).
func (s *ExternalIssuerService) Delete(ctx context.Context, accountID, id, actor string) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if !validUUID(id) {
		return errIssuerNotFound
	}
	err := s.inTx(ctx, actor, func(ctx context.Context) error {
		return notFoundOr(s.repo.Delete(ctx, id, accountID), errIssuerNotFound)
	})
	if err == nil {
		log.Info().Str("account_id", accountID).Str("id", id).Str("actor", actor).Msg("external issuer deleted")
	}
	return err
}

// Check runs what Create would fetch for issuer: its discovery document,
// then the key set it names, through the SSRF-guarded client. A fetch
// failure is a result (Reachable false, Error set), not an error; only an
// invalid issuer URL is an error.
func (s *ExternalIssuerService) Check(ctx context.Context, issuer string) (*JWKSCheck, error) {
	issuer = strings.TrimSpace(issuer)
	if err := domain.ValidateIssuerURL(issuer, s.cfg.AllowPrivateEndpoints); err != nil {
		return nil, validationToAPIError(err)
	}
	jwksURI, err := s.discover(ctx, issuer)
	if err != nil {
		var apiErr *IssuerAPIError
		if errors.As(err, &apiErr) {
			return &JWKSCheck{Error: apiErr.Code, KIDs: []string{}, CheckedAt: time.Now().UTC()}, nil
		}
		return nil, err
	}
	return s.probeJWKS(ctx, jwksURI), nil
}

// Refresh re-reads an issuer's discovery document and moves the row to the
// key set it now names, after probing it. The only way jwks_uri changes.
func (s *ExternalIssuerService) Refresh(ctx context.Context, accountID, id, actor string) (*domain.ExternalIssuer, *JWKSCheck, error) {
	row, err := s.Get(ctx, accountID, id)
	if err != nil {
		return nil, nil, err
	}
	jwksURI, err := s.discover(ctx, row.Issuer)
	if err != nil {
		return nil, nil, err
	}
	check, err := s.requireJWKS(ctx, jwksURI)
	if err != nil {
		return nil, check, err
	}
	if jwksURI == row.JWKSURI {
		return row, check, nil
	}
	row.JWKSURI = jwksURI
	row.UpdatedBy = actor
	err = s.inTx(ctx, actor, func(ctx context.Context) error {
		return notFoundOr(s.repo.SetJWKSURI(ctx, row), errIssuerNotFound)
	})
	if err != nil {
		return nil, check, err
	}
	log.Info().Str("account_id", accountID).Str("id", id).Str("jwks_uri", jwksURI).Msg("external issuer keys re-discovered")
	return row, check, nil
}

// maxDiscoveryBytes bounds a discovery document.
const maxDiscoveryBytes = 256 << 10

// discover fetches iss's OpenID discovery document and returns the jwks_uri
// it names. The document's issuer must equal iss exactly (OpenID Connect
// Discovery §4.3), so a document served elsewhere cannot vouch for it.
func (s *ExternalIssuerService) discover(ctx context.Context, iss string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	unreachable := issuerErr(http.StatusUnprocessableEntity, "discovery_unreachable",
		"the issuer's OpenID discovery document could not be fetched")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(iss, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", unreachable
	}
	req.Header.Set("Accept", "application/json")
	// Discovery is served at the issuer itself (Entra and Okta do not
	// redirect), so a redirect is refused rather than followed.
	noRedirect := *s.httpClient
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		// A private address is reported as unreachable: a distinct answer
		// would let an admin probe internal DNS. The log keeps the reason.
		reason := "unreachable"
		if errors.Is(err, attestation.ErrPrivateAttestationEndpoint) {
			reason = "private_address"
		}
		log.Info().Err(err).Str("issuer", iss).Str("reason", reason).Msg("issuer discovery failed")
		return "", unreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		log.Info().Str("issuer", iss).Int("status", resp.StatusCode).Msg("issuer discovery failed")
		return "", unreachable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes+1))
	if err != nil || len(body) > maxDiscoveryBytes {
		return "", unreachable
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.JWKSURI == "" {
		return "", issuerErr(http.StatusUnprocessableEntity, "discovery_invalid",
			"the issuer's discovery document names no jwks_uri")
	}
	if doc.Issuer != iss {
		return "", issuerErr(http.StatusUnprocessableEntity, "discovery_issuer_mismatch",
			"the discovery document at the issuer names a different issuer")
	}
	if err := domain.ValidateIssuerURL(doc.JWKSURI, s.cfg.AllowPrivateEndpoints); err != nil {
		return "", issuerErr(http.StatusUnprocessableEntity, "discovery_invalid",
			"the issuer's discovery document names an unusable jwks_uri")
	}
	return doc.JWKSURI, nil
}

// requireJWKS probes and turns an unusable key set into a 422.
func (s *ExternalIssuerService) requireJWKS(ctx context.Context, jwksURI string) (*JWKSCheck, error) {
	check := s.probeJWKS(ctx, jwksURI)
	if check.Error != "" {
		msg := "the issuer's JWKS could not be fetched"
		if check.Error == "jwks_empty" {
			msg = "the issuer's JWKS has no usable signing keys"
		}
		return check, issuerErr(http.StatusUnprocessableEntity, check.Error, msg)
	}
	return check, nil
}

func (s *ExternalIssuerService) probeJWKS(ctx context.Context, jwksURI string) *JWKSCheck {
	out := &JWKSCheck{JWKSURI: jwksURI, CheckedAt: time.Now().UTC(), KIDs: []string{}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		out.Error = "jwks_unreachable"
		return out
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		// Folded into unreachable, as for discovery; the log keeps why.
		out.Error = "jwks_unreachable"
		log.Info().Err(err).Str("jwks_uri", jwksURI).
			Bool("private_address", errors.Is(err, attestation.ErrPrivateAttestationEndpoint)).Msg("JWKS probe failed")
		return out
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		out.Error = "jwks_unreachable"
		return out
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSProbeBytes+1))
	if err != nil || len(body) > maxJWKSProbeBytes {
		out.Error = "jwks_unreachable"
		return out
	}
	out.Reachable = true
	set, err := jwk.Parse(body)
	if err != nil {
		out.Error = "jwks_empty"
		return out
	}
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok || !signingKey(key) {
			continue
		}
		out.KeyCount++
		if kid, ok := key.KeyID(); ok && kid != "" {
			out.KIDs = append(out.KIDs, kid)
		}
	}
	if out.KeyCount == 0 {
		out.Error = "jwks_empty"
	}
	return out
}

// signingKey reports whether a JWK can verify an RS256, ES256 or PS256 token.
func signingKey(key jwk.Key) bool {
	if use, ok := key.KeyUsage(); ok && use != "" && use != string(jwk.ForSignature) {
		return false
	}
	switch key.KeyType() {
	case jwa.RSA(), jwa.EC():
		return true
	}
	return false
}

// ── Bindings ─────────────────────────────────────────────────────────────────

// BindingInput is a create request for a credential binding (ADR 0042 D6).
type BindingInput struct {
	SubjectKey string
	IdentityID string
	Enabled    *bool
	// Client, when set, also creates or links the OAuth client the agent
	// presents on P1b/P1c.
	Client *BindingClientInput
}

// BindingClientInput names the presenting OAuth client. ClientID defaults to
// the subject key (on P1c the client_id is the ID token's aud).
type BindingClientInput struct {
	ClientID string
}

// BindingClientResult reports what happened to the presenting client.
type BindingClientResult struct {
	ClientID string `json:"client_id"`
	Created  bool   `json:"created"`
}

// CreateBinding binds a subject key under one of accountID's issuers to an
// identity in the same account. A binding for an identity that is not active
// is created disabled (D6: enabled on adoption).
func (s *ExternalIssuerService) CreateBinding(ctx context.Context, accountID, issuerID, actor string, in BindingInput) (*domain.IssuerBinding, *BindingClientResult, error) {
	if err := s.requireDB(); err != nil {
		return nil, nil, err
	}
	in.SubjectKey = strings.TrimSpace(in.SubjectKey)
	if in.SubjectKey == "" || len(in.SubjectKey) > domain.MaxSubjectKeyBytes {
		return nil, nil, issuerErr(http.StatusBadRequest, "invalid_subject_key",
			fmt.Sprintf("subject_key is required (at most %d bytes)", domain.MaxSubjectKeyBytes))
	}
	if !validUUID(issuerID) {
		return nil, nil, errIssuerNotFound
	}
	if !validUUID(in.IdentityID) {
		return nil, nil, issuerErr(http.StatusUnprocessableEntity, "identity_not_found", "identity_id names no identity in this account")
	}
	if _, err := s.repo.Get(ctx, issuerID, accountID); err != nil {
		return nil, nil, notFoundOr(err, errIssuerNotFound)
	}
	identity, err := s.identityLookup(ctx, in.IdentityID, []string{accountID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, issuerErr(http.StatusUnprocessableEntity, "identity_not_found", "identity_id names no identity in this account")
		}
		return nil, nil, err
	}
	enabled := in.Enabled == nil || *in.Enabled
	if identity.Status != domain.IdentityStatusActive {
		enabled = false
	}
	b := &domain.IssuerBinding{
		AccountID: accountID, IssuerID: issuerID, SubjectKey: in.SubjectKey,
		IdentityID: identity.ID, Enabled: enabled, CreatedBy: actor, UpdatedBy: actor,
		// Asked for disabled: an admin's decision, which adoption must not
		// undo. Disabled only for a non-active identity is not.
		ExplicitlyDisabled: in.Enabled != nil && !*in.Enabled,
	}
	var clientRes *BindingClientResult
	err = s.inTx(ctx, actor, func(ctx context.Context) error {
		// Re-read the issuer locked: a delete committing between the read
		// above and this insert would otherwise leave a live binding under
		// a deleted issuer.
		if _, err := s.repo.GetForShare(ctx, issuerID, accountID); err != nil {
			return notFoundOr(err, errIssuerNotFound)
		}
		if err := s.repo.InsertBinding(ctx, b); err != nil {
			return bindingWriteError(err)
		}
		if in.Client != nil {
			res, err := s.ensurePresentingClient(ctx, identity, in.Client, in.SubjectKey)
			if err != nil {
				return err
			}
			clientRes = res
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return b, clientRes, nil
}

// bindingWriteError maps the two binding unique indexes.
func bindingWriteError(err error) error {
	var pgErr interface{ Field(byte) string }
	if errors.As(err, &pgErr) && pgErr.Field('C') == "23505" {
		if strings.Contains(pgErr.Field('n'), "enabled_uq") {
			return issuerErr(http.StatusConflict, "binding_conflict",
				"another enabled binding already maps this subject key under this issuer")
		}
		return issuerErr(http.StatusConflict, "binding_exists", "this binding already exists")
	}
	return err
}

// ensurePresentingClient creates, or confirms, the OAuth client an agent
// presents on P1b/P1c: private_key_jwt with the identity's registered key,
// linked to the identity, allowed token-exchange and jwt-bearer.
func (s *ExternalIssuerService) ensurePresentingClient(ctx context.Context, identity *domain.Identity, in *BindingClientInput, subjectKey string) (*BindingClientResult, error) {
	clientID := strings.TrimSpace(in.ClientID)
	if clientID == "" {
		clientID = subjectKey
	}
	existing, err := s.oauthClientSvc.GetClientByClientID(ctx, clientID)
	switch {
	case err == nil:
		if existing.IdentityID != nil && *existing.IdentityID == identity.ID && existing.TokenEndpointAuthMethod == clientAuthMethodPrivateKeyJWT {
			return &BindingClientResult{ClientID: clientID}, nil
		}
		return nil, issuerErr(http.StatusConflict, "client_conflict",
			"an OAuth client with this client_id exists and is not this identity's private_key_jwt client")
	case !errors.Is(err, ErrOAuthClientNotFound):
		return nil, err
	}
	jwks, err := identityJWKS(identity)
	if err != nil {
		return nil, issuerErr(http.StatusUnprocessableEntity, "identity_has_no_public_key",
			"the identity has no registered EC P-256 public key to authenticate its client with")
	}
	_, _, err = s.oauthClientSvc.RegisterClient(ctx, RegisterClientRequest{
		ClientID:                clientID,
		Name:                    "IdP client for " + identity.ExternalID,
		TokenEndpointAuthMethod: clientAuthMethodPrivateKeyJWT,
		JWKS:                    jwks,
		GrantTypes:              []string{grantTypeTokenExchangeURN, grantTypeJWTBearerURN},
		IdentityID:              identity.ID,
	})
	if err != nil {
		if errors.Is(err, ErrOAuthClientAlreadyExists) {
			return nil, issuerErr(http.StatusConflict, "client_conflict", "an OAuth client with this client_id already exists")
		}
		return nil, err
	}
	return &BindingClientResult{ClientID: clientID, Created: true}, nil
}

// identityJWKS renders an identity's registered public key as a JWK Set.
func identityJWKS(identity *domain.Identity) (json.RawMessage, error) {
	if identity.PublicKeyPEM == "" {
		return nil, errors.New("no public key")
	}
	pub, err := parseECPublicKeyPEM(identity.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	key, err := jwk.Import[jwk.Key](pub)
	if err != nil {
		return nil, err
	}
	_ = key.Set(jwk.KeyIDKey, identity.ID)
	_ = key.Set(jwk.AlgorithmKey, jwa.ES256())
	_ = key.Set(jwk.KeyUsageKey, jwk.ForSignature)
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, err
	}
	return json.Marshal(set)
}

// ListBindings returns an issuer's bindings, or only identityID's when it
// is non-empty.
func (s *ExternalIssuerService) ListBindings(ctx context.Context, accountID, issuerID, identityID string) ([]*domain.IssuerBinding, error) {
	if identityID != "" && !validUUID(identityID) {
		return nil, issuerErr(http.StatusBadRequest, "invalid_identity_id", "identity_id must be a UUID")
	}
	if _, err := s.Get(ctx, accountID, issuerID); err != nil {
		return nil, err
	}
	return s.repo.ListBindings(ctx, accountID, issuerID, identityID)
}

// ListAccountBindings returns the account's bindings under every issuer, or
// only identityID's when it is non-empty: one query where a caller would
// otherwise walk every issuer.
func (s *ExternalIssuerService) ListAccountBindings(ctx context.Context, accountID, identityID string) ([]*domain.IssuerBinding, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if identityID != "" && !validUUID(identityID) {
		return nil, issuerErr(http.StatusBadRequest, "invalid_identity_id", "identity_id must be a UUID")
	}
	return s.repo.ListBindings(ctx, accountID, "", identityID)
}

// GetBinding returns one binding.
func (s *ExternalIssuerService) GetBinding(ctx context.Context, accountID, issuerID, id string) (*domain.IssuerBinding, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if !validUUID(issuerID) || !validUUID(id) {
		return nil, errBindingNotFound
	}
	b, err := s.repo.GetBinding(ctx, id, issuerID, accountID)
	if err != nil {
		return nil, notFoundOr(err, errBindingNotFound)
	}
	return b, nil
}

// SetBindingEnabled enables or disables a binding. Enabling needs an active
// identity and no other enabled binding for the same subject key. With
// unlessExplicitlyDisabled an enable applies only if no admin disabled the
// binding, decided atomically (the deployer's enable at adoption).
func (s *ExternalIssuerService) SetBindingEnabled(ctx context.Context, accountID, issuerID, id, actor string, enabled, unlessExplicitlyDisabled bool) (*domain.IssuerBinding, error) {
	b, err := s.GetBinding(ctx, accountID, issuerID, id)
	if err != nil {
		return nil, err
	}
	if enabled {
		identity, err := s.identityLookup(ctx, b.IdentityID, []string{accountID})
		if err != nil {
			return nil, err
		}
		if identity.Status != domain.IdentityStatusActive {
			return nil, issuerErr(http.StatusConflict, "identity_not_active",
				fmt.Sprintf("the identity is %s; a binding is enabled only for an active (adopted) identity", identity.Status))
		}
	}
	b.Enabled = enabled
	b.ExplicitlyDisabled = !enabled
	b.UpdatedBy = actor
	err = s.inTx(ctx, actor, func(ctx context.Context) error {
		if err := s.repo.UpdateBinding(ctx, b, enabled && unlessExplicitlyDisabled); err != nil {
			if errors.Is(err, postgres.ErrBindingExplicitlyDisabled) {
				return issuerErr(http.StatusConflict, "binding_explicitly_disabled",
					"an admin disabled this binding; it is enabled only by an explicit request")
			}
			if errors.Is(err, sql.ErrNoRows) {
				return errBindingNotFound
			}
			return bindingWriteError(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DeleteBinding removes a binding.
func (s *ExternalIssuerService) DeleteBinding(ctx context.Context, accountID, issuerID, id, actor string) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if !validUUID(issuerID) || !validUUID(id) {
		return errBindingNotFound
	}
	return s.inTx(ctx, actor, func(ctx context.Context) error {
		return notFoundOr(s.repo.DeleteBinding(ctx, id, issuerID, accountID), errBindingNotFound)
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (s *ExternalIssuerService) inTx(ctx context.Context, actor string, fn func(ctx context.Context) error) error {
	return s.repo.DB().RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		ctx = postgres.WithTx(ctx, tx)
		if err := s.repo.SetAuditActor(ctx, actor); err != nil {
			return err
		}
		return fn(ctx)
	})
}

func notFoundOr(err, notFound error) error {
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return notFound
	}
	return err
}

func validationToAPIError(err error) error {
	var ve *domain.IssuerValidationError
	if errors.As(err, &ve) {
		status := http.StatusBadRequest
		if ve.Code == "shared_issuer_requires_constraints" {
			status = http.StatusUnprocessableEntity
		}
		return issuerErr(status, ve.Code, ve.Message)
	}
	return err
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneConstraints(m map[string][]string) map[string][]string {
	if m == nil {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}
