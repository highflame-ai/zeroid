package integration_test

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Code-agent bootstrap integration tests (highflame-architecture#136, epic
// #132 slice S3): a code agent on a developer machine registers itself with a
// zeroid:bootstrap-scoped developer token + locally generated EC P-256
// custody key, receives identity + first token, self-serves subsequent
// tokens via jwt_bearer, periodically attests, and is revocable by machine.

// mintBootstrapToken mints a developer bootstrap token through the PKCE
// authorization_code flow — the real path a `zeroid login`-style CLI uses.
// The resulting access token is RS256 with sub = userID and carries the given
// scopes, exercising BootstrapAuthMiddleware's RS256 fallback.
func mintBootstrapToken(t *testing.T, userID string, scopes []string) string {
	t.Helper()
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testCLIClientID, userID, testRedirectURI, challenge, scopes)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "bootstrap token mint: expected 200")
	return decode(t, resp)["access_token"].(string)
}

// bootstrappedCodeAgent bundles everything a bootstrap call returns plus the
// custody key the "machine" generated.
type bootstrappedCodeAgent struct {
	IdentityID  string
	WIMSEURI    string
	AccessToken string
	Key         *ecdsa.PrivateKey
	MachineID   string
}

// bootstrapCodeAgent generates a custody keypair and registers a code agent
// via POST /code-agents/bootstrap, asserting the 201 happy path.
func bootstrapCodeAgent(t *testing.T, bootstrapToken, framework, machineID string) bootstrappedCodeAgent {
	t.Helper()
	key := generateKey(t)
	resp := post(t, "/code-agents/bootstrap", map[string]any{
		"public_key_pem": ecPublicKeyPEM(t, key),
		"framework":      framework,
		"machine_id":     machineID,
	}, map[string]string{"Authorization": "Bearer " + bootstrapToken})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "bootstrap: expected 201")
	body := decode(t, resp)

	identity := body["identity"].(map[string]any)
	accessToken := body["access_token"].(map[string]any)
	return bootstrappedCodeAgent{
		IdentityID:  identity["id"].(string),
		WIMSEURI:    body["wimse_uri"].(string),
		AccessToken: accessToken["access_token"].(string),
		Key:         key,
		MachineID:   machineID,
	}
}

// codeAgentBootstrapRow reads the migration-038 columns for one identity
// directly from the database.
type codeAgentBootstrapRow struct {
	OwnerUserID         string
	BootstrapMachineID  sql.NullString
	LastAttestedAt      sql.NullTime
	AttestationEvidence sql.NullString
	Status              string
}

func fetchBootstrapRow(t *testing.T, identityID string) codeAgentBootstrapRow {
	t.Helper()
	var row codeAgentBootstrapRow
	err := testDB.NewSelect().
		TableExpr("identities").
		ColumnExpr("owner_user_id, bootstrap_machine_id, last_attested_at, attestation_evidence, status").
		Where("id = ?", identityID).
		Scan(context.Background(), &row.OwnerUserID, &row.BootstrapMachineID, &row.LastAttestedAt, &row.AttestationEvidence, &row.Status)
	require.NoError(t, err)
	return row
}

// TestCodeAgentBootstrap_HappyPath: PKCE developer token → bootstrap → 201
// with a spiffe:// identity, persisted machine binding, owner = token sub,
// and a first access token that is a valid ES256 ZeroID JWT for the agent.
func TestCodeAgentBootstrap_HappyPath(t *testing.T) {
	developer := uid("dev-boot")
	token := mintBootstrapToken(t, developer, []string{"zeroid:bootstrap"})

	agent := bootstrapCodeAgent(t, token, "claude-code", uid("machine"))

	assert.True(t, strings.HasPrefix(agent.WIMSEURI, "spiffe://"), "wimse_uri must be a SPIFFE ID, got %q", agent.WIMSEURI)

	// DB row: machine binding + ownership from the token, never the body.
	row := fetchBootstrapRow(t, agent.IdentityID)
	require.True(t, row.BootstrapMachineID.Valid)
	assert.Equal(t, agent.MachineID, row.BootstrapMachineID.String)
	assert.Equal(t, developer, row.OwnerUserID, "owner_user_id must be the bootstrap token's sub")
	require.True(t, row.LastAttestedAt.Valid, "bootstrap counts as the first attestation")

	// First token: ES256, signed by this server, sub = the agent's WIMSE URI.
	parsed, err := jwt.Parse([]byte(agent.AccessToken),
		jwt.WithKey(jwa.ES256(), &testServerPrivKey.PublicKey),
		jwt.WithValidate(true),
		jwt.WithIssuer(testIssuer),
	)
	require.NoError(t, err, "first access token must be a valid ES256 ZeroID JWT")
	sub, _ := parsed.Subject()
	assert.Equal(t, agent.WIMSEURI, sub)
}

// TestCodeAgentBootstrap_ES256ClientCredentialsTokenAccepted covers the
// middleware's primary ES256 branch: a client_credentials-minted token
// carrying zeroid:bootstrap also authorizes bootstrap (sub is the client
// identity's WIMSE URI, which simply becomes the owner id).
func TestCodeAgentBootstrap_ES256ClientCredentialsTokenAccepted(t *testing.T) {
	extID := uid("boot-cc-client")
	registerIdentity(t, extID, []string{"zeroid:bootstrap"})
	client := registerOAuthClient(t, extID, []string{"zeroid:bootstrap"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "zeroid:bootstrap",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	ccToken := decode(t, resp)["access_token"].(string)

	agent := bootstrapCodeAgent(t, ccToken, "claude-code", uid("machine-cc"))
	row := fetchBootstrapRow(t, agent.IdentityID)
	require.True(t, row.BootstrapMachineID.Valid)
	assert.Equal(t, agent.MachineID, row.BootstrapMachineID.String)
}

// TestCodeAgentBootstrap_JWTBearerRoundTrip: after bootstrap the agent
// self-serves its next token via jwt_bearer signed with the custody key —
// and a single tampered signature byte flips the answer to invalid_grant.
func TestCodeAgentBootstrap_JWTBearerRoundTrip(t *testing.T) {
	token := mintBootstrapToken(t, uid("dev-jb"), []string{"zeroid:bootstrap"})
	agent := bootstrapCodeAgent(t, token, "claude-code", uid("machine-jb"))

	assertion := buildAssertion(t, agent.Key, agent.WIMSEURI)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    assertion,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "jwt_bearer with the bootstrap custody key must succeed")
	nextToken := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, nextToken)
	sub := decodeJWTUnsafe(t, nextToken)["sub"].(string)
	assert.Equal(t, agent.WIMSEURI, sub)

	// Tamper one byte of the assertion's signature → invalid_grant.
	tampered := assertion[:len(assertion)-1] + flipLastByte(assertion)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    tampered,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"], "tampered assertion signature must be invalid_grant")
}

// TestCodeAgentBootstrap_MissingScopeForbidden: a perfectly valid ZeroID
// token WITHOUT zeroid:bootstrap must be rejected with 403
// insufficient_scope — ordinary access tokens can never register code agents.
func TestCodeAgentBootstrap_MissingScopeForbidden(t *testing.T) {
	token := mintBootstrapToken(t, uid("dev-noscope"), []string{"data:read"})

	key := generateKey(t)
	resp := post(t, "/code-agents/bootstrap", map[string]any{
		"public_key_pem": ecPublicKeyPEM(t, key),
		"framework":      "claude-code",
		"machine_id":     uid("machine-noscope"),
	}, map[string]string{"Authorization": "Bearer " + token})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "insufficient_scope",
		"403 must carry an RFC 6750 insufficient_scope challenge")
	_ = resp.Body.Close()
}

// TestCodeAgentAttest: the agent refreshes its attestation with its OWN
// access token; another agent's token is rejected with 403.
func TestCodeAgentAttest(t *testing.T) {
	token := mintBootstrapToken(t, uid("dev-attest"), []string{"zeroid:bootstrap"})
	agentA := bootstrapCodeAgent(t, token, "claude-code", uid("machine-att-a"))
	agentB := bootstrapCodeAgent(t, token, "claude-code", uid("machine-att-b"))

	before := fetchBootstrapRow(t, agentA.IdentityID)
	require.True(t, before.LastAttestedAt.Valid)

	resp := post(t, "/code-agents/"+agentA.IdentityID+"/attest", map[string]any{
		"evidence": map[string]any{"os": "darwin", "hostname_hash": "abc123"},
	}, map[string]string{"Authorization": "Bearer " + agentA.AccessToken})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	require.NotEmpty(t, body["last_attested_at"])

	after := fetchBootstrapRow(t, agentA.IdentityID)
	require.True(t, after.LastAttestedAt.Valid)
	assert.True(t, after.LastAttestedAt.Time.After(before.LastAttestedAt.Time),
		"attest must bump last_attested_at past the bootstrap timestamp")
	require.True(t, after.AttestationEvidence.Valid)
	assert.Contains(t, after.AttestationEvidence.String, "darwin")

	// Another agent's token must not attest agent A.
	resp = post(t, "/code-agents/"+agentA.IdentityID+"/attest", map[string]any{
		"evidence": map[string]any{"os": "linux"},
	}, map[string]string{"Authorization": "Bearer " + agentB.AccessToken})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestCodeAgentRevokeByMachine: the lost-laptop response — every agent
// bootstrapped from the machine is deactivated in one admin call, and the
// custody key stops working for jwt_bearer immediately.
func TestCodeAgentRevokeByMachine(t *testing.T) {
	token := mintBootstrapToken(t, uid("dev-revoke"), []string{"zeroid:bootstrap"})
	machineID := uid("machine-rv")
	agent := bootstrapCodeAgent(t, token, "claude-code", machineID)
	// A second framework on the same machine — revoke must catch both.
	agent2 := bootstrapCodeAgent(t, token, "cursor", machineID)

	resp := post(t, adminPath("/code-agents/by-machine/"+machineID+"/revoke"),
		map[string]any{}, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, float64(2), body["revoked"], "both agents on the machine must be revoked")

	for _, id := range []string{agent.IdentityID, agent2.IdentityID} {
		row := fetchBootstrapRow(t, id)
		assert.Equal(t, "deactivated", row.Status)
	}

	// The custody key is dead: a fresh jwt_bearer assertion now fails.
	assertion := buildAssertion(t, agent.Key, agent.WIMSEURI)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    assertion,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	tokenBody := decode(t, resp)
	assert.Equal(t, "invalid_grant", tokenBody["error"],
		"a revoked code agent must not mint fresh tokens")

	// Idempotent-ish: a second sweep finds nothing active.
	resp = post(t, adminPath("/code-agents/by-machine/"+machineID+"/revoke"),
		map[string]any{}, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, float64(0), decode(t, resp)["revoked"])
}

// TestCodeAgentRevokeByMachine_OwnerFilter: the optional owner_user_id filter
// only revokes that developer's agents on the shared machine.
func TestCodeAgentRevokeByMachine_OwnerFilter(t *testing.T) {
	devA := uid("dev-shared-a")
	devB := uid("dev-shared-b")
	machineID := uid("machine-shared")
	agentA := bootstrapCodeAgent(t, mintBootstrapToken(t, devA, []string{"zeroid:bootstrap"}), "claude-code", machineID)
	agentB := bootstrapCodeAgent(t, mintBootstrapToken(t, devB, []string{"zeroid:bootstrap"}), "cursor", machineID)

	resp := post(t, adminPath("/code-agents/by-machine/"+machineID+"/revoke"),
		map[string]any{"owner_user_id": devA}, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, float64(1), decode(t, resp)["revoked"])

	assert.Equal(t, "deactivated", fetchBootstrapRow(t, agentA.IdentityID).Status)
	assert.Equal(t, "active", fetchBootstrapRow(t, agentB.IdentityID).Status,
		"the other developer's agent on the same machine must stay active")
}

// TestCodeAgentListByDeveloper: the admin inventory view returns the
// developer's bootstrapped agents (and only theirs).
func TestCodeAgentListByDeveloper(t *testing.T) {
	developer := uid("dev-list")
	token := mintBootstrapToken(t, developer, []string{"zeroid:bootstrap"})
	agent := bootstrapCodeAgent(t, token, "claude-code", uid("machine-ls"))

	resp := get(t, adminPath("/code-agents/by-developer/"+developer), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents, ok := body["code_agents"].([]any)
	require.True(t, ok, "response must carry a code_agents array")
	require.Len(t, agents, 1)
	got := agents[0].(map[string]any)
	assert.Equal(t, agent.IdentityID, got["id"])
	assert.Equal(t, developer, got["owner_user_id"])

	// A developer with no agents gets an empty list, not an error.
	resp = get(t, adminPath("/code-agents/by-developer/"+uid("dev-empty")), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	empty := decode(t, resp)
	assert.Empty(t, empty["code_agents"])
}

// TestCodeAgentReBootstrap_SameOwnerWithEnrolledKeyConflicts: re-bootstrapping
// the same (framework, machine) while its agent is still active and already
// has a custody key MUST be refused (409), never a silent key swap — otherwise
// a stolen bootstrap token could hijack an established identity (INV-IDN-004).
// The original custody key keeps working; nothing is rotated.
func TestCodeAgentReBootstrap_SameOwnerWithEnrolledKeyConflicts(t *testing.T) {
	developer := uid("dev-reboot")
	token := mintBootstrapToken(t, developer, []string{"zeroid:bootstrap"})
	machineID := uid("machine-rb")

	first := bootstrapCodeAgent(t, token, "claude-code", machineID)

	// Second bootstrap for the same machine with a DIFFERENT key → 409.
	newKey := generateKey(t)
	resp := post(t, "/code-agents/bootstrap", map[string]any{
		"public_key_pem": ecPublicKeyPEM(t, newKey),
		"framework":      "claude-code",
		"machine_id":     machineID,
	}, map[string]string{"Authorization": "Bearer " + token})
	assert.Equal(t, http.StatusConflict, resp.StatusCode,
		"re-bootstrap of an active agent with an enrolled key must be refused, not swap the key")
	_ = resp.Body.Close()

	// The ORIGINAL key still works — the refused re-bootstrap changed nothing.
	assertion := buildAssertion(t, first.Key, first.WIMSEURI)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    assertion,
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"the original custody key must remain valid after a refused re-bootstrap")
	_ = resp.Body.Close()
}

// TestCodeAgentReBootstrap_RevokedMachineCreatesFreshIdentity: the sanctioned
// lost-laptop recovery. After revoke-by-machine, re-bootstrapping the same
// machine mints a BRAND-NEW identity (new id + WIMSE URI); the revoked row
// stays deactivated (audit lineage preserved) and its old key stays dead.
func TestCodeAgentReBootstrap_RevokedMachineCreatesFreshIdentity(t *testing.T) {
	developer := uid("dev-recover")
	token := mintBootstrapToken(t, developer, []string{"zeroid:bootstrap"})
	machineID := uid("machine-recover")

	first := bootstrapCodeAgent(t, token, "claude-code", machineID)

	// Lost laptop → revoke the machine.
	resp := post(t, adminPath("/code-agents/by-machine/"+machineID+"/revoke"),
		map[string]any{}, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, float64(1), decode(t, resp)["revoked"])

	// Re-bootstrap now succeeds with a fresh identity (not the revoked one).
	second := bootstrapCodeAgent(t, token, "claude-code", machineID)
	assert.NotEqual(t, first.IdentityID, second.IdentityID,
		"recovery must mint a NEW identity, not reuse the revoked one")
	assert.NotEqual(t, first.WIMSEURI, second.WIMSEURI,
		"the fresh identity must carry its own WIMSE URI")

	// The revoked identity stays deactivated and its key stays dead.
	assert.Equal(t, "deactivated", fetchBootstrapRow(t, first.IdentityID).Status)
	oldAssertion := buildAssertion(t, first.Key, first.WIMSEURI)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    oldAssertion,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"the revoked identity's key must stay dead")
	_ = resp.Body.Close()

	// The fresh identity's new key works.
	newAssertion := buildAssertion(t, second.Key, second.WIMSEURI)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    newAssertion,
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the fresh identity's key must work")
	_ = resp.Body.Close()
}

// TestCodeAgentReBootstrap_DifferentOwnerConflicts: another developer cannot
// take over an existing machine registration — the deterministic external_id
// collision surfaces as 409 rather than a silent key swap.
func TestCodeAgentReBootstrap_DifferentOwnerConflicts(t *testing.T) {
	machineID := uid("machine-steal")
	bootstrapCodeAgent(t, mintBootstrapToken(t, uid("dev-victim"), []string{"zeroid:bootstrap"}), "claude-code", machineID)

	thief := mintBootstrapToken(t, uid("dev-thief"), []string{"zeroid:bootstrap"})
	key := generateKey(t)
	resp := post(t, "/code-agents/bootstrap", map[string]any{
		"public_key_pem": ecPublicKeyPEM(t, key),
		"framework":      "claude-code",
		"machine_id":     machineID,
	}, map[string]string{"Authorization": "Bearer " + thief})
	assert.Equal(t, http.StatusConflict, resp.StatusCode,
		"another developer must not be able to take over an existing machine registration")
	_ = resp.Body.Close()
}
