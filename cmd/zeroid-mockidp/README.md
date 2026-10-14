# zeroid-mockidp

A fake upstream IdP for running trusted issuers (ADR 0042) end to end without a real Entra tenant or Okta org.
It signs whatever it is asked to sign, so it is a test fixture and never a deployment component.

It publishes three issuers, each with its own RSA key:

| Issuer | Discovery | Keys | Shape |
|---|---|---|---|
| `{base}/entra/{tenant}/v2.0` | `{base}/entra/{tenant}/v2.0/.well-known/openid-configuration` | `{base}/entra/{tenant}/discovery/v2.0/keys` | Keys carry no `alg`, like Entra's |
| `{base}/okta` | `{base}/okta/.well-known/openid-configuration` | `{base}/okta/oauth2/v1/keys` | An Okta org authorization server |
| `{base}/k8s` | `{base}/k8s/.well-known/openid-configuration` | `{base}/k8s/openid/v1/jwks` | A Kubernetes service-account issuer |

Any tenant id works in the Entra paths; `11111111-2222-3333-4444-555555555555` is the default.

## Run

```bash
go run ./cmd/zeroid-mockidp -addr :8080 -base-url http://mockidp:8080
```

`-base-url` must be the URL ZeroID uses to reach the server, because it is the `iss` in every token.
The issuers are plain http, so the ZeroID under test needs `federation.allow_private_endpoints: true` (`ZEROID_FEDERATION_ALLOW_PRIVATE_ENDPOINTS=true`), which also admits http issuer and JWKS URLs.
That setting is for local development only.

## Mint a token

`POST /mint` with a JSON body:

| Field | Meaning |
|---|---|
| `profile` | One of the profiles below. |
| `tenant` | Entra tenant id for the Entra profiles. |
| `claims` | Overrides the profile's claims; a `null` value removes one. `aud` is always required. |
| `header_typ` | Overrides the JWS `typ` header (`""` drops it). |
| `ttl_seconds` | Token lifetime, default 300. |

The response is `{"token": "<jwt>", "claims": {...}}`.

| Profile | What it is | ZeroID should |
|---|---|---|
| `entra_id_token` | An Entra v2.0 ID token: `oid`, `tid`, pairwise `sub`, `email` with `xms_edov: true` | Exchange it (P1c) when presented by the client in `aud` |
| `entra_app_only` | An Entra app-only token: `idtyp: app`, `sub` = `oid` | Refuse it on person grants |
| `access_token_lookalike` | An Entra access token: the ID token claims plus `scp` | Refuse it as an ID token |
| `okta_id_jag` | An Okta Cross App Access ID-JAG: `typ: oauth-id-jag+jwt`, person in `sub`, agent in `act.sub` and `client_id` (default `0oaAGENT`) | Redeem it (P1b) for the agent bound to `act.sub`; add `resource` |
| `k8s_sa` | A Kubernetes service-account token, `sub` = `system:serviceaccount:default:agent` | Refuse it on person grants |

```bash
curl -s localhost:8080/mint -d '{"profile":"entra_id_token","claims":{"aud":"<agent-app-id>","email":"alice@acme.example"}}'
curl -s localhost:8080/mint -d '{"profile":"okta_id_jag","claims":{"aud":"<zeroid-issuer>","resource":"https://gateway/mcp/github","act":{"sub":"0oaAGENT","sub_profile":"ai_agent"}}}'
```

## Wiring it to ZeroID

See `docs/external-issuers.md` for the admin API.
For an Entra-shaped person issuer, create a row with the generic preset (the `entra` preset only accepts `login.microsoftonline.com`):

```json
{
  "kind": "person",
  "issuer": "http://mockidp:8080/entra/11111111-2222-3333-4444-555555555555/v2.0",
  "jwks_uri": "http://mockidp:8080/entra/11111111-2222-3333-4444-555555555555/discovery/v2.0/keys",
  "algorithms": ["RS256"],
  "claim_mapping": {"user_id": "oid", "email": "email", "email_verified": "xms_edov", "name": "name"},
  "claim_constraints": {"tid": ["11111111-2222-3333-4444-555555555555"]}
}
```

The row needs no `audiences`: bind the agent's app id (`POST /external-issuers/{id}/bindings` with `subject_key` = the app id and `oauth_client: {}`), and that binding admits the app id as the ID token's audience.
