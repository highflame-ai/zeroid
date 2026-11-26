# ZeroID as an AAuth Agent Provider: interop and demo

A workload with no secrets gets an [AAuth](https://aauth.dev) agent identity
from ZeroID, calls an AAuth resource with it, and bridges to an OAuth-only
MCP resource. Everything runs on one machine; nothing is sent anywhere else.

The agent signing and the resource-side agent-token verification are
[aauth-go](https://github.com/aauth-dev/aauth-go)'s, the reference
implementation, so both the test and the demo check ZeroID against an
independent implementation.

This is its own Go module so ZeroID's module never depends on aauth-go. It is
not in `go.work`: run Go commands here with `GOWORK=off`.

## Interop test

```bash
cd examples/aauth
GOWORK=off go test ./interop -v
```

Needs Docker for Postgres (set `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` if
testcontainers can't reach it over IPv6). It checks that:

1. aauth-go's `agentprovider.Client` enrolls at ZeroID's `POST /ap/token`,
   signing with aauth-go's RFC 9421 signer, and the same pod key redeems the
   pod's platform token again;
2. aauth-go's agent transport presents the ZeroID agent token to an aauth-go
   `ResourceGuard`, which verifies it from ZeroID's
   `/.well-known/aauth-agent.json` and `/ap/jwks.json`;
3. the bridged, DPoP-bound OAuth token works at the OAuth-only resource, is
   useless without the agent key, and dies when the agent token is revoked;
4. another key presenting the same platform token is refused.

## Demo

```bash
cd examples/aauth
docker compose up --build --abort-on-container-exit --exit-code-from demo-agent demo-agent
docker compose down -v
```

| Service | Role |
| --- | --- |
| `zeroid` | ZeroID with `aauth.enabled`, behind Caddy as `https://auth.zeroid.test` |
| `caddy` | TLS for `auth.zeroid.test` and `resource.zeroid.test` from its local CA (AAuth issuers are https, host only) |
| `mockidp` | Stands in for a Kubernetes cluster's service-account issuer |
| `demo-setup` | The one-time admin setup, through ZeroID's admin API: a policy listing `aauth_agent` and `aauth_bridge`, the agent identity, the cluster's issuer row and the service account binding |
| `demo-resource` | `/whoami`, an AAuth resource guarded by aauth-go; `/mcp`, an OAuth-only tool that takes the bridged DPoP token and introspects it |
| `demo-agent` | The workload, narrating each step |

### Use a throwaway database

This branch adds migration 073 but not main's 069–072. A persistent database
migrated by it is recorded at version 73, and later builds of main would then
skip 069–072. The compose demo uses its own Postgres volume
(`docker compose down -v` removes it); don't point this branch at a shared or
long-lived database until it is rebased onto main.

### Dev-only settings

The compose file turns on settings that must stay off in production:
`ZEROID_FEDERATION_ALLOW_PRIVATE_ENDPOINTS` (the mock issuer is plain http),
`ZEROID_ALLOW_UNAUTHENTICATED_TOKEN_INSPECTION` (the demo resource introspects
without client credentials), and the issuer row is written enabled directly,
skipping the proof of control Highflame Admin runs before enabling one. ZeroID's
admin API is reachable through Caddy too; a real deployment keeps it private.

## On a real cluster or cloud

`demo-agent` also takes `PLATFORM=k8s` (a projected service account token file
with audience ZeroID's issuer and `expirationSeconds: 600`; `TOKEN_FILE`) and
`PLATFORM=aws` (an STS web identity token from the AWS CLI). The Kubernetes
path is written but not yet run on a real cluster.

### With a real AWS token

Verified on 2026-11-26 against a real account. The account needs outbound
identity federation (`aws iam enable-outbound-web-identity-federation`, which
prints its issuer) and the principal `sts:GetWebIdentityToken`. The token's
`sub` is the role ARN, so bind that.

```bash
docker compose up -d --build postgres keygen zeroid caddy demo-resource
docker compose run --rm -e CLUSTER_ISSUER=<account issuer> -e SA_SUBJECT=<role ARN> demo-setup
aws sts get-web-identity-token --audience https://auth.zeroid.test --signing-algorithm RS256 \
  --output json | jq -r .WebIdentityToken > aws-token        # valid 5 minutes
docker compose run --rm --no-deps -e PLATFORM=k8s -e TOKEN_FILE=/aws/token \
  -v "$PWD/aws-token:/aws/token:ro" demo-agent
docker compose down -v && rm -f aws-token
``` Keep `KEY_FILE` on a volume
every container of the pod shares (an `emptyDir`): the pod keeps one agent key,
which is what lets a restarted container redeem the pod's platform token again.
