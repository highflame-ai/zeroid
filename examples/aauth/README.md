# Secretless agents with ZeroID and AAuth

AI agents need to call APIs and MCP servers. Today that usually means an API
key or client secret in an environment variable: something to store, rotate,
and eventually leak.

This demo shows another way. An agent running in Kubernetes or on AWS proves
who it is with the identity its platform **already gives it**. ZeroID turns
that into an [AAuth](https://aauth.dev) agent identity, and the agent uses it
to call both AAuth-native resources and ordinary OAuth-protected MCP servers.
**No secret is created, stored or shipped at any point.**

## Why it matters

- **Nothing to leak.** The agent starts from a short-lived token minted by its
  cloud or cluster. There's no API key to put in a vault, and none to rotate.
- **Stolen tokens are useless.** Every credential ZeroID issues is bound to a
  key that never leaves the agent. A copied token, on its own, gets an attacker
  nothing, and the demo shows this.
- **Works with what you already run.** Resources that speak AAuth verify the
  agent directly. Resources that only speak OAuth, like most MCP servers today,
  get a standard OAuth access token through ZeroID's bridge.
- **One identity across both worlds.** Every call traces back to one agent
  identity in ZeroID, so revoking it cuts off everything at once.
- **Built on open standards.** AAuth, HTTP Message Signatures (RFC 9421) and
  DPoP (RFC 9449). The agent and resource sides of this demo use
  [aauth-go](https://github.com/aauth-dev/aauth-go), the AAuth reference
  implementation, so ZeroID is checked against independent code, not its own.

## From workload identity to the AAuth ecosystem

Your workloads already have strong identities: an IAM role on AWS, a service
account in Kubernetes, a SPIFFE ID in a service mesh. AAuth needs something
different: an **Agent Provider** that vouches for each agent, so any AAuth
resource can trust it. ZeroID connects the two.

```text
  Where your code runs          Who vouches for the agent      Where the agent can go
  ────────────────────          ─────────────────────────      ──────────────────────

  AWS IAM role (STS)       ──┐                              ┌──▶  AAuth resources
                             │                              │
  Kubernetes service       ──┼──▶   ZeroID                ──┤
  account                    │      (AAuth Agent Provider)  │
                             │                              └──▶  OAuth and MCP servers,
  SPIFFE / WIMSE (coming)  ──┘                                    through ZeroID's bridge
```

- **No new root of trust.** You don't hand out credentials to agents. ZeroID
  trusts what your cloud or cluster already asserts, and you decide which
  roles or service accounts count as which agent.
- **Resources trust one issuer, not every cloud.** An AAuth resource never has
  to understand AWS STS tokens, Kubernetes tokens or SPIFFE. It checks one
  thing: an agent token signed by ZeroID. Adding a new platform or a new
  resource doesn't change anything on the other side.
- **The platform says where the code runs; ZeroID decides what it may do.**
  A platform token proves where code is running. ZeroID maps it to a named
  agent, applies that agent's policy (which credentials, for which resources,
  for how long), records every credential it issues, and revokes them all at
  once when needed.
- **SPIFFE and WIMSE are built in.** Every agent ZeroID vouches for also has a
  SPIFFE ID (a WIMSE workload URI). It's the `sub` of the bridged token in the
  demo's step 5, so the same agent fits zero-trust and service-mesh tooling
  that speaks SPIFFE.
- **AAuth today, OAuth and MCP too.** AAuth is new, and most APIs and MCP
  servers speak OAuth. The bridge lets an agent use one identity everywhere
  while the ecosystem catches up.

| Platform | Token the agent starts with | Status |
| --- | --- | --- |
| AWS | STS web identity token for the agent's IAM role | Works; tested with real AWS tokens |
| Kubernetes (EKS, GKE, AKS, self-managed) | Projected service account token | Works; this demo uses a mock cluster |
| SPIFFE / SPIRE | JWT-SVID | Coming |
| Google Cloud, Azure | Workload identity token | Coming |

## How it works

```text
  ┌───────────────┐  1. platform identity token   ┌──────────────┐
  │  Kubernetes   │ ────────────────────────────▶ │              │
  │  or AWS       │                               │    Agent     │  holds one private key,
  └───────────────┘                               │  (workload)  │  and nothing else
                                                  └──────┬───────┘
                       2. "here's my platform token,     │
                           signed with my key"           ▼
                                                  ┌──────────────┐
                       3. AAuth agent token,      │    ZeroID    │
                          bound to that key  ◀─── │ (Agent       │
                                                  │  Provider)   │
                                                  └──────┬───────┘
                                                         │
             ┌───────────────────────────────────────────┴───────────────┐
             ▼                                                           ▼
  4. AAuth resource                                  5. OAuth-only MCP server
     verifies the agent token against                   gets a DPoP-bound OAuth token
     ZeroID's published keys                            from ZeroID's bridge
```

1. The platform hands the agent a short-lived identity token: a Kubernetes
   service account token, or an AWS STS web identity token.
2. The agent generates a key pair, then sends that token to ZeroID in a request
   signed with the key.
3. ZeroID checks the token against the issuer and binding an administrator set
   up, then returns an AAuth agent token tied to the agent's key.
4. The agent calls an AAuth resource, signing each request with its key. The
   resource checks the agent token against ZeroID's public keys.
5. For a resource that only understands OAuth, the agent swaps its agent token
   for an OAuth access token scoped to that one resource, and proves it holds
   the key on every call.

## Try it in three minutes

You need [Docker](https://docs.docker.com/get-docker/) (Docker Desktop is
fine). Nothing else is installed, and nothing leaves your machine.

```bash
git clone https://github.com/highflame-ai/zeroid.git
cd zeroid/examples/aauth
docker compose up --build --abort-on-container-exit --exit-code-from demo-agent demo-agent
```

The first run builds ZeroID and the demo, which takes a couple of minutes.
Then the agent tells you what it's doing at each step:

```text
[1] Platform identity token (no secret anywhere)
    iss http://mockidp:8080/k8s
    sub system:serviceaccount:agents:planner
    aud [https://auth.zeroid.test]
```

The agent starts with a Kubernetes service account token. That's its only
credential. A small mock stands in for the cluster here, so you can run the
demo on a laptop.

```text
[2] Agent key, one per pod
    Ed25519 key at /pod/agent.key
```

The agent creates its own key. The private half never leaves the pod.

```text
[3] Enroll at ZeroID's Agent Provider (aauth-go client, hwk-signed)
    agent aauth:dbea2cd6-b084-4d63-a52b-762bd3b93314@auth.zeroid.test
    iss   https://auth.zeroid.test
    cnf   bound to this pod's key
    exp   in 900s
```

ZeroID accepts the platform token and issues an AAuth agent identity. The
token lasts 15 minutes and works only together with the agent's key.

```text
[4] Call an AAuth resource (aauth-go signs; the resource verifies via ZeroID's JWKS)
    200 map[agent:aauth:dbea2cd6-…@auth.zeroid.test agent_issuer:https://auth.zeroid.test agent_jkt:xOmGL_… token_type:aa-agent+jwt]
```

An AAuth resource recognizes the agent. It verified the signature and the
agent token itself, with no call back to ZeroID beyond fetching its public
keys.

```text
[5] Bridge to OAuth for an MCP server (DPoP-bound, one resource)
    sub spiffe://zeroid.test/acme/prod/agent/planner
    aauth_agent aauth:dbea2cd6-b084-4d63-a52b-762bd3b93314@auth.zeroid.test
    aud [https://resource.zeroid.test]

[6] Call the MCP tool
    map[content:[map[text:ran search for spiffe://zeroid.test/acme/prod/agent/planner type:text]]]

Done: no secret was stored, shipped or exchanged.
```

For an MCP server that only accepts OAuth, the agent gets an access token
limited to that one server and bound to its key, then calls a tool. The token
carries both the agent's ZeroID identity and its AAuth identity, so the call
can be audited back to the workload that made it.

## Try it with your own AWS identity

The same flow works with a real AWS identity in place of the mock cluster.
You'll need the [AWS CLI](https://aws.amazon.com/cli/) v2.32 or later, `jq`,
and an AWS account you can sign in to.

### 1. Let your account issue identity tokens

AWS can mint signed identity tokens for your IAM roles, for use with services
outside AWS. Turn it on once per account (this needs an administrator):

```bash
aws sso login                                       # or however you sign in
aws iam enable-outbound-web-identity-federation
```

The role you sign in with also needs permission for `sts:GetWebIdentityToken`.

### 2. See who AWS says you are

Mint a token and read its issuer (`iss`) and subject (`sub`):

```bash
aws sts get-web-identity-token --audience https://auth.zeroid.test --signing-algorithm RS256 \
  --output json | jq -r .WebIdentityToken | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{iss, sub}'
```

`iss` is your account's token issuer, and `sub` is the ARN of the IAM role
you're signed in as. In production, give each agent its own role, since every
caller using a role gets the same agent identity.

### 3. Tell ZeroID to trust that role

Start ZeroID and the demo resource, then register your account as a trusted
issuer and bind your role to the demo agent:

```bash
cd examples/aauth
export AWS_ISSUER='https://<id>.tokens.sts.global.api.aws'    # iss from step 2
export AWS_ROLE_ARN='arn:aws:iam::<account>:role/<role>'      # sub from step 2

docker compose up -d --build postgres keygen zeroid caddy demo-resource
docker compose run --rm -e CLUSTER_ISSUER="$AWS_ISSUER" -e SA_SUBJECT="$AWS_ROLE_ARN" demo-setup
```

### 4. Run the agent

AWS tokens are valid for five minutes, so mint one right before you run:

```bash
aws sts get-web-identity-token --audience https://auth.zeroid.test --signing-algorithm RS256 \
  --output json | jq -r .WebIdentityToken > aws-token

docker compose run --rm --no-deps -e PLATFORM=k8s -e TOKEN_FILE=/aws/token \
  -v "$PWD/aws-token:/aws/token:ro" demo-agent
```

Step `[1]` now shows your AWS account and role, and the agent runs through to
`Done` as before.

### 5. Try to steal the token

Now act as an attacker who copied that AWS token and presents it with a
different key:

```bash
docker compose run --rm --no-deps -e PLATFORM=k8s -e TOKEN_FILE=/aws/token -e KEY_FILE=/tmp/thief.key \
  -v "$PWD/aws-token:/aws/token:ro" demo-agent
```

ZeroID refuses:

```text
agentprovider: status 403: {"error":"invalid_grant","detail":"the attestation was already redeemed by another key"}
```

The first key to present a platform token owns it. A copy is worthless.

## Verify against the AAuth reference implementation

If you have Go 1.27 and Docker, you can run the interop test. It points
aauth-go's own client and resource code at ZeroID, all in one process:

```bash
cd examples/aauth
GOWORK=off go test ./interop -v
```

It checks, using aauth-go's own code on the other side of every exchange:

- **Enrollment:** aauth-go's client enrolls at ZeroID, and an aauth-go
  resource accepts the agent token.
- **The OAuth bridge:** the bridged token works only with the agent's key,
  and stops working when the agent is revoked.
- **Sub-agents:** aauth-go's client gets a sub-agent token, and an aauth-go
  resource accepts the sub-agent.
- **Refresh:** aauth-go's two-key refresh gets a token for a fresh key.
- **Revocation:** revoking an agent at ZeroID revokes it at aauth-go's
  person server.
- **Theft:** a stolen platform token is refused.

## The full Agent Provider

The demo uses enrollment and the OAuth bridge. ZeroID implements the rest of
the AAuth Agent Provider role too. Each feature is switched on per agent, in
the agent's credential policy.

| Feature | Endpoint | Turn it on by | What it does |
| --- | --- | --- | --- |
| Enrollment | `POST /ap/token` | listing `aauth_agent` in `allowed_grant_types` | Trades a platform token, in a request signed by the agent's key, for an agent token bound to that key |
| Refresh | `POST /ap/refresh` | also listing `aauth_refresh` | Lets an enrolled key move its identity to a fresh key without a new platform token, for up to 8 hours. Every refresh re-checks the issuer, the binding and the agent's status |
| Sub-agents | `POST /ap/subagent` | also listing `aauth_subagent` | Lets an agent get tokens for helper agents with keys of their own. They never outlive the parent, can't have sub-agents of their own, and are revoked with it |
| Person server | none | setting `aauth_person_server` | Puts the agent's person server in its tokens (the `ps` claim), and revokes the agent there whenever ZeroID revokes it |
| OAuth bridge | `POST /oauth2/token` | also listing `aauth_bridge` | Exchanges an agent token for a DPoP-bound OAuth token for one resource |

ZeroID publishes `/.well-known/aauth-agent.json` and its signing keys. It
answers every error in the AAuth format, signature failures included, and
limits each agent's requests (`aauth.requests_per_minute`, default 60).

It implements the Agent Provider requirements of the AAuth protocol
(`draft-hardt-oauth-aauth-protocol-11`) and works with aauth-go, the
reference implementation. AAuth events and deferred (`202`) responses from
the Agent Provider are not supported.

## What's running

| Service | What it does |
| --- | --- |
| `zeroid` | ZeroID, acting as the AAuth Agent Provider at `https://auth.zeroid.test` |
| `caddy` | Serves ZeroID and the resource over HTTPS, as AAuth requires |
| `keygen` | Creates ZeroID's signing keys on first start |
| `mockidp` | Stands in for a Kubernetes cluster's token issuer |
| `demo-setup` | The administrator's one-time setup: which issuer to trust, which service account (or AWS role) maps to which agent, and which credentials that agent may receive |
| `demo-resource` | Two endpoints: `/whoami`, an AAuth resource, and `/mcp`, an OAuth-only MCP-style tool |
| `demo-agent` | The workload: no secrets, one key |

## Taking it further

This demo trades some safety for convenience, so it runs anywhere with no
setup. A production deployment would:

- keep ZeroID's admin API private (here it's reachable for the setup step);
- verify an issuer is genuine before trusting it (here it's trusted directly);
- turn off the demo's `ZEROID_FEDERATION_ALLOW_PRIVATE_ENDPOINTS` and
  `ZEROID_ALLOW_UNAUTHENTICATED_TOKEN_INSPECTION` settings.

On a real Kubernetes cluster, project a service account token into the pod
with its `audience` set to your ZeroID URL and `expirationSeconds: 600`. Point
the agent at it with `PLATFORM=k8s` and `TOKEN_FILE`. Keep the agent's key
(`KEY_FILE`) on a volume shared by the pod's containers, so the pod keeps one
identity for its whole life.
