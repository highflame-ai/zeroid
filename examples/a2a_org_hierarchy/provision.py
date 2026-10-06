"""
provision.py — one-shot bootstrapper for the 32-agent cascade-revocation demo.

On each `docker compose up`:
  • If /shared/manifest.json already exists, skip provisioning and print the
    revocation command (fast path for restarts without `docker compose down -v`).
  • Otherwise register all 32 agents (idempotent: existing identities get their
    public key updated and a fresh API key issued), build the mission tree, and
    write the manifest. Each agent's scope ceiling is a credential policy
    (one per distinct scope set, reused across runs).
"""

import hashlib
import json
import os
import sys
import time
import urllib.request

import jwt
import yaml
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from highflame.zeroid import ZeroIDClient
from highflame.zeroid.errors import ConflictError

ZEROID_BASE_URL = os.getenv("ZEROID_BASE_URL", "http://zeroid:8899")
MANIFEST_PATH   = os.getenv("MANIFEST_PATH", "/shared/manifest.json")
HIERARCHY_PATH  = os.getenv("HIERARCHY_PATH", "/app/hierarchy.yaml")

# account_id / project_id default to "default" when omitted
client = ZeroIDClient(base_url=ZEROID_BASE_URL)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _wait_for_zeroid(timeout: int = 60):
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{ZEROID_BASE_URL}/health", timeout=3)
            return
        except Exception:
            time.sleep(2)
    print("ERROR: ZeroID did not become healthy in time", file=sys.stderr)
    sys.exit(1)


def _get_issuer() -> str:
    import urllib.request, json as _json
    with urllib.request.urlopen(
        f"{ZEROID_BASE_URL}/.well-known/oauth-authorization-server"
    ) as r:
        return _json.loads(r.read())["issuer"]


def _generate_keypair():
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def _build_actor_token(wimse_uri: str, private_key_pem: bytes, aud: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": wimse_uri, "sub": wimse_uri, "aud": aud, "iat": now, "exp": now + 300},
        private_key_pem,
        algorithm="ES256",
    )


def _fetch_all_identities() -> dict[str, tuple[str, str]]:
    """Return {external_id: (id, wimse_uri)} for ALL identities.

    identities.list() returns a single page (limit 20 by default) ordered by
    created_at DESC, so the first-registered identities fall off the end.
    iter_all() walks every page at the service ceiling of 100.
    """
    return {
        i.external_id: (i.id, i.wimse_uri or "")
        for i in client.identities.iter_all()
    }


def _admin_request(method: str, path: str, body: dict) -> dict:
    """Call the ZeroID admin REST API directly.

    Used where the published SDK has no parameter for the field we need:
    identities.create() / identities.update() do not accept
    credential_policy_id. Sends the same tenant headers as the SDK client
    (account_id / project_id default to "default").
    """
    req = urllib.request.Request(
        f"{ZEROID_BASE_URL}{path}",
        data=json.dumps(body).encode(),
        method=method,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Account-ID": "default",
            "X-Project-ID": "default",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"{}")


_policy_ids: dict[tuple, str] = {}


def _policy_for_scopes(scopes: list) -> str:
    """Return the id of a credential policy whose allowed_scopes is *scopes*.

    The credential policy is the identity's scope ceiling (the identity row
    carries no allowed_scopes). One policy per distinct scope set, named by a
    hash of the set so re-runs reuse it: a 409 on create means it already
    exists, so look it up by name.
    """
    key = tuple(sorted(scopes))
    if key in _policy_ids:
        return _policy_ids[key]
    name = "cascade-demo-" + hashlib.sha256(" ".join(key).encode()).hexdigest()[:12]
    try:
        policy = client.credential_policies.create(
            name=name,
            description="cascade-demo scope ceiling: " + " ".join(key),
            allowed_scopes=list(key),
            # Tier 1 roots use api_key; tiers 2-3 are delegated via token_exchange.
            allowed_grant_types=["api_key", "token_exchange"],
            # The tree is depth 2; 0 would refuse every delegation.
            max_delegation_depth=2,
        )
    except ConflictError:
        policy = next(p for p in client.credential_policies.list() if p.name == name)
    _policy_ids[key] = policy.id
    return policy.id


def load_hierarchy():
    with open(HIERARCHY_PATH) as f:
        data = yaml.safe_load(f)
    all_scopes = data["all_scopes"]
    agents = data["agents"]
    for ag in agents:
        if ag["scopes"] == "all":
            ag["scopes"] = all_scopes
    return agents, all_scopes


# ── Phase 1: Register ─────────────────────────────────────────────────────────

def register_agents(agents: list, all_scopes: list) -> dict:
    print(f"\n=== Registering {len(agents)} agents ===")
    existing = _fetch_all_identities()
    print(f"  Found {len(existing)} existing identities in ZeroID.")
    registry = {}

    for ag in agents:
        priv, pub = _generate_keypair()
        name = ag["name"]
        existing_id, existing_wimse = existing.get(ag["external_id"], (None, None))
        # The agent's scope ceiling lives on its credential policy.
        policy_id = _policy_for_scopes(ag["scopes"])

        if ag["tier"] == 1:
            if existing_id:
                # Re-link the policy before minting the key, so the key is
                # issued under the current ceiling.
                _admin_request("PATCH", f"/identities/{existing_id}", {
                    "credential_policy_id": policy_id,
                    "public_key_pem":       pub,
                })
                new_key = client.api_keys.create(
                    name=f"{ag['external_id']}-demo",
                    identity_id=existing_id,
                    scopes=ag["scopes"],
                )
                api_key     = new_key.key
                identity_id = existing_id
                wimse_uri   = existing_wimse
                print(f"  [Tier 1] {name:30s} → existing, new api key issued")
            else:
                reg = client.agents.register(
                    name=ag["display_name"],
                    external_id=ag["external_id"],
                    sub_type=ag["sub_type"],
                    trust_level="first_party",
                    created_by="provision@demo.local",
                    public_key_pem=pub,
                    credential_policy_id=policy_id,
                )
                api_key     = reg.api_key
                identity_id = reg.identity.id
                wimse_uri   = reg.identity.wimse_uri
                print(f"  [Tier 1] {name:30s} → {wimse_uri}")

            registry[name] = {
                "identity_id":     identity_id,
                "wimse_uri":       wimse_uri,
                "api_key":         api_key,
                "private_key_pem": priv.decode(),
                "tier":            ag["tier"],
                "scopes":          ag["scopes"],
                "parent":          ag["parent"],
            }

        else:
            if existing_id:
                _admin_request("PATCH", f"/identities/{existing_id}", {
                    "credential_policy_id": policy_id,
                    "public_key_pem":       pub,
                })
                identity_id = existing_id
                wimse_uri   = existing_wimse
                indent = "    " if ag["tier"] == 3 else "  "
                print(f"{indent}[Tier {ag['tier']}] {name:28s} → existing, pubkey updated")
            else:
                # REST rather than client.identities.create(): the SDK's
                # create() has no credential_policy_id, and setting it in the
                # same call means the identity never exists without its ceiling.
                identity = _admin_request("POST", "/identities", {
                    "external_id":          ag["external_id"],
                    "name":                 ag["display_name"],
                    "owner_user_id":        "provision@demo.local",
                    "identity_type":        "agent",
                    "sub_type":             ag["sub_type"],
                    "trust_level":          "first_party",
                    "credential_policy_id": policy_id,
                    "public_key_pem":       pub,
                })
                identity_id = identity["id"]
                wimse_uri   = identity.get("wimse_uri", "")
                indent = "    " if ag["tier"] == 3 else "  "
                print(f"{indent}[Tier {ag['tier']}] {name:28s} → {wimse_uri}")

            registry[name] = {
                "identity_id":     identity_id,
                "wimse_uri":       wimse_uri,
                "api_key":         None,
                "private_key_pem": priv.decode(),
                "tier":            ag["tier"],
                "scopes":          ag["scopes"],
                "parent":          ag["parent"],
            }

    print(f"\n  {len(registry)} agents registered.")
    return registry


# ── Phase 2: Mission tree ─────────────────────────────────────────────────────

def build_delegation_chains(registry: dict, issuer: str) -> dict:
    print("\n=== Building mission tree ===")
    tokens = {}

    for name, entry in registry.items():
        if entry["tier"] == 1:
            tok = client.tokens.issue_api_key(
                entry["api_key"],
                scope=" ".join(entry["scopes"]),
            )
            tokens[name] = tok.access_token
            print(f"  [depth=0] {name}")

    for name, entry in registry.items():
        if entry["tier"] == 2:
            actor = _build_actor_token(
                entry["wimse_uri"], entry["private_key_pem"].encode(), issuer
            )
            tok = client.tokens.issue_token_exchange(
                subject_token=tokens[entry["parent"]],
                actor_token=actor,
                scope=" ".join(entry["scopes"]),
            )
            tokens[name] = tok.access_token
            print(f"  [depth=1] {name}")

    for name, entry in registry.items():
        if entry["tier"] == 3:
            actor = _build_actor_token(
                entry["wimse_uri"], entry["private_key_pem"].encode(), issuer
            )
            tok = client.tokens.issue_token_exchange(
                subject_token=tokens[entry["parent"]],
                actor_token=actor,
                scope=" ".join(entry["scopes"]),
            )
            tokens[name] = tok.access_token
            print(f"    [depth=2] {name}")

    print(f"\n  {len(tokens)} tokens issued.")
    return tokens


# ── Phase 3: Write manifest ───────────────────────────────────────────────────

def write_manifest(registry: dict, tokens: dict):
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)
    manifest = {
        name: {
            "identity_id":     entry["identity_id"],
            "wimse_uri":       entry["wimse_uri"],
            "private_key_pem": entry["private_key_pem"],
            "token":           tokens[name],
            "tier":            entry["tier"],
            "scopes":          entry["scopes"],
            "parent":          entry["parent"],
        }
        for name, entry in registry.items()
    }
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n  Manifest written to {MANIFEST_PATH}")


def _print_signal_command(manifest_path: str):
    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
        spec_legal_id = manifest.get("spec-legal", {}).get("identity_id", "<spec-legal-id>")
    except Exception:
        spec_legal_id = "<spec-legal-id>"

    print("\n" + "=" * 50)
    print("PROVISIONING COMPLETE")
    print()
    print("Cascade revocation command:")
    print()
    print(f"  zid signal \\")
    print(f"    --profile cascade-demo \\")
    print(f"    --agent {spec_legal_id} \\")
    print(f"    --type anomalous_behavior \\")
    print(f"    --severity high \\")
    print(f"    --source security-monitor \\")
    print(f"    --reason 'compromised agent detected'")
    print()
    print("Grafana dashboard: http://localhost:3100")
    print("  spec-legal + its 3 tool agents flip red within seconds.")
    print("  The other 28 agents stay green.")
    print("=" * 50)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("ZeroID Cascade Revocation Demo — Provisioner")
    print("=" * 50)

    if os.path.exists(MANIFEST_PATH):
        print(f"\nManifest already exists — skipping provisioning.")
        print("(Run 'docker compose down -v && docker compose up' to fully reset.)")
        _print_signal_command(MANIFEST_PATH)
        return

    _wait_for_zeroid()
    agents, all_scopes = load_hierarchy()
    issuer   = _get_issuer()
    registry = register_agents(agents, all_scopes)
    tokens   = build_delegation_chains(registry, issuer)
    write_manifest(registry, tokens)
    _print_signal_command(MANIFEST_PATH)


if __name__ == "__main__":
    main()
