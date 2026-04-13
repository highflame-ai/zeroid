#!/usr/bin/env python3
"""
Demo: instant agent revocation via ZeroID CAE signal.

Reads the live token from the agent's auth-profiles.json (written by the
sidecar), shows the delegation chain, then ingests a critical CAE
session_revoked signal.  ZeroID auto-revokes all active credentials for the
identity on high/critical signals, so the next proxy request fails immediately.

Usage:
    python scripts/demo-revoke.py --config identity-map.json --agent <agent-id>
    python scripts/demo-revoke.py --config identity-map.json --agent <agent-id> --deactivate
"""

import argparse
import json
import sys
from pathlib import Path


def read_live_token(agents_root: Path, agent_id: str) -> str:
    """Read the JWT the sidecar injected into the agent's auth-profiles.json."""
    profiles_path = agents_root / agent_id / "agent" / "auth-profiles.json"
    if not profiles_path.exists():
        sys.exit(f"auth-profiles.json not found at {profiles_path} — is the agent running?")
    store = json.loads(profiles_path.read_text())
    for profile in store.get("profiles", {}).values():
        if isinstance(profile, dict) and profile.get("key"):
            return profile["key"]
    sys.exit(f"no token found in {profiles_path} — run the sidecar first")


def fetch_issuer(zeroid_url: str) -> str:
    import urllib.request
    url = zeroid_url.rstrip("/") + "/.well-known/oauth-authorization-server"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())["issuer"]


def resolve_state_dir(cfg: dict) -> Path:
    import os
    override = os.environ.get("OPENCLAW_STATE_DIR", "").strip()
    return Path(override).expanduser() if override else Path("~/.openclaw").expanduser()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--agent", required=True, help="Agent ID (subdirectory under agents/)")
    parser.add_argument("--reason", default="demo revocation")
    parser.add_argument("--deactivate", action="store_true",
                        help="Deactivate the identity entirely instead of revoking just this token")
    args = parser.parse_args()

    cfg = json.loads(args.config.expanduser().read_text())

    try:
        from highflame.zeroid import ZeroIDClient
    except ImportError:
        sys.exit("requires highflame SDK: pip install highflame")

    zeroid_url = cfg.get("zeroid_url", "").strip()
    if not zeroid_url:
        sys.exit("identity-map.json must have 'zeroid_url'")

    key_store_path = Path(cfg.get("agent_key_store", "~/.openclaw/sidecar-agent-keys.json")).expanduser()
    if not key_store_path.exists():
        sys.exit(f"key store not found: {key_store_path} — run the sidecar first")
    store = json.loads(key_store_path.read_text())
    orch_key = store.get("__orchestrator_api_key__", "").strip()
    if not orch_key:
        sys.exit("no orchestrator API key in key store — run the sidecar first")

    agent_id = args.agent
    agents_root = resolve_state_dir(cfg) / "agents"

    # Read the token the sidecar already injected — this is the live token.
    live_token = read_live_token(agents_root, agent_id)
    print(f"Found live token in auth-profiles.json for agent '{agent_id}'")

    client = ZeroIDClient(
        base_url=zeroid_url,
        api_key=orch_key,
        account_id=cfg.get("admin_account_id") or None,
        project_id=cfg.get("admin_project_id") or None,
    )
    print(client.identities.list())
    # Show the delegation chain from the live token.
    print("\n-- Delegation chain --")
    orch_token = client.tokens.issue_api_key(orch_key)
    orch = client.tokens.introspect(orch_token.access_token)
    print(f"  orchestrator  sub={orch.sub!r}  scope={orch.scope!r}")
    agent_tok = client.tokens.introspect(live_token)
    act_sub = (agent_tok.act or {}).get("sub", "")
    print(f"  agent         sub={agent_tok.sub!r}  act.sub={act_sub!r}  scope={agent_tok.scope!r}")

    print("\n-- Before revocation --")
    print(f"  active={agent_tok.active}")

    # sub is the WIMSE URI, not a UUID — resolve the identity UUID from the registry.
    agent_cfg = cfg.get("agents", {}).get(agent_id) or cfg.get("agents", {}).get("*") or {}
    external_id = (agent_cfg.get("external_id") if isinstance(agent_cfg, dict) else None) or agent_id
    identities = client.identities.list()
    identity = next((i for i in identities if i.external_id == external_id), None)
    if identity is None:
        sys.exit(f"identity not found for external_id={external_id!r} — has the sidecar registered it?")
    identity_id = identity.id
    print(f"\nIngesting CAE session_revoked signal for identity {identity_id!r} (external_id={external_id!r})...")
    signal = client.signals.ingest(
        signal_type="session_revoked",
        severity="critical",
        source="demo-revoke",
        identity_id=identity_id,
        payload={"reason": args.reason, "agent_id": agent_id},
    )
    print(f"  signal_id={signal.id!r}  type={signal.signal_type!r}  severity={signal.severity!r}")

    print("\n-- After CAE signal --")
    after = client.tokens.introspect(live_token)
    print(f"  active={after.active}")

    if not after.active:
        print("\nInstant revocation confirmed via CAE signal.")
    else:
        print("\nToken still active — ZeroID may need a moment to propagate.")


if __name__ == "__main__":
    main()
