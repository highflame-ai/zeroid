#!/usr/bin/env python3
"""
Agent identity sidecar for OpenClaw.

On each poll cycle:

1. openclaw.json (shared):
   - Sets baseUrl to the proxy for every provider in models.providers
   - Upserts agents.list[] entries with per-agent tool policy derived from
     JWT scope claims — enforced mid-session since tools-invoke-http calls
     loadConfig() fresh on every tool invocation

2. auth-profiles.json (per agent):
   Overwrites every existing credential with an api_key carrying the identity
   key so the proxy receives it as the bearer token for identity verification.

With both in place every provider request carries:
  Authorization: Bearer <identity-key>   (from auth-profiles.json)

The proxy (NGINX auth_request → ZeroID /oauth2/token/verify) verifies the
identity key, strips both headers, re-injects the real Authorization header,
and forwards to the upstream provider.

Usage:
    python scripts/agent-identity-sidecar.py --config identity-map.json

identity-map.json format:
    {
      "proxy_base_url": "https://your-proxy.example.com/v1",
      "provider_key_env_vars": {
        "xai": "XAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "*": "PROVIDER_API_KEY"
      },
      "scope_tool_map": {
        "read":  { "allow": ["read"] },
        "write": { "allow": ["write"] },
        "exec":  { "allow": ["exec"] }
      },
      "agents": {
        "agent-a": "<jwt-identity-key>",
        "agent-b": "<jwt-identity-key>",
        "*": "<fallback-jwt>"
      }
    }

scope_tool_map is optional. If omitted or no matching scope is found,
no tools entry is written for that agent.

"*" in agents is optional fallback for any unlisted agent.
"""

import argparse
import base64
import json
import logging
import os
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("agent-identity-sidecar")

# Module-level caches — survive across poll cycles within the same process.
_token_cache: dict[str, tuple[str, float]] = {}  # agent_id → (jwt, expires_at)
_wimse_cache: dict[str, str] = {}                # "<acct>/<proj>/<external_id>" → wimse_uri
_issuer_cache: dict[str, str] = {}               # zeroid_url → issuer

AUTH_STORE_VERSION = 1   # src/agents/auth-profiles/constants.ts
LOCK_STALE_SECS = 30     # src/agents/auth-profiles/constants.ts AUTH_STORE_LOCK_OPTIONS.stale
LOCK_RETRY_ATTEMPTS = 10
LOCK_RETRY_DELAY_SECS = 0.2
SIDECAR_PROFILE_SUFFIX = "sidecar-identity"


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def resolve_state_dir(state_dir_override: str | None = None) -> Path:
    if state_dir_override:
        return Path(state_dir_override).expanduser()
    env_state = os.environ.get("OPENCLAW_STATE_DIR", "").strip()
    if env_state:
        return Path(env_state).expanduser()
    return Path("~/.openclaw").expanduser()


def resolve_openclaw_config_path(state_dir: Path) -> Path:
    env_override = os.environ.get("OPENCLAW_CONFIG_PATH", "").strip()
    if env_override:
        return Path(env_override).expanduser()
    return state_dir / "openclaw.json"


def resolve_agents_root(state_dir: Path) -> Path:
    return state_dir / "agents"


# ---------------------------------------------------------------------------
# JWT scope decoding
# ---------------------------------------------------------------------------

def decode_jwt_payload(token: str) -> dict:
    """
    Decode JWT payload without verification — NGINX/ZeroID already verified it.
    Returns empty dict on any parse error.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def resolve_tool_config(payload: dict, scope_tool_map: dict) -> dict | None:
    """
    Map JWT scope claims to an AgentToolsConfig dict.
    Handles both ZeroID JWTs ("scopes": [...] array) and static JWTs ("scope": "..." string).
    Returns the first matching scope_tool_map entry as-is, supporting any combination of
    "profile", "allow", and "deny" keys that openclaw accepts in agents.list[].tools.
    Returns None if no scopes match.
    """
    if not scope_tool_map:
        return None
    raw = payload.get("scopes")
    if isinstance(raw, list):
        scopes = [s for s in raw if isinstance(s, str)]
    else:
        scopes = str(payload.get("scope", "")).split()
    for scope in scopes:
        entry = scope_tool_map.get(scope)
        if entry and isinstance(entry, dict):
            return dict(entry)
    return None


# ---------------------------------------------------------------------------
# openclaw.json patching
# ---------------------------------------------------------------------------

def resolve_provider_env_var(provider_id: str, provider_key_env_vars: dict) -> str | None:
    return provider_key_env_vars.get(provider_id) or provider_key_env_vars.get("*") or None


def resolve_provider_proxy_url(provider_id: str, proxy_base_url) -> str:
    """Resolve the proxy base URL for a provider.

    proxy_base_url may be a plain string (used for all providers) or a dict
    mapping provider IDs to URLs, with an optional "*" fallback.  A "{provider}"
    placeholder in the template is replaced with the provider ID.
    """
    if isinstance(proxy_base_url, dict):
        tpl = proxy_base_url.get(provider_id) or proxy_base_url.get("*", "")
        return tpl.replace("{provider}", provider_id)
    return proxy_base_url  # backward-compatible string


def upsert_agent_tools(agent_list: list, agent_id: str, tools_cfg: dict) -> bool:
    """
    Upsert agents.list[] entry for agent_id with the given tools config.
    Returns True if anything changed.
    """
    for entry in agent_list:
        if isinstance(entry, dict) and entry.get("id") == agent_id:
            if entry.get("tools") == tools_cfg:
                return False
            entry["tools"] = tools_cfg
            log.info("openclaw.json: updated tools policy for agent %s", agent_id)
            return True
    agent_list.append({"id": agent_id, "tools": tools_cfg})
    log.info("openclaw.json: added tools policy for agent %s", agent_id)
    return True


def patch_openclaw_config(
    config_path: Path,
    proxy_base_url,  # str | dict — see resolve_provider_proxy_url
    provider_key_env_vars: dict,
    agent_tool_updates: dict[str, dict],
) -> bool:
    """
    Patch openclaw.json in one atomic write:
      - Set baseUrl + real-key header for every provider in models.providers
      - Upsert agents.list[] tool policies for agents with resolved scopes

    Uses atomic rename; no lock needed (openclaw.json is lock-free in core).
    """
    if not config_path.exists():
        log.debug("openclaw.json not found at %s — skipping", config_path)
        return False

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.warning("could not read openclaw.json: %s — skipping", e)
        return False

    changed = False

    # --- provider patches ---
    providers: dict = (config.get("models") or {}).get("providers") or {}
    for provider_id, provider_cfg in providers.items():
        if not isinstance(provider_cfg, dict):
            continue
        provider_proxy_url = resolve_provider_proxy_url(provider_id, proxy_base_url)
        if provider_cfg.get("baseUrl") != provider_proxy_url and provider_proxy_url:
            provider_cfg["baseUrl"] = provider_proxy_url
            changed = True
            log.info("openclaw.json: set baseUrl for provider %s → %s", provider_id, provider_proxy_url)

        # --- per-agent tool policy patches ---
    # --- per-agent tool policy patches ---
    if agent_tool_updates:
        agents_cfg = config.setdefault("agents", {})
        agent_list: list = agents_cfg.setdefault("list", [])
        for agent_id, tools_cfg in agent_tool_updates.items():
            if upsert_agent_tools(agent_list, agent_id, tools_cfg):
                changed = True

    if not changed:
        return False

    tmp_path = config_path.with_name(f"{config_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        tmp_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        tmp_path.replace(config_path)
    except OSError as e:
        log.error("could not write openclaw.json: %s", e)
        tmp_path.unlink(missing_ok=True)
        return False

    log.info("openclaw.json patched")
    return True


# ---------------------------------------------------------------------------
# auth-profiles.json locking + injection
# ---------------------------------------------------------------------------

def acquire_lock(lock_path: Path) -> bool:
    """Acquire the .lock sidecar file used by OpenClaw's file-lock.ts."""
    for attempt in range(LOCK_RETRY_ATTEMPTS):
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            payload = json.dumps(
                {"pid": os.getpid(), "createdAt": datetime.now(timezone.utc).isoformat()},
                indent=2,
            )
            os.write(fd, payload.encode())
            os.close(fd)
            return True
        except FileExistsError:
            try:
                stat = lock_path.stat()
                if time.time() - stat.st_mtime > LOCK_STALE_SECS:
                    log.debug("removing stale lock %s", lock_path)
                    lock_path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if attempt < LOCK_RETRY_ATTEMPTS - 1:
                time.sleep(LOCK_RETRY_DELAY_SECS)
    return False


def release_lock(lock_path: Path) -> None:
    lock_path.unlink(missing_ok=True)


def load_auth_profiles(path: Path) -> dict:
    if not path.exists():
        return {"version": AUTH_STORE_VERSION, "profiles": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.warning("could not read %s: %s — skipping", path, e)
        return {"version": AUTH_STORE_VERSION, "profiles": {}}


def collect_provider_profiles(store: dict) -> dict[str, list[str]]:
    """
    Return provider -> [profile_id, ...] for all existing profiles,
    excluding sidecar-injected ones so we don't re-process our own writes.
    """
    result: dict[str, list[str]] = {}
    for profile_id, cred in store.get("profiles", {}).items():
        if not isinstance(cred, dict):
            continue
        if profile_id.endswith(f":{SIDECAR_PROFILE_SUFFIX}"):
            continue
        provider = cred.get("provider", "").strip()
        if provider:
            result.setdefault(provider, []).append(profile_id)
    return result


def inject_identities_for_agent(
    auth_profiles_path: Path,
    agent_id: str,
    identity_key: str,
    providers: list[str] | None = None,
) -> bool:
    """
    Overwrite every existing profile with an api_key credential carrying the
    identity key. When no profiles exist yet, creates one per provider from
    the supplied providers list. Acquires the .lock sidecar before writing.
    Returns True if changed.
    """
    lock_path = Path(str(auth_profiles_path) + ".lock")
    if not acquire_lock(lock_path):
        log.warning("could not acquire lock for %s — skipping", auth_profiles_path)
        return False

    try:
        store = load_auth_profiles(auth_profiles_path)
        if not isinstance(store.get("profiles"), dict):
            store["profiles"] = {}

        provider_profiles = collect_provider_profiles(store)

        if not provider_profiles:
            if not providers:
                log.debug("agent %s: no profiles in store yet", agent_id)
                return False
            # No existing profiles — seed one per known provider.
            # Use a plain ID (no sidecar suffix) so collect_provider_profiles
            # picks them up on subsequent cycles instead of re-seeding forever.
            for provider in providers:
                pid = f"{provider}:primary"
                store["profiles"][pid] = {"type": "api_key", "provider": provider, "key": identity_key}
                log.info("agent %s: seeded profile %s", agent_id, pid)
            store["version"] = AUTH_STORE_VERSION
            tmp_path = auth_profiles_path.with_suffix(".json.tmp")
            tmp_path.write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")
            tmp_path.replace(auth_profiles_path)
            return True

        changed = False
        for provider, profile_ids in sorted(provider_profiles.items()):
            for pid in profile_ids:
                existing = store["profiles"][pid]
                desired = {"type": "api_key", "provider": provider, "key": identity_key}
                if existing != desired:
                    store["profiles"][pid] = desired
                    changed = True
                    log.info(
                        "agent %s: overwrote profile %s (was type=%s)",
                        agent_id, pid, existing.get("type", "?"),
                    )

        if not changed:
            return False

        store["version"] = AUTH_STORE_VERSION
        tmp_path = auth_profiles_path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")
        tmp_path.replace(auth_profiles_path)
        return True
    finally:
        release_lock(lock_path)


# ---------------------------------------------------------------------------
# EC key store (dynamic mode)
# ---------------------------------------------------------------------------

_ORCH_KEY_FIELD = "__orchestrator_api_key__"
_ORCH_EXTERNAL_ID = "openclaw-sidecar-orchestrator"


class AgentKeyStore:
    """Persist EC P-256 key pairs and the orchestrator API key across poll cycles."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._store: dict = {}
        self._dirty = False
        if path.exists():
            try:
                self._store = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                log.warning("could not read key store %s: %s", path, e)

    def get_orchestrator_key(self) -> str | None:
        val = self._store.get(_ORCH_KEY_FIELD)
        return val if isinstance(val, str) else None

    def set_orchestrator_key(self, key: str) -> None:
        self._store[_ORCH_KEY_FIELD] = key
        self._dirty = True

    def clear_orchestrator_key(self) -> None:
        if _ORCH_KEY_FIELD in self._store:
            del self._store[_ORCH_KEY_FIELD]
            self._dirty = True

    def get_or_create(self, agent_id: str) -> tuple[str, str]:
        """Return (private_pem, public_pem), generating a new P-256 key if absent."""
        if agent_id in self._store:
            entry = self._store[agent_id]
            return entry["private_pem"], entry["public_pem"]

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        key = ec.generate_private_key(ec.SECP256R1())
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        self._store[agent_id] = {"private_pem": private_pem, "public_pem": public_pem}
        self._dirty = True
        log.info("generated EC key pair for agent %s", agent_id)
        return private_pem, public_pem

    def save_if_dirty(self) -> None:
        if not self._dirty:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(self._store, indent=2) + "\n", encoding="utf-8")
            tmp.replace(self._path)
            self._dirty = False
        except OSError as e:
            log.error("could not save agent key store: %s", e)
            tmp.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Actor assertion JWT (dynamic mode)
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def build_actor_assertion(private_pem: str, wimse_uri: str, issuer: str) -> str:
    """
    Build a short-lived ES256 JWT assertion for RFC 8693 token exchange.
    The assertion proves the sub-agent's identity to ZeroID.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives import hashes, serialization

    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "ES256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "iss": wimse_uri,
        "sub": wimse_uri,
        "aud": issuer,
        "iat": now,
        "exp": now + 300,
        "jti": uuid.uuid4().hex,
    }).encode())
    signing_input = f"{header}.{payload}".encode()
    der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    # Convert DER (r, s) → IEEE P1363 (r || s, 32 bytes each) for ES256.
    r, s = decode_dss_signature(der_sig)
    sig = _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"{header}.{payload}.{sig}"


# ---------------------------------------------------------------------------
# ZeroID helpers (dynamic mode)
# ---------------------------------------------------------------------------

def fetch_zeroid_issuer(zeroid_url: str) -> str:
    """Fetch and cache issuer from /.well-known/oauth-authorization-server."""
    if zeroid_url in _issuer_cache:
        return _issuer_cache[zeroid_url]
    url = zeroid_url.rstrip("/") + "/.well-known/oauth-authorization-server"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
        issuer = data.get("issuer", "").strip()
        if not issuer:
            raise ValueError("issuer field missing from well-known response")
        _issuer_cache[zeroid_url] = issuer
        return issuer
    except Exception as e:
        raise RuntimeError(f"could not fetch ZeroID issuer from {url}: {e}") from e


def ensure_sub_agent_identity(
    client,
    external_id: str,
    public_pem: str,
    allowed_scopes: list[str],
    owner_user_id: str = "",
) -> str:
    """
    Register or update the sub-agent identity in ZeroID and return its wimse_uri.
    On 409 (already exists), patches public_key_pem and allowed_scopes in place.
    Results are cached for the process lifetime.
    """
    cache_key = f"{client.account_id}/{client.project_id}/{external_id}"
    if cache_key in _wimse_cache:
        return _wimse_cache[cache_key]

    from highflame.zeroid.errors import ZeroIDError

    try:
        identity = client.identities.create(
            external_id=external_id,
            owner_user_id=owner_user_id or client.account_id,
            name=external_id,
            identity_type="agent",
            sub_type="tool_agent",
            trust_level="first_party",
            allowed_scopes=allowed_scopes,
            public_key_pem=public_pem,
        )
        wimse_uri = identity.wimse_uri
        log.info("registered sub-agent identity %s → %s", external_id, wimse_uri)
    except ZeroIDError as e:
        if "409" not in str(e) and getattr(e, "code", "") not in ("conflict", "already_exists"):
            raise
        # Already registered — find by external_id (list has no filter param) and patch.
        existing = next(
            (i for i in client.identities.list() if i.external_id == external_id),
            None,
        )
        if existing is None:
            raise RuntimeError(
                f"identity {external_id!r} returned 409 but was not found in list"
            ) from e
        updated = client.identities.update(
            existing.id,
            public_key_pem=public_pem,
            allowed_scopes=allowed_scopes,
        )
        wimse_uri = updated.wimse_uri
        log.info("updated sub-agent identity %s → %s", external_id, wimse_uri)

    _wimse_cache[cache_key] = wimse_uri
    return wimse_uri


def resolve_identity_key_dynamic(
    agent_id: str,
    agent_cfg: dict,
    orch_client,
    key_store: AgentKeyStore,
    zeroid_url: str,
    buffer_secs: int,
    owner_user_id: str = "",
    subject_token: str | None = None,
) -> str | None:
    """
    Return a valid sub-agent JWT, refreshing via RFC 8693 token exchange when
    the cached token is within buffer_secs of expiry.

    When subject_token is provided (chained delegation), it is used as the
    RFC 8693 subject — meaning revoking the parent's token cascades to this
    agent's token automatically. When omitted, the orchestrator's token is
    used as the subject via client.tokens.delegate().

    ZeroID enforces: granted scope = subject scopes ∩ agent allowed_scopes
    ∩ requested scope — so the tool policy written to openclaw.json reflects
    what was actually granted, not what was requested.
    """
    cached = _token_cache.get(agent_id)
    if cached and time.time() < cached[1]:
        return cached[0]

    external_id: str = agent_cfg.get("external_id") or agent_id
    scope: str = agent_cfg.get("scope", "")
    allowed_scopes: list[str] = (
        agent_cfg.get("allowed_scopes") or (scope.split() if scope else [])
    )

    try:
        issuer = fetch_zeroid_issuer(zeroid_url)
        private_pem, public_pem = key_store.get_or_create(agent_id)
        wimse_uri = ensure_sub_agent_identity(
            orch_client, external_id, public_pem, allowed_scopes,
            owner_user_id=owner_user_id,
        )
        actor_token = build_actor_assertion(private_pem, wimse_uri, issuer)
        if subject_token:
            # Chained delegation: parent token is the subject.
            token = orch_client.tokens.issue_token_exchange(
                subject_token=subject_token,
                actor_token=actor_token,
                scope=scope,
            )
        else:
            # Root delegation: orchestrator token is the subject.
            token = orch_client.tokens.delegate(actor_token=actor_token, scope=scope)
    except Exception as e:
        log.error("agent %s: token exchange failed: %s", agent_id, e)
        if cached:
            log.warning("agent %s: using stale cached token", agent_id)
            return cached[0]
        return None

    expires_at = time.time() + token.expires_in - buffer_secs
    _token_cache[agent_id] = (token.access_token, expires_at)
    log.info(
        "agent %s: delegated token issued (subject=%s, scope=%r, expires_in=%ds)",
        agent_id, "parent" if subject_token else "orchestrator", token.scope, token.expires_in,
    )
    return token.access_token


# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------

def resolve_identity_key(agent_id: str, agent_map: dict) -> str | None:
    val = agent_map.get(agent_id) or agent_map.get("*")
    return val if isinstance(val, str) else None


def run_cycle(
    openclaw_config_path: Path,
    agents_root: Path,
    cfg: dict,
    orch_client=None,
    key_store: "AgentKeyStore | None" = None,
) -> None:
    proxy_base_url: str = cfg["proxy_base_url"]
    provider_key_env_vars: dict = cfg["provider_key_env_vars"]
    scope_tool_map: dict = cfg["scope_tool_map"]
    agent_map: dict = cfg["agents"]
    zeroid_url: str = cfg.get("zeroid_url", "")
    buffer_secs: int = cfg.get("token_refresh_buffer_secs", 60)

    agent_tool_updates: dict[str, dict] = {}

    # Provider list from openclaw.json for seeding auth-profiles when empty.
    _oc_providers: list[str] = []
    if openclaw_config_path.exists():
        try:
            _oc = json.loads(openclaw_config_path.read_text(encoding="utf-8"))
            _oc_providers = list((_oc.get("models") or {}).get("providers") or {})
        except (json.JSONDecodeError, OSError):
            pass

    if agents_root.exists():
        for agent_id_dir in sorted(agents_root.iterdir()):
            if not agent_id_dir.is_dir():
                continue
            agent_id = agent_id_dir.name
            agent_dir = agent_id_dir / "agent"
            if not agent_dir.is_dir():
                continue

            agent_entry = agent_map.get(agent_id) or agent_map.get("*")
            if agent_entry is None:
                continue

            # Resolve identity key — dynamic dict or static string.
            if isinstance(agent_entry, dict):
                if orch_client is None or key_store is None:
                    log.error(
                        "agent %s: dynamic config requires zeroid_url + orchestrator_api_key",
                        agent_id,
                    )
                    continue
                # If this agent delegates from a parent, use the parent's cached
                # token as the subject so revoking the parent cascades here.
                parent_id = agent_entry.get("delegated_from", "")
                subject_token: str | None = None
                if parent_id:
                    parent_cached = _token_cache.get(parent_id)
                    if parent_cached:
                        subject_token = parent_cached[0]
                    else:
                        log.warning(
                            "agent %s: parent %r has no cached token yet — "
                            "will retry next cycle",
                            agent_id, parent_id,
                        )
                        continue
                identity_key = resolve_identity_key_dynamic(
                    agent_id, agent_entry, orch_client, key_store, zeroid_url, buffer_secs,
                    owner_user_id=cfg.get("admin_user_id", ""),
                    subject_token=subject_token,
                )
            else:
                identity_key = agent_entry if isinstance(agent_entry, str) else None

            if not identity_key:
                continue

            # Decode JWT scope → OpenClaw tool policy.
            payload = decode_jwt_payload(identity_key)
            tools_cfg = resolve_tool_config(payload, scope_tool_map)
            if tools_cfg:
                agent_tool_updates[agent_id] = tools_cfg

            inject_identities_for_agent(agent_dir / "auth-profiles.json", agent_id, identity_key, _oc_providers)
    else:
        log.debug("agents root %s does not exist yet", agents_root)

    if key_store is not None:
        key_store.save_if_dirty()

    patch_openclaw_config(
        openclaw_config_path,
        proxy_base_url,
        provider_key_env_vars,
        agent_tool_updates,
    )


# ---------------------------------------------------------------------------
# Config loading + main loop
# ---------------------------------------------------------------------------

def load_sidecar_config(config_path: Path) -> dict:
    raw = json.loads(config_path.read_text(encoding="utf-8"))

    proxy_base_url = raw.get("proxy_base_url")
    if isinstance(proxy_base_url, str):
        proxy_base_url = proxy_base_url.strip()
        if not proxy_base_url:
            raise ValueError("identity-map.json 'proxy_base_url' must be non-empty")
    elif isinstance(proxy_base_url, dict):
        if not proxy_base_url:
            raise ValueError("identity-map.json 'proxy_base_url' dict must have at least one entry")
    else:
        raise ValueError("identity-map.json 'proxy_base_url' must be a string or object")
    provider_key_env_vars = raw.get("provider_key_env_vars", {})
    if not isinstance(provider_key_env_vars, dict):
        raise ValueError("identity-map.json 'provider_key_env_vars' must be an object")
    scope_tool_map = raw.get("scope_tool_map", {})
    if not isinstance(scope_tool_map, dict):
        raise ValueError("identity-map.json 'scope_tool_map' must be an object")
    agents = raw.get("agents", {})
    if not isinstance(agents, dict):
        raise ValueError("identity-map.json 'agents' must be an object")

    # Dynamic mode fields — zeroid_url required when any agent value is a dict.
    # orchestrator_api_key is optional: if omitted the sidecar auto-registers.
    has_dynamic = any(isinstance(v, dict) for v in agents.values())
    zeroid_url = raw.get("zeroid_url", "").strip()
    if has_dynamic and not zeroid_url:
        raise ValueError("dynamic agents require 'zeroid_url'")

    return {
        "proxy_base_url": proxy_base_url,
        "provider_key_env_vars": provider_key_env_vars,
        "scope_tool_map": scope_tool_map,
        "agents": agents,
        "zeroid_url": zeroid_url,
        "orchestrator_api_key": raw.get("orchestrator_api_key", "").strip(),
        "zeroid_admin_url": raw.get("zeroid_admin_url", "").strip(),
        "admin_account_id": raw.get("admin_account_id", "").strip(),
        "admin_project_id": raw.get("admin_project_id", "").strip(),
        "admin_user_id": raw.get("admin_user_id", "").strip(),
        "agent_key_store": raw.get("agent_key_store", "~/.openclaw/sidecar-agent-keys.json"),
        "token_refresh_buffer_secs": int(raw.get("token_refresh_buffer_secs", 60)),
    }


def ensure_orchestrator_ready(cfg: dict, key_store: AgentKeyStore) -> str:
    """
    Return a valid orchestrator API key using the first available source:
      1. 'orchestrator_api_key' in config (explicit / bring-your-own)
      2. Key store (persisted from a previous auto-registration)
      3. Auto-register a new orchestrator identity and issue an API key

    The key is always persisted to the key store after step 3 so subsequent
    runs skip registration. The orchestrator's allowed_scopes is set to the
    union of all agent scopes so every sub-agent exchange has a valid parent.
    """
    if cfg.get("orchestrator_api_key"):
        return cfg["orchestrator_api_key"]
    existing = key_store.get_orchestrator_key()
    if existing:
        return existing

    try:
        from highflame.zeroid import ZeroIDClient
        from highflame.zeroid.errors import ZeroIDError
    except ImportError as e:
        raise SystemExit("dynamic mode requires the highflame SDK: pip install highflame") from e

    # Collect the union of all scopes the sub-agents will ever request.
    all_scopes = sorted({
        s
        for v in cfg["agents"].values()
        if isinstance(v, dict)
        for s in (v.get("allowed_scopes") or v.get("scope", "").split())
        if s
    })

    admin_url = cfg.get("zeroid_admin_url") or cfg["zeroid_url"]
    bootstrap = ZeroIDClient(
        base_url=admin_url,
        account_id=cfg["admin_account_id"] or None,
        project_id=cfg["admin_project_id"] or None,
    )

    owner_user_id = cfg.get("admin_user_id", "").strip() or None
    api_key: str
    try:
        identity = bootstrap.identities.create(
            name=_ORCH_EXTERNAL_ID,
            external_id=_ORCH_EXTERNAL_ID,
            owner_user_id=owner_user_id,
            allowed_scopes=all_scopes or None,
        )
        created = bootstrap.api_keys.create(
            name="sidecar-orchestrator",
            identity_id=identity.id,
            scopes=all_scopes or None,
        )
        api_key = created.key
        log.info(
            "registered orchestrator identity (id=%s, owner=%s, scopes=%s)",
            identity.id, owner_user_id, all_scopes,
        )
    except ZeroIDError as e:
        if "409" not in str(e) and getattr(e, "code", "") not in ("conflict", "already_exists"):
            raise
        # Already registered — find identity, update scopes, issue a fresh API key.
        existing_identity = next(
            (i for i in bootstrap.identities.list() if i.external_id == _ORCH_EXTERNAL_ID),
            None,
        )
        if existing_identity is None:
            raise RuntimeError(
                "orchestrator identity returned 409 but was not found in list"
            ) from e
        bootstrap.identities.update(
            existing_identity.id,
            owner_user_id=owner_user_id,
            allowed_scopes=all_scopes or None,
        )
        created = bootstrap.api_keys.create(
            name="sidecar-orchestrator",
            identity_id=existing_identity.id,
            scopes=all_scopes or None,
        )
        api_key = created.key
        log.info(
            "issued new API key for existing orchestrator (id=%s, scopes=%s)",
            existing_identity.id, all_scopes,
        )

    key_store.set_orchestrator_key(api_key)
    key_store.save_if_dirty()
    return api_key


def _build_orch_client(cfg: dict, key_store: "AgentKeyStore"):
    """Resolve the orchestrator API key then construct a ZeroIDClient.

    If the stored key is invalid (revoked or expired), clears it from the key
    store and re-registers so the next call to ensure_orchestrator_ready issues
    a fresh key.
    """
    try:
        from highflame.zeroid import ZeroIDClient
    except ImportError as e:
        raise SystemExit("dynamic mode requires the highflame SDK: pip install highflame") from e

    def _make_client(api_key: str) -> "ZeroIDClient":
        return ZeroIDClient(
            base_url=cfg["zeroid_url"],
            api_key=api_key,
            account_id=cfg["admin_account_id"] or None,
            project_id=cfg["admin_project_id"] or None,
        )

    api_key = ensure_orchestrator_ready(cfg, key_store)
    client = _make_client(api_key)

    # Validate the key with a cheap authenticated call. If it fails with an
    # auth error, the stored key is stale — clear it and re-register.
    try:
        client.identities.list()
    except Exception as e:
        if "401" in str(e) or "403" in str(e) or getattr(e, "status_code", None) in (401, 403):
            log.warning("stored orchestrator API key is invalid (%s) — re-registering", e)
            key_store.clear_orchestrator_key()
            key_store.save_if_dirty()
            api_key = ensure_orchestrator_ready(cfg, key_store)
            client = _make_client(api_key)
        else:
            log.warning("orchestrator key validation call failed (non-auth): %s", e)

    return client


def _ensure_credential_policy(client) -> None:
    """
    Create the openclaw credential policy if it doesn't already exist.
    max_delegation_depth=2 allows orchestrator → main agent → sub-agent but
    prevents sub-agents from spawning further delegates.
    """
    try:
        from highflame.zeroid.errors import ZeroIDError
        client.credential_policies.create(
            name="openclaw-policy",
            max_ttl_seconds=3600,
            required_trust_level="first_party",
            max_delegation_depth=2,
        )
        log.info("created credential policy 'openclaw-policy'")
    except Exception as e:
        if "409" in str(e) or getattr(e, "code", "") in ("conflict", "already_exists"):
            log.debug("credential policy 'openclaw-policy' already exists")
        else:
            log.warning("could not create credential policy: %s", e)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", required=True, type=Path, help="Path to identity-map.json")
    parser.add_argument("--state-dir", type=str, default=None, help="Override OpenClaw state dir (default: ~/.openclaw)")
    parser.add_argument("--interval", type=float, default=5.0, help="Poll interval in seconds (default: 5)")
    parser.add_argument("--once", action="store_true", help="Run once and exit instead of polling")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config_path: Path = args.config.expanduser().resolve()
    if not config_path.exists():
        raise SystemExit(f"config not found: {config_path}")

    state_dir = resolve_state_dir(args.state_dir)
    openclaw_config_path = resolve_openclaw_config_path(state_dir)
    agents_root = resolve_agents_root(state_dir)
    log.info("state dir: %s", state_dir)
    log.info("watching agents: %s every %.1fs", agents_root, args.interval)

    # Load config once up front to decide whether to build dynamic mode objects.
    cfg = load_sidecar_config(config_path)
    has_dynamic = any(isinstance(v, dict) for v in cfg["agents"].values())

    # AgentKeyStore must be created before the orchestrator client so
    # ensure_orchestrator_ready() can read/write the persisted API key.
    key_store = AgentKeyStore(Path(cfg["agent_key_store"]).expanduser()) if has_dynamic else None
    orch_client = _build_orch_client(cfg, key_store) if has_dynamic else None

    if orch_client is not None:
        _ensure_credential_policy(orch_client)
    while True:
        try:
            # Re-read config each cycle so agent/scope changes take effect without restart.
            cfg = load_sidecar_config(config_path)
            new_has_dynamic = any(isinstance(v, dict) for v in cfg["agents"].values())
            if new_has_dynamic and orch_client is None:
                key_store = AgentKeyStore(Path(cfg["agent_key_store"]).expanduser())
                orch_client = _build_orch_client(cfg, key_store)

            run_cycle(openclaw_config_path, agents_root, cfg, orch_client, key_store)
        except Exception as e:
            log.error("cycle failed: %s", e)

        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
