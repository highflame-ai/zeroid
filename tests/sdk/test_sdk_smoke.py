"""SDK smoke tests against a live ZeroID server.

Spins up a real PostgreSQL container via testcontainers, builds the zeroid
binary, starts it, and runs the full SDK lifecycle against it. Works
identically in CI and local dev — no Docker Compose or external setup needed.

Requires:
    pip install highflame testcontainers "PyJWT[cryptography]>=2.8" pytest

    The zeroid Go source must be in the repo root (go build must succeed).

Usage:
    pytest tests/sdk/test_sdk_smoke.py -v
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Locate repo root (two levels up from this file)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Session-scoped fixture: Postgres + ZeroID server
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def zeroid_url():
    """Build zeroid, start Postgres via testcontainers, start the server."""
    # Check Go is available
    if not shutil.which("go"):
        pytest.skip("Go toolchain not found — required to build zeroid")

    from testcontainers.postgres import PostgresContainer

    # 1. Start Postgres
    pg = PostgresContainer("postgres:17-alpine", dbname="zeroid", username="zeroid", password="zeroid")
    pg.start()
    db_url = pg.get_connection_url().replace("+psycopg2", "")  # Go driver needs plain postgres://
    if "sslmode" not in db_url:
        db_url += ("&" if "?" in db_url else "?") + "sslmode=disable"

    # 2. Generate signing keys
    keys_dir = Path(tempfile.mkdtemp(prefix="zeroid-keys-"))
    subprocess.run(
        ["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(keys_dir / "private.pem")],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "ec", "-in", str(keys_dir / "private.pem"), "-pubout", "-out", str(keys_dir / "public.pem")],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "genrsa", "-out", str(keys_dir / "rsa_private.pem"), "2048"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "rsa", "-in", str(keys_dir / "rsa_private.pem"), "-pubout", "-out", str(keys_dir / "rsa_public.pem")],
        check=True, capture_output=True,
    )

    # 3. Config via env vars (avoids path resolution issues with YAML)
    port = _free_port()
    server_env = {
        **os.environ,
        "ZEROID_PORT": str(port),
        "ZEROID_DATABASE_URL": db_url,
        "ZEROID_PRIVATE_KEY_PATH": str(keys_dir / "private.pem"),
        "ZEROID_PUBLIC_KEY_PATH": str(keys_dir / "public.pem"),
        "ZEROID_RSA_PRIVATE_KEY_PATH": str(keys_dir / "rsa_private.pem"),
        "ZEROID_RSA_PUBLIC_KEY_PATH": str(keys_dir / "rsa_public.pem"),
        # ZEROID_ISSUER now serves three roles per RFC 8414 §3: JWT iss claim,
        # discovery anchor, AND URL prefix for advertised endpoints. Point it
        # at the test server's actual URL so all three roles work coherently.
        "ZEROID_ISSUER": f"http://localhost:{port}",
        "ZEROID_TOKEN_TTL_SECONDS": "3600",
        "ZEROID_WIMSE_DOMAIN": "zeroid.test",
        "ZEROID_LOG_LEVEL": "warn",
    }

    # 4. Build zeroid
    binary = keys_dir / "zeroid"
    result = subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/zeroid"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pg.stop()
        pytest.fail(f"go build failed:\n{result.stderr}")

    # 5. Start server
    proc = subprocess.Popen(
        [str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=server_env,
    )

    # 6. Wait for health
    base_url = f"http://localhost:{port}"
    import urllib.request
    import urllib.error

    for _ in range(30):
        try:
            urllib.request.urlopen(f"{base_url}/health", timeout=1)
            break
        except (urllib.error.URLError, ConnectionError, OSError):
            if proc.poll() is not None:
                stdout = proc.stdout.read().decode() if proc.stdout else ""
                stderr = proc.stderr.read().decode() if proc.stderr else ""
                pg.stop()
                pytest.fail(f"ZeroID process exited with code {proc.returncode}\nstdout: {stdout}\nstderr: {stderr}")
            time.sleep(0.5)
    else:
        stdout = proc.stdout.read().decode() if proc.stdout else ""
        stderr = proc.stderr.read().decode() if proc.stderr else ""
        proc.kill()
        pg.stop()
        pytest.fail(f"ZeroID server did not become healthy within 15s\nstdout: {stdout}\nstderr: {stderr}")

    yield base_url

    # Teardown
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    pg.stop()
    shutil.rmtree(keys_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def client(zeroid_url):
    from highflame.zeroid import ZeroIDClient

    return ZeroIDClient(
        base_url=zeroid_url,
        account_id="sdk-smoke-test",
        project_id="sdk-smoke-test",
    )


# ---------------------------------------------------------------------------
# 1. Health + discovery
# ---------------------------------------------------------------------------


class TestHealth:
    def test_server_is_reachable(self, client):
        resp = client.health()
        assert resp is not None

    def test_jwks_returns_keys(self, client):
        resp = client.jwks()
        assert resp is not None


# ---------------------------------------------------------------------------
# 2. Agent lifecycle
# ---------------------------------------------------------------------------


class TestAgentLifecycle:
    def test_register_get_list_delete(self, client):
        # Register
        result = client.agents.register(
            name="Smoke Agent",
            external_id=f"smoke-{os.getpid()}-{time.monotonic_ns()}",
            created_by="sdk-smoke-test",
        )
        assert result.identity is not None
        assert result.api_key.startswith("zid_sk_")
        agent_id = result.identity.id

        # Get
        agent = client.agents.get(agent_id)
        assert agent.id == agent_id
        assert agent.name == "Smoke Agent"

        # List
        agents = client.agents.list()
        assert agent_id in [a.id for a in agents]

        # Deactivate + activate
        d = client.agents.deactivate(agent_id)
        assert d.status in ("suspended", "deactivated")
        a = client.agents.activate(agent_id)
        assert a.status == "active"

        # Rotate key
        rotated = client.agents.rotate_key(agent_id)
        assert rotated.api_key != result.api_key

        # Delete
        client.agents.delete(agent_id)


# ---------------------------------------------------------------------------
# 3. Token lifecycle
# ---------------------------------------------------------------------------


class TestTokenLifecycle:
    def test_issue_verify_introspect_revoke(self, client):
        # Setup: register agent
        reg = client.agents.register(
            name="Token Agent",
            external_id=f"token-{os.getpid()}-{time.monotonic_ns()}",
            created_by="sdk-smoke-test",
        )

        try:
            # Issue
            token = client.tokens.issue_api_key(reg.api_key)
            assert token.access_token
            assert token.token_type.lower() == "bearer"
            assert token.expires_in > 0

            # Verify locally
            identity = client.tokens.verify(token.access_token)
            assert identity.sub  # WIMSE URI

            # Session introspection
            session = client.tokens.session(token.access_token)
            assert session.active is True
            assert session.sub

            # Revoke
            client.tokens.revoke(token.access_token)
            revoked = client.tokens.introspect(token.access_token)
            assert revoked.active is False
        finally:
            client.agents.delete(reg.identity.id)


# ---------------------------------------------------------------------------
# 4. Verification guards
# ---------------------------------------------------------------------------


class TestVerificationGuards:
    def test_require_scope_and_trust(self, client):
        from highflame.zeroid import ZeroIDError

        reg = client.agents.register(
            name="Guard Agent",
            external_id=f"guard-{os.getpid()}-{time.monotonic_ns()}",
            created_by="sdk-smoke-test",
        )

        try:
            token = client.tokens.issue_api_key(reg.api_key, scope="read:data")
            identity = client.tokens.verify(token.access_token)

            # Passes
            identity.require_scope("read:data")
            identity.require_trust("unverified")

            # Fails
            with pytest.raises(ZeroIDError, match="Missing required scope"):
                identity.require_scope("admin:delete")

            assert identity.is_delegated() is False
        finally:
            client.agents.delete(reg.identity.id)


# ---------------------------------------------------------------------------
# 5. Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_not_found_raises(self, client):
        from highflame.zeroid.errors import NotFoundError

        with pytest.raises(NotFoundError):
            client.agents.get("00000000-0000-0000-0000-000000000000")

    def test_introspect_invalid_token(self, client):
        result = client.tokens.introspect("invalid.token.value")
        assert result.active is False


# ---------------------------------------------------------------------------
# 6. OAuth client → client_credentials → RFC 8693 delegation
#
# Exercises the surface the quickstart notebook depends on, which the
# agent/api_key path above does NOT cover: oauth_clients.create (confidential),
# the client_credentials grant, and token_exchange delegation. Runs against the
# live server so any SDK<->server contract drift on these endpoints fails here.
# ---------------------------------------------------------------------------


class TestOAuthClientCredentialsAndDelegation:
    def test_client_credentials_and_delegation(self, client, zeroid_url):
        import json
        import urllib.request

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import jwt as pyjwt

        suffix = f"{os.getpid()}-{time.monotonic_ns()}"
        orch_external_id = f"orch-{suffix}"

        # 1. Orchestrator identity (client_credentials resolves the identity by
        #    external_id == client_id, so the OAuth client_id must match this).
        orchestrator = client.identities.create(
            external_id=orch_external_id,
            owner_user_id="sdk-smoke-test",
            name="Smoke Orchestrator",
            identity_type="agent",
            sub_type="orchestrator",
            trust_level="first_party",
            allowed_scopes=["data:read", "data:write"],
        )

        # 2. Tool agent identity with an ECDSA P-256 public key (for the
        #    self-signed actor assertion in the token exchange).
        priv = ec.generate_private_key(ec.SECP256R1())
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        tool_agent = client.identities.create(
            external_id=f"tool-{suffix}",
            owner_user_id="sdk-smoke-test",
            name="Smoke Tool Agent",
            identity_type="agent",
            sub_type="tool_agent",
            trust_level="first_party",
            allowed_scopes=["data:read"],
            public_key_pem=pub_pem,
        )

        oauth_client_id = None
        try:
            # 3. Confidential OAuth client — returns a client_secret for M2M.
            created = client.oauth_clients.create(
                client_id=orch_external_id,
                name="Smoke Orchestrator Client",
                confidential=True,
                identity_id=orchestrator.id,
                grant_types=[
                    "client_credentials",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ],
                scopes=["data:read", "data:write"],
            )
            oauth_client_id = created.client.id
            assert created.client_secret, "confidential client must return a secret"
            assert created.client.client_id == orch_external_id

            # 4. client_credentials grant.
            token = client.tokens.issue_client_credentials(
                client_id=orch_external_id,
                client_secret=created.client_secret,
                scope="data:read",
            )
            assert token.access_token
            assert token.token_type.lower() == "bearer"

            # 5. Tool agent's self-signed actor assertion (RFC 7523: iss, sub,
            #    aud, exp; self-signed → sub == iss == WIMSE URI).
            with urllib.request.urlopen(
                f"{zeroid_url}/.well-known/oauth-authorization-server", timeout=5
            ) as resp:
                issuer = json.load(resp)["issuer"]
            now = int(time.time())
            actor_assertion = pyjwt.encode(
                {
                    "iss": tool_agent.wimse_uri,
                    "sub": tool_agent.wimse_uri,
                    "aud": [issuer],
                    "iat": now,
                    "exp": now + 300,
                },
                priv,
                algorithm="ES256",
            )

            # 6. RFC 8693 token exchange — orchestrator delegates to tool agent.
            delegated = client.tokens.issue_token_exchange(
                subject_token=token.access_token,
                actor_token=actor_assertion,
                scope="data:read",
            )
            assert delegated.access_token

            # 7. Introspect: delegated token carries the act (delegation) chain.
            introspection = client.tokens.introspect(delegated.access_token)
            assert introspection.active is True
            assert introspection.sub == tool_agent.wimse_uri
            assert introspection.act and introspection.act.get("sub") == orchestrator.wimse_uri

            # 8. Revoke → inactive.
            client.tokens.revoke(delegated.access_token)
            assert client.tokens.introspect(delegated.access_token).active is False
        finally:
            if oauth_client_id:
                client.oauth_clients.delete(oauth_client_id)
            client.identities.delete(tool_agent.id)
            client.identities.delete(orchestrator.id)
