"""
agent.py — FastAPI agent for the 32-agent cascade-revocation demo.

One image, 32 containers. Each container reads its token and identity from
the shared manifest written by provision.py, then:

  • Validates every inbound bearer token via ZeroID introspection (middleware).
  • Polls its own token every 2 s and updates the `zeroid_token_active` gauge.
  • Posts a stub task to a random child every 5 s (real HTTP, real auth header).
  • Exposes /metrics for Prometheus and /health for compose health checks.

No LLM calls — task payloads are fixture JSON that proves the delegation chain
is alive without touching any inference API.
"""

import asyncio
import json
import os
import random
import sys
import time

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CollectorRegistry, Gauge, generate_latest, CONTENT_TYPE_LATEST

# ── Configuration from environment ───────────────────────────────────────────
AGENT_NAME     = os.environ["AGENT_NAME"]
ZEROID_URL     = os.getenv("ZEROID_BASE_URL", "http://zeroid:8899")
MANIFEST_PATH  = os.getenv("MANIFEST_PATH", "/shared/manifest.json")
CHILD_URLS_RAW = os.getenv("CHILD_URLS", "")
CHILD_URLS     = [u.strip() for u in CHILD_URLS_RAW.split(",") if u.strip()]

# ── Prometheus metrics ────────────────────────────────────────────────────────
registry = CollectorRegistry()
TOKEN_ACTIVE = Gauge(
    "zeroid_token_active",
    "1 if the agent's ZeroID token is active, 0 if revoked",
    ["agent", "parent"],
    registry=registry,
)
TOKEN_REVOKED_AT = Gauge(
    "zeroid_token_revoked_at_seconds",
    "Unix timestamp when the token was first detected as revoked (0 = still active)",
    ["agent", "parent"],
    registry=registry,
)

# ── Load manifest ─────────────────────────────────────────────────────────────
def _load_manifest() -> dict:
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            with open(MANIFEST_PATH) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(2)
    print(f"[{AGENT_NAME}] ERROR: manifest not found at {MANIFEST_PATH}", file=sys.stderr)
    sys.exit(1)

manifest  = _load_manifest()
MY_ENTRY  = manifest[AGENT_NAME]
MY_TOKEN  = MY_ENTRY["token"]
MY_PARENT = MY_ENTRY.get("parent") or "root"

# Initialise optimistically; updated every 2 s by the self-introspect loop
TOKEN_ACTIVE.labels(agent=AGENT_NAME, parent=MY_PARENT).set(1)
TOKEN_REVOKED_AT.labels(agent=AGENT_NAME, parent=MY_PARENT).set(0)

# ── ZeroID introspection (sync, called from middleware via run_in_executor) ───
def _introspect_sync(token: str) -> bool:
    try:
        r = httpx.post(
            f"{ZEROID_URL}/oauth2/token/introspect",
            json={"token": token},
            timeout=5.0,
        )
        return r.json().get("active", False)
    except Exception:
        return False  # fail closed

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title=AGENT_NAME)

_first_revoked_at: float = 0.0  # module-level state for revocation timestamp


@app.middleware("http")
async def zeroid_auth_middleware(request: Request, call_next):
    # Skip auth for internal endpoints
    if request.url.path in ("/health", "/metrics"):
        return await call_next(request)

    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else None
    if not token:
        return JSONResponse({"error": "missing bearer token"}, status_code=401)

    loop = asyncio.get_event_loop()
    active = await loop.run_in_executor(None, _introspect_sync, token)
    if not active:
        return JSONResponse({"error": "credential revoked by ZeroID"}, status_code=401)
    return await call_next(request)


@app.get("/health")
async def health():
    return {"agent": AGENT_NAME, "status": "ok"}


@app.get("/metrics")
async def metrics():
    data = generate_latest(registry)
    return PlainTextResponse(data.decode(), media_type=CONTENT_TYPE_LATEST)


@app.post("/task")
async def receive_task(request: Request):
    body = await request.json()
    # Stub response — proves the chain is alive without an LLM call
    return {
        "agent":   AGENT_NAME,
        "task":    body.get("task", ""),
        "status":  "completed",
        "payload": {"result": f"stub result from {AGENT_NAME}", "ts": time.time()},
    }


# ── Background: self-introspect every 2 s and update gauge ───────────────────
async def _self_introspect_loop():
    global _first_revoked_at
    while True:
        await asyncio.sleep(2)
        loop = asyncio.get_event_loop()
        active = await loop.run_in_executor(None, _introspect_sync, MY_TOKEN)
        TOKEN_ACTIVE.labels(agent=AGENT_NAME, parent=MY_PARENT).set(1 if active else 0)
        if not active and _first_revoked_at == 0.0:
            _first_revoked_at = time.time()
            TOKEN_REVOKED_AT.labels(agent=AGENT_NAME, parent=MY_PARENT).set(_first_revoked_at)
            print(
                f"[{AGENT_NAME}] TOKEN REVOKED at {_first_revoked_at:.3f} "
                f"(cascade from ZeroID signal)",
                flush=True,
            )


# ── Background: call random child every 5 s with this agent's delegation token
async def _task_delegation_loop():
    await asyncio.sleep(10)  # let agents settle first
    while True:
        if CHILD_URLS:
            target = random.choice(CHILD_URLS)
            task_payload = {
                "task": f"quarterly-review from {AGENT_NAME}",
                "ts":   time.time(),
            }
            try:
                async with httpx.AsyncClient(timeout=5.0) as c:
                    r = await c.post(
                        f"{target}/task",
                        json=task_payload,
                        headers={"Authorization": f"Bearer {MY_TOKEN}"},
                    )
                if r.status_code == 401:
                    print(
                        f"[{AGENT_NAME}] → {target}: 401 UNAUTHORIZED "
                        f"(token revoked, delegation blocked)",
                        flush=True,
                    )
                else:
                    resp = r.json()
                    print(
                        f"[{AGENT_NAME}] → {resp.get('agent', target)}: "
                        f"{resp.get('status', '?')}",
                        flush=True,
                    )
            except Exception as e:
                print(f"[{AGENT_NAME}] → {target}: error ({e})", flush=True)
        await asyncio.sleep(5)


@app.on_event("startup")
async def startup():
    print(f"[{AGENT_NAME}] starting (tier={MY_ENTRY['tier']}, children={len(CHILD_URLS)})", flush=True)
    asyncio.create_task(_self_introspect_loop())
    asyncio.create_task(_task_delegation_loop())
