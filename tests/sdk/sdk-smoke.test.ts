/**
 * SDK smoke tests against a live ZeroID server.
 *
 * Spins up a real PostgreSQL container via testcontainers, builds the zeroid
 * binary, starts it, and runs the full SDK lifecycle against it. Works
 * identically in CI and local dev — no Docker Compose or external setup needed.
 *
 * Requires:
 *   npm install @highflame/sdk testcontainers vitest
 *   Go toolchain (to build zeroid from source)
 *
 * Usage:
 *   npx vitest run tests/sdk/sdk-smoke.test.ts
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from "@testcontainers/postgresql";
import { execSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "../..");
const ACCOUNT_ID = "sdk-smoke-test";
const PROJECT_ID = "sdk-smoke-test";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, () => {
      const addr = srv.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        srv.close(() => resolve(port));
      } else {
        srv.close(() => reject(new Error("Could not get port")));
      }
    });
  });
}

async function waitForHealth(url: string, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`${url}/health`);
      if (resp.ok) return;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`ZeroID server did not become healthy within ${timeoutMs}ms`);
}

// ---------------------------------------------------------------------------
// Test suite — server lifecycle managed in beforeAll/afterAll
// ---------------------------------------------------------------------------

let baseUrl: string;
let pgContainer: StartedPostgreSqlContainer;
let serverProc: ChildProcess;
let keysDir: string;

// Dynamic import — SDK may not be installed as a regular dep in this repo
let ZeroIDClient: typeof import("@highflame/sdk").ZeroIDClient;
let ZeroIDError: typeof import("@highflame/sdk").ZeroIDError;

beforeAll(async () => {
  // 0. Import SDK
  const sdk = await import("@highflame/sdk");
  ZeroIDClient = sdk.ZeroIDClient;
  ZeroIDError = sdk.ZeroIDError;

  // 1. Start Postgres
  pgContainer = await new PostgreSqlContainer("postgres:17-alpine")
    .withDatabase("zeroid")
    .withUsername("zeroid")
    .withPassword("zeroid")
    .start();

  const dbUrl = `postgres://zeroid:zeroid@${pgContainer.getHost()}:${pgContainer.getPort()}/zeroid?sslmode=disable`;

  // 2. Generate signing keys
  keysDir = mkdtempSync(join(tmpdir(), "zeroid-keys-"));
  execSync(`openssl ecparam -genkey -name prime256v1 -noout -out ${keysDir}/private.pem`, { stdio: "pipe" });
  execSync(`openssl ec -in ${keysDir}/private.pem -pubout -out ${keysDir}/public.pem`, { stdio: "pipe" });
  execSync(`openssl genrsa -out ${keysDir}/rsa_private.pem 2048`, { stdio: "pipe" });
  execSync(`openssl rsa -in ${keysDir}/rsa_private.pem -pubout -out ${keysDir}/rsa_public.pem`, { stdio: "pipe" });

  // 3. Build zeroid
  const binaryPath = join(keysDir, "zeroid");
  const buildResult = execSync(`go build -o ${binaryPath} ./cmd/zeroid`, {
    cwd: REPO_ROOT,
    stdio: "pipe",
    encoding: "utf-8",
  });

  // 4. Start server
  const port = await freePort();
  baseUrl = `http://localhost:${port}`;

  serverProc = spawn(binaryPath, [], {
    env: {
      ...process.env,
      ZEROID_PORT: String(port),
      ZEROID_DATABASE_URL: dbUrl,
      ZEROID_PRIVATE_KEY_PATH: join(keysDir, "private.pem"),
      ZEROID_PUBLIC_KEY_PATH: join(keysDir, "public.pem"),
      ZEROID_RSA_PRIVATE_KEY_PATH: join(keysDir, "rsa_private.pem"),
      ZEROID_RSA_PUBLIC_KEY_PATH: join(keysDir, "rsa_public.pem"),
      ZEROID_ISSUER: "https://zeroid.test",
      ZEROID_BASE_URL: baseUrl,
      ZEROID_TOKEN_TTL_SECONDS: "3600",
      ZEROID_WIMSE_DOMAIN: "zeroid.test",
      ZEROID_LOG_LEVEL: "warn",
    },
    stdio: "pipe",
  });

  // 5. Wait for health
  await waitForHealth(baseUrl);
}, 120_000); // 2 min — includes Postgres pull + Go build

afterAll(async () => {
  serverProc?.kill();
  await pgContainer?.stop();
  if (keysDir) rmSync(keysDir, { recursive: true, force: true });
}, 15_000);

// ---------------------------------------------------------------------------
// 1. Health + discovery
// ---------------------------------------------------------------------------

describe("Health", () => {
  it("server is reachable", async () => {
    const client = new ZeroIDClient({ baseUrl, accountId: ACCOUNT_ID, projectId: PROJECT_ID });
    const health = await client.tokens.health();
    expect(health).toBeDefined();
  });

  it("JWKS returns keys", async () => {
    const client = new ZeroIDClient({ baseUrl, accountId: ACCOUNT_ID, projectId: PROJECT_ID });
    const jwks = await client.tokens.jwks();
    expect(jwks).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// 2. Agent lifecycle
// ---------------------------------------------------------------------------

describe("Agent lifecycle", () => {
  it("register → get → list → deactivate → activate → rotate → delete", async () => {
    const client = new ZeroIDClient({ baseUrl, accountId: ACCOUNT_ID, projectId: PROJECT_ID });
    const externalId = `smoke-ts-${Date.now()}`;

    // Register
    const result = await client.agents.register({
      name: "TS Smoke Agent",
      external_id: externalId,
      created_by: "sdk-smoke-test",
    });
    expect(result.identity).toBeDefined();
    expect(result.identity.id).toBeTruthy();
    expect(result.api_key).toMatch(/^zid_sk_/);
    const agentId = result.identity.id;

    // Get
    const agent = await client.agents.get(agentId);
    expect(agent.id).toBe(agentId);
    expect(agent.name).toBe("TS Smoke Agent");

    // List
    const list = await client.agents.list();
    expect(list.agents.some((a: { id: string }) => a.id === agentId)).toBe(true);

    // Deactivate + activate
    const deactivated = await client.agents.deactivate(agentId);
    expect(["suspended", "deactivated"]).toContain(deactivated.status);
    const activated = await client.agents.activate(agentId);
    expect(activated.status).toBe("active");

    // Rotate key
    const rotated = await client.agents.rotateKey(agentId);
    expect(rotated.api_key).not.toBe(result.api_key);

    // Delete
    await client.agents.delete(agentId);
  });
});

// ---------------------------------------------------------------------------
// 3. Token lifecycle
// ---------------------------------------------------------------------------

describe("Token lifecycle", () => {
  it("issue → verify → session → revoke", async () => {
    const client = new ZeroIDClient({ baseUrl, accountId: ACCOUNT_ID, projectId: PROJECT_ID });

    // Register agent
    const reg = await client.agents.register({
      name: "TS Token Agent",
      external_id: `token-ts-${Date.now()}`,
      created_by: "sdk-smoke-test",
    });

    try {
      // Issue
      const token = await client.tokens.issueApiKey(reg.api_key);
      expect(token.access_token).toBeTruthy();
      expect(token.token_type.toLowerCase()).toBe("bearer");
      expect(token.expires_in).toBeGreaterThan(0);

      // Verify locally
      const identity = await client.tokens.verify(token.access_token);
      expect(identity.sub).toBeTruthy();

      // Session introspection
      const session = await client.tokens.session(token.access_token);
      expect(session.active).toBe(true);
      expect(session.sub).toBeTruthy();

      // Revoke
      await client.tokens.revoke(token.access_token);
      const revoked = await client.tokens.introspect(token.access_token);
      expect(revoked.active).toBe(false);
    } finally {
      await client.agents.delete(reg.identity.id);
    }
  });
});

// ---------------------------------------------------------------------------
// 4. Verification guards
// ---------------------------------------------------------------------------

describe("Verification guards", () => {
  it("requireScope passes and fails correctly", async () => {
    const client = new ZeroIDClient({ baseUrl, accountId: ACCOUNT_ID, projectId: PROJECT_ID });

    const reg = await client.agents.register({
      name: "TS Guard Agent",
      external_id: `guard-ts-${Date.now()}`,
      created_by: "sdk-smoke-test",
    });

    try {
      const token = await client.tokens.issueApiKey(reg.api_key, { scope: "read:data" });
      const identity = await client.tokens.verify(token.access_token);

      // Passes
      identity.requireScope("read:data");
      identity.requireTrust("unverified");

      // Fails
      expect(() => identity.requireScope("admin:delete")).toThrow(ZeroIDError);

      // Not delegated
      expect(identity.isDelegated()).toBe(false);
    } finally {
      await client.agents.delete(reg.identity.id);
    }
  });
});

// ---------------------------------------------------------------------------
// 5. Error handling
// ---------------------------------------------------------------------------

describe("Error handling", () => {
  it("throws on nonexistent agent", async () => {
    const client = new ZeroIDClient({ baseUrl, accountId: ACCOUNT_ID, projectId: PROJECT_ID });
    await expect(
      client.agents.get("00000000-0000-0000-0000-000000000000"),
    ).rejects.toThrow();
  });

  it("introspect returns inactive for invalid token", async () => {
    const client = new ZeroIDClient({ baseUrl, accountId: ACCOUNT_ID, projectId: PROJECT_ID });
    const result = await client.tokens.introspect("invalid.token.value");
    expect(result.active).toBe(false);
  });
});
