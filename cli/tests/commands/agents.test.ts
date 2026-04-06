/**
 * Tests for `zid agents` subcommands: list, get, rotate-key, deactivate, activate.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { runCLI, BASE_URL } from "../helpers.js";
import type { AgentResponse, AgentRegistered, AgentListResponse } from "@highflame/sdk";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const AGENT: AgentResponse = {
  id: "agt_abc123",
  account_id: "acct_test",
  project_id: "proj_test",
  name: "github-mcp-server",
  external_id: "github-mcp-server",
  wimse_uri: "wimse:agent:acct_test/proj_test/github-mcp-server",
  api_key_prefix: "zid_sk_abc",
  identity_type: "mcp_server",
  sub_type: "tool_agent",
  trust_level: "first_party",
  status: "active",
  framework: "mcp",
  version: "",
  publisher: "",
  description: "GitHub MCP server",
  capabilities: null,
  labels: null,
  metadata: null,
  created_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
  created_by: "user_xyz",
  updated_at: new Date().toISOString(),
};

const AGENT_LIST: AgentListResponse = {
  agents: [AGENT],
  total: 1,
  limit: 50,
  offset: 0,
};

const ROTATED: AgentRegistered = {
  identity: { ...AGENT, updated_at: new Date().toISOString() },
  api_key: "zid_sk_newkey123",
};

// ---------------------------------------------------------------------------
// agents list
// ---------------------------------------------------------------------------

describe("zid agents list", () => {
  it("GET /api/v1/agents/registry and renders a table", async () => {
    server.use(http.get(`${BASE_URL}/api/v1/agents/registry`, () => HttpResponse.json(AGENT_LIST)));
    const { stdout, exitCode } = await runCLI(["agents", "list"]);
    expect(exitCode).toBeUndefined();
    const out = stdout.join("\n");
    expect(out).toContain("github-mcp-server");
    expect(out).toContain("mcp_server");
    expect(out).toContain("first_party");
    expect(out).toContain("active");
  });

  it("forwards --type as query param", async () => {
    let qs = "";
    server.use(
      http.get(`${BASE_URL}/api/v1/agents/registry`, ({ request }) => {
        qs = new URL(request.url).search;
        return HttpResponse.json(AGENT_LIST);
      }),
    );
    await runCLI(["agents", "list", "--type", "mcp_server"]);
    expect(qs).toContain("identity_type=mcp_server");
  });

  it("outputs a JSON array with --json", async () => {
    server.use(http.get(`${BASE_URL}/api/v1/agents/registry`, () => HttpResponse.json(AGENT_LIST)));
    const { stdout } = await runCLI(["agents", "list", "--json"]);
    const parsed = JSON.parse(stdout.join("")) as AgentResponse[];
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0]?.id).toBe("agt_abc123");
  });

  it("prints 'No agents found' when list is empty", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/agents/registry`, () =>
        HttpResponse.json({ agents: [], total: 0, limit: 50, offset: 0 }),
      ),
    );
    const { stdout } = await runCLI(["agents", "list"]);
    expect(stdout.join("")).toMatch(/no agents/i);
  });

  it("exits 1 when tenant context is missing", async () => {
    const { exitCode, stderr } = await runCLI(
      ["agents", "list", "--profile", "ghost"],
      { ZID_API_KEY: "", ZID_ACCOUNT_ID: "", ZID_PROJECT_ID: "" },
    );
    expect(exitCode).toBe(1);
    expect(stderr.join("")).toMatch(/tenant context/i);
  });

  it("exits 1 on API error", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/agents/registry`, () =>
        HttpResponse.json({ title: "Unauthorized" }, { status: 401 }),
      ),
    );
    const { exitCode } = await runCLI(["agents", "list"]);
    expect(exitCode).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// agents get
// ---------------------------------------------------------------------------

describe("zid agents get", () => {
  it("GET /api/v1/agents/registry/:id and prints agent details", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/agents/registry/agt_abc123`, () => HttpResponse.json(AGENT)),
    );
    const { stdout, exitCode } = await runCLI(["agents", "get", "agt_abc123"]);
    expect(exitCode).toBeUndefined();
    const out = stdout.join("\n");
    expect(out).toContain("github-mcp-server");
    expect(out).toContain("wimse:agent:acct_test/proj_test/github-mcp-server");
    expect(out).toContain("mcp_server");
  });

  it("outputs raw JSON with --json", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/agents/registry/agt_abc123`, () => HttpResponse.json(AGENT)),
    );
    const { stdout } = await runCLI(["agents", "get", "--json", "agt_abc123"]);
    const parsed = JSON.parse(stdout.join("")) as AgentResponse;
    expect(parsed.id).toBe("agt_abc123");
    expect(parsed.wimse_uri).toBe("wimse:agent:acct_test/proj_test/github-mcp-server");
  });

  it("exits 1 when agent not found", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/agents/registry/ghost`, () =>
        HttpResponse.json({ title: "Not Found", detail: "identity not found" }, { status: 404 }),
      ),
    );
    const { exitCode } = await runCLI(["agents", "get", "ghost"]);
    expect(exitCode).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// agents rotate-key
// ---------------------------------------------------------------------------

describe("zid agents rotate-key", () => {
  it("POST /api/v1/agents/registry/:id/rotate-key and prints new key", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/registry/agt_abc123/rotate-key`, () =>
        HttpResponse.json(ROTATED),
      ),
    );
    const { stdout, stderr, exitCode } = await runCLI(["agents", "rotate-key", "agt_abc123"]);
    expect(exitCode).toBeUndefined();
    expect(stdout.join("\n")).toContain("zid_sk_newkey123");
    // Should warn about storing the key
    expect(stderr.join("")).toMatch(/securely/i);
  });

  it("outputs raw JSON with --json", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/registry/agt_abc123/rotate-key`, () =>
        HttpResponse.json(ROTATED),
      ),
    );
    const { stdout } = await runCLI(["agents", "rotate-key", "--json", "agt_abc123"]);
    const parsed = JSON.parse(stdout.join("")) as AgentRegistered;
    // SDK type check: AgentRegistered uses .identity not .agent
    expect(parsed.identity.id).toBe("agt_abc123");
    expect(parsed.api_key).toBe("zid_sk_newkey123");
  });

  it("exits 1 when agent not found", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/registry/ghost/rotate-key`, () =>
        HttpResponse.json({ title: "Not Found", detail: "identity not found" }, { status: 404 }),
      ),
    );
    const { exitCode } = await runCLI(["agents", "rotate-key", "ghost"]);
    expect(exitCode).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// agents deactivate / activate
// ---------------------------------------------------------------------------

describe("zid agents deactivate", () => {
  it("POST /api/v1/agents/registry/:id/deactivate", async () => {
    const deactivated = { ...AGENT, status: "deactivated" as const };
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/registry/agt_abc123/deactivate`, () =>
        HttpResponse.json(deactivated),
      ),
    );
    const { stdout, exitCode } = await runCLI(["agents", "deactivate", "agt_abc123"]);
    expect(exitCode).toBeUndefined();
    expect(stdout.join("")).toMatch(/deactivated/i);
  });

  it("outputs raw JSON with --json", async () => {
    const deactivated = { ...AGENT, status: "deactivated" as const };
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/registry/agt_abc123/deactivate`, () =>
        HttpResponse.json(deactivated),
      ),
    );
    const { stdout, exitCode } = await runCLI(["agents", "deactivate", "--json", "agt_abc123"]);
    expect(exitCode).toBeUndefined();
    const parsed = JSON.parse(stdout.join("")) as AgentResponse;
    expect(parsed.id).toBe("agt_abc123");
    expect(parsed.status).toBe("deactivated");
  });

  it("exits 1 on API error", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/registry/ghost/deactivate`, () =>
        HttpResponse.json({ title: "Not Found" }, { status: 404 }),
      ),
    );
    const { exitCode } = await runCLI(["agents", "deactivate", "ghost"]);
    expect(exitCode).toBe(1);
  });
});

describe("zid agents activate", () => {
  it("POST /api/v1/agents/registry/:id/activate", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/registry/agt_abc123/activate`, () =>
        HttpResponse.json(AGENT),
      ),
    );
    const { stdout, exitCode } = await runCLI(["agents", "activate", "agt_abc123"]);
    expect(exitCode).toBeUndefined();
    expect(stdout.join("")).toMatch(/activated/i);
  });

  it("outputs raw JSON with --json", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/registry/agt_abc123/activate`, () =>
        HttpResponse.json(AGENT),
      ),
    );
    const { stdout, exitCode } = await runCLI(["agents", "activate", "--json", "agt_abc123"]);
    expect(exitCode).toBeUndefined();
    const parsed = JSON.parse(stdout.join("")) as AgentResponse;
    expect(parsed.id).toBe("agt_abc123");
    expect(parsed.status).toBe("active");
  });

  it("exits 1 on API error", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/registry/ghost/activate`, () =>
        HttpResponse.json({ title: "Not Found" }, { status: 404 }),
      ),
    );
    const { exitCode } = await runCLI(["agents", "activate", "ghost"]);
    expect(exitCode).toBe(1);
  });
});
