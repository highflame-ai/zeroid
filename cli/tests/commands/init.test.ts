/**
 * Tests for `zid init`.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { runCLI, BASE_URL } from "../helpers.js";
import type { AgentRegistered, AgentResponse } from "@highflame/sdk";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const AGENT: AgentResponse = {
  id: "agt_new123",
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
  description: "",
  capabilities: null,
  labels: null,
  metadata: null,
  created_at: new Date().toISOString(),
  created_by: "user_xyz",
  updated_at: new Date().toISOString(),
};

const REGISTER_RESPONSE: AgentRegistered = {
  identity: AGENT,
  api_key: "zid_sk_brand_new",
};

// Cleanup .env.zeroid written by init
afterEach(() => rmSync(join(process.cwd(), ".env.zeroid"), { force: true }));

describe("zid init", () => {
  it("POST /api/v1/agents/register with correct fields", async () => {
    let captured: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/register`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(REGISTER_RESPONSE);
      }),
    );

    await runCLI(["init", "--name", "github-mcp-server", "--type", "mcp_server"]);

    expect(captured["name"]).toBe("github-mcp-server");
    expect(captured["external_id"]).toBe("github-mcp-server");
    expect(captured["identity_type"]).toBe("mcp_server");
  });

  it("uses --id as external_id when provided", async () => {
    let captured: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/register`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(REGISTER_RESPONSE);
      }),
    );

    await runCLI(["init", "--name", "My Agent", "--id", "my-agent-001"]);

    expect(captured["external_id"]).toBe("my-agent-001");
    expect(captured["name"]).toBe("My Agent");
  });

  it("includes framework and description when provided", async () => {
    let captured: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/register`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(REGISTER_RESPONSE);
      }),
    );

    await runCLI([
      "init", "--name", "agent",
      "--framework", "langchain",
      "--description", "A code reviewer",
    ]);

    expect(captured["framework"]).toBe("langchain");
    expect(captured["description"]).toBe("A code reviewer");
  });

  it("prints WIMSE URI and API key on success", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/register`, () => HttpResponse.json(REGISTER_RESPONSE)),
    );

    const { stdout, stderr } = await runCLI(["init", "--name", "github-mcp-server"]);
    const out = stdout.join("\n");
    expect(out).toContain("wimse:agent:acct_test/proj_test/github-mcp-server");
    expect(out).toContain("zid_sk_brand_new");
    // Should warn about storing the key
    expect(stderr.join("")).toMatch(/securely/i);
  });

  it("writes .env.zeroid with the api_key", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/register`, () => HttpResponse.json(REGISTER_RESPONSE)),
    );

    await runCLI(["init", "--name", "github-mcp-server"]);

    const { readFileSync } = await import("node:fs");
    const content = readFileSync(join(process.cwd(), ".env.zeroid"), "utf8");
    expect(content).toBe("ZID_API_KEY=zid_sk_brand_new\n");
  });

  it("outputs raw JSON with --json", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/register`, () => HttpResponse.json(REGISTER_RESPONSE)),
    );

    const { stdout } = await runCLI(["init", "--name", "agent", "--json"]);
    const parsed = JSON.parse(stdout.join("")) as AgentRegistered;
    // SDK type contract: must be .identity not .agent
    expect(parsed.identity.id).toBe("agt_new123");
    expect(parsed.api_key).toBe("zid_sk_brand_new");
  });

  it("still writes .env.zeroid when --json is given", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/register`, () => HttpResponse.json(REGISTER_RESPONSE)),
    );

    await runCLI(["init", "--name", "agent", "--json"]);

    const { readFileSync } = await import("node:fs");
    const content = readFileSync(join(process.cwd(), ".env.zeroid"), "utf8");
    expect(content).toBe("ZID_API_KEY=zid_sk_brand_new\n");
  });

  it("exits 1 on conflict (agent already exists)", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/agents/register`, () =>
        HttpResponse.json({ title: "Conflict", detail: "agent already exists" }, { status: 409 }),
      ),
    );
    const { exitCode, stderr } = await runCLI(["init", "--name", "duplicate"]);
    expect(exitCode).toBe(1);
    expect(stderr.join("")).toMatch(/already exists/i);
  });

  it("exits 1 when --name is missing", async () => {
    const { exitCode } = await runCLI(["init"]);
    expect(exitCode).toBe(1);
  });
});
