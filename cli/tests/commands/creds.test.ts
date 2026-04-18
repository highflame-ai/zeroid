/**
 * Tests for `zeroid creds list`.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { runCLI, BASE_URL } from "../helpers.js";
import type { CredentialListResponse, IssuedCredential } from "@highflame/sdk";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const now = new Date().toISOString();
const past = new Date(Date.now() - 30 * 60 * 1000).toISOString();
const future = new Date(Date.now() + 10 * 60 * 1000).toISOString();

const ACTIVE_CRED: IssuedCredential = {
  id: "cred_abc",
  identity_id: "agt_abc123",
  account_id: "acct_test",
  project_id: "proj_test",
  jti: "jti_abc",
  subject: "wimse:agent:acct_test/proj_test/test",
  issued_at: past,
  expires_at: future,
  ttl_seconds: 900,
  scopes: ["repo:read", "pr:write"],
  is_revoked: false,
  grant_type: "api_key",
  delegation_depth: 0,
};

const REVOKED_CRED: IssuedCredential = {
  ...ACTIVE_CRED,
  id: "cred_xyz",
  is_revoked: true,
  revoked_at: now,
  revoke_reason: "manual",
};

const LIST_RESPONSE: CredentialListResponse = {
  credentials: [ACTIVE_CRED, REVOKED_CRED],
  total: 2,
};

describe("zeroid creds list", () => {
  it("GET /api/v1/credentials?identity_id=<agent> and renders table", async () => {
    let capturedUrl = "";
    server.use(
      http.get(`${BASE_URL}/api/v1/credentials`, ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json(LIST_RESPONSE);
      }),
    );

    const { stdout, exitCode } = await runCLI(["creds", "list", "--agent", "agt_abc123"]);

    expect(exitCode).toBeUndefined();
    expect(capturedUrl).toContain("identity_id=agt_abc123");
    const out = stdout.join("\n");
    expect(out).toContain("cred_abc");
    expect(out).toContain("active");
    expect(out).toContain("cred_xyz");
    expect(out).toContain("revoked");
  });

  it("--active filters out revoked credentials", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/credentials`, () => HttpResponse.json(LIST_RESPONSE)),
    );

    const { stdout } = await runCLI(["creds", "list", "--agent", "agt_abc123", "--active"]);
    const out = stdout.join("\n");
    expect(out).toContain("cred_abc");
    expect(out).not.toContain("cred_xyz");
    expect(out).toContain("1 credential(s)");
  });

  it("shows scopes in the table", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/credentials`, () => HttpResponse.json(LIST_RESPONSE)),
    );
    const { stdout } = await runCLI(["creds", "list", "--agent", "agt_abc123"]);
    expect(stdout.join("\n")).toContain("repo:read pr:write");
  });

  it("outputs raw JSON with --json", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/credentials`, () => HttpResponse.json(LIST_RESPONSE)),
    );
    const { stdout } = await runCLI(["creds", "list", "--agent", "agt_abc123", "--json"]);
    const parsed = JSON.parse(stdout.join("")) as IssuedCredential[];
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
    // SDK type contract: is_revoked field must exist
    expect(typeof parsed[0]?.is_revoked).toBe("boolean");
  });

  it("prints 'No credentials found' when list is empty", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({ credentials: [], total: 0 }),
      ),
    );
    const { stdout } = await runCLI(["creds", "list", "--agent", "agt_abc123"]);
    expect(stdout.join("")).toMatch(/no credentials/i);
  });

  it("normalizes null credentials to an empty array", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({ credentials: null, total: 0 }),
      ),
    );
    const { stdout } = await runCLI(["creds", "list", "--agent", "agt_abc123", "--json"]);
    expect(JSON.parse(stdout.join(""))).toEqual([]);
  });

  it("exits 1 when --agent is missing", async () => {
    const { exitCode } = await runCLI(["creds", "list"]);
    expect(exitCode).toBe(1);
  });

  it("exits 1 on API error", async () => {
    server.use(
      http.get(`${BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({ title: "Not Found" }, { status: 404 }),
      ),
    );
    const { exitCode } = await runCLI(["creds", "list", "--agent", "ghost"]);
    expect(exitCode).toBe(1);
  });
});
