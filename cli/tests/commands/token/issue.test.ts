/**
 * Tests for `zeroid token issue`.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { runCLI, BASE_URL } from "../../helpers.js";
import type { AccessToken } from "@highflame/sdk";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const TOKEN_RESPONSE: AccessToken = {
  access_token: "eyJhbGciOiJFUzI1NiJ9.test.sig",
  token_type: "Bearer",
  expires_in: 900,
  jti: "jti_abc",
  iat: Math.floor(Date.now() / 1000),
  account_id: "acct_test",
  project_id: "proj_test",
};

describe("zeroid token issue", () => {
  it("posts to /oauth2/token with api_key grant", async () => {
    let captured: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/oauth2/token`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(TOKEN_RESPONSE);
      }),
    );

    await runCLI(["token", "issue"]);

    expect(captured["grant_type"]).toBe("api_key");
    expect(captured["api_key"]).toBe("zid_sk_test");
  });

  it("includes scope when --scope is given", async () => {
    let captured: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/oauth2/token`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(TOKEN_RESPONSE);
      }),
    );

    await runCLI(["token", "issue", "--scope", "repo:read pr:write"]);

    expect(captured["scope"]).toBe("repo:read pr:write");
  });

  it("omits scope field when --scope is empty", async () => {
    let captured: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/oauth2/token`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(TOKEN_RESPONSE);
      }),
    );

    await runCLI(["token", "issue"]);

    expect(captured["scope"]).toBeUndefined();
  });

  it("prints access_token and expires_in", async () => {
    server.use(http.post(`${BASE_URL}/oauth2/token`, () => HttpResponse.json(TOKEN_RESPONSE)));
    const { stdout } = await runCLI(["token", "issue"]);
    const out = stdout.join("\n");
    expect(out).toContain(TOKEN_RESPONSE.access_token);
    expect(out).toContain("900s");
  });

  it("outputs raw JSON with --json", async () => {
    server.use(http.post(`${BASE_URL}/oauth2/token`, () => HttpResponse.json(TOKEN_RESPONSE)));
    const { stdout } = await runCLI(["token", "issue", "--json"]);
    const parsed = JSON.parse(stdout.join("")) as AccessToken;
    expect(parsed.access_token).toBe(TOKEN_RESPONSE.access_token);
    expect(parsed.expires_in).toBe(900);
  });

  it("exits 1 on API error", async () => {
    server.use(
      http.post(`${BASE_URL}/oauth2/token`, () =>
        HttpResponse.json({ error: "invalid_grant", error_description: "API key invalid" }, { status: 401 }),
      ),
    );
    const { exitCode, stderr } = await runCLI(["token", "issue"]);
    expect(exitCode).toBe(1);
    expect(stderr.join("")).toMatch(/invalid/i);
  });
});
