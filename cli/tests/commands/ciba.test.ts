/**
 * Tests for `zeroid ciba` subcommands.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { runCLI, BASE_URL } from "../helpers.js";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const INIT_RESPONSE = {
  auth_req_id: "ari_test_123",
  expires_in: 300,
  interval: 5,
};

const TOKEN_RESPONSE = {
  access_token: "eyJhbGciOiJSUzI1NiJ9.ciba.sig",
  token_type: "Bearer",
  expires_in: 900,
  jti: "jti_ciba_123",
  iat: Math.floor(Date.now() / 1000),
  account_id: "acct_test",
  project_id: "proj_test",
};

describe("zeroid ciba init", () => {
  it("posts to /oauth2/bc-authorize with tenant fields in the body", async () => {
    let captured: Record<string, unknown> = {};
    let accountHeader: string | null = "";

    server.use(
      http.post(`${BASE_URL}/oauth2/bc-authorize`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        accountHeader = request.headers.get("x-account-id");
        return HttpResponse.json(INIT_RESPONSE);
      }),
    );

    const { stdout, exitCode } = await runCLI([
      "ciba",
      "init",
      "--client-id",
      "my-ciba-client",
      "--login-hint",
      "user@example.com",
      "--scope",
      "openid profile",
      "--binding-message",
      "Approve login?",
      "--requested-expiry",
      "600",
      "--client-notification-token",
      "opaque-token",
    ]);

    expect(exitCode).toBeUndefined();
    expect(captured["client_id"]).toBe("my-ciba-client");
    expect(captured["account_id"]).toBe("acct_test");
    expect(captured["project_id"]).toBe("proj_test");
    expect(captured["login_hint"]).toBe("user@example.com");
    expect(captured["scope"]).toBe("openid profile");
    expect(captured["binding_message"]).toBe("Approve login?");
    expect(captured["requested_expiry"]).toBe(600);
    expect(captured["client_notification_token"]).toBe("opaque-token");
    expect(accountHeader).toBeNull();
    expect(stdout.join("\n")).toContain("ari_test_123");
  });

  it("outputs raw JSON with --json", async () => {
    server.use(http.post(`${BASE_URL}/oauth2/bc-authorize`, () => HttpResponse.json(INIT_RESPONSE)));

    const { stdout } = await runCLI([
      "ciba",
      "init",
      "--client-id",
      "my-ciba-client",
      "--login-hint",
      "user@example.com",
      "--json",
    ]);

    expect(JSON.parse(stdout.join(""))).toEqual(INIT_RESPONSE);
  });
});

describe("zeroid ciba approve", () => {
  it("posts approval details with tenant headers", async () => {
    let captured: Record<string, unknown> = {};
    let accountHeader = "";
    let projectHeader = "";

    server.use(
      http.post(`${BASE_URL}/api/v1/oauth2/bc-authorize/ari_test_123/approve`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        accountHeader = request.headers.get("x-account-id") ?? "";
        projectHeader = request.headers.get("x-project-id") ?? "";
        return HttpResponse.json({ auth_req_id: "ari_test_123", status: "approved" });
      }),
    );

    const { stdout, exitCode } = await runCLI([
      "ciba",
      "approve",
      "ari_test_123",
      "--subject-id",
      "user@example.com",
      "--subject-email",
      "user@example.com",
      "--subject-name",
      "Alice User",
    ]);

    expect(exitCode).toBeUndefined();
    expect(accountHeader).toBe("acct_test");
    expect(projectHeader).toBe("proj_test");
    expect(captured["subject_id"]).toBe("user@example.com");
    expect(captured["subject_email"]).toBe("user@example.com");
    expect(captured["subject_name"]).toBe("Alice User");
    expect(stdout.join("")).toMatch(/approved/i);
  });

  it("supports AuthN-mounted approval routes with internal service headers", async () => {
    let captured: Record<string, unknown> = {};
    let accountHeader = "";
    let projectHeader = "";
    let internalServiceHeader = "";
    let internalSecretHeader = "";

    server.use(
      http.post(`${BASE_URL}/oauth2/bc-authorize/ari_test_123/approve`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        accountHeader = request.headers.get("x-account-id") ?? "";
        projectHeader = request.headers.get("x-project-id") ?? "";
        internalServiceHeader = request.headers.get("x-internal-service") ?? "";
        internalSecretHeader = request.headers.get("x-internal-service-secret") ?? "";
        return HttpResponse.json({ auth_req_id: "ari_test_123", status: "approved" });
      }),
    );

    const { stdout, exitCode } = await runCLI([
      "ciba",
      "approve",
      "ari_test_123",
      "--subject-id",
      "user@example.com",
      "--admin-prefix",
      "",
      "--internal-service",
      "highflame-admin",
      "--internal-service-secret",
      "dev-secret",
    ]);

    expect(exitCode).toBeUndefined();
    expect(accountHeader).toBe("acct_test");
    expect(projectHeader).toBe("proj_test");
    expect(internalServiceHeader).toBe("highflame-admin");
    expect(internalSecretHeader).toBe("dev-secret");
    expect(captured["subject_id"]).toBe("user@example.com");
    expect(stdout.join("")).toMatch(/approved/i);
  });
});

describe("zeroid ciba deny", () => {
  it("posts denial with tenant headers and optional reason", async () => {
    let captured: Record<string, unknown> = {};
    let accountHeader = "";

    server.use(
      http.post(`${BASE_URL}/api/v1/oauth2/bc-authorize/ari_test_123/deny`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        accountHeader = request.headers.get("x-account-id") ?? "";
        return HttpResponse.json({ auth_req_id: "ari_test_123", status: "denied" });
      }),
    );

    const { stdout, exitCode } = await runCLI([
      "ciba",
      "deny",
      "ari_test_123",
      "--reason",
      "user rejected",
    ]);

    expect(exitCode).toBeUndefined();
    expect(accountHeader).toBe("acct_test");
    expect(captured["reason"]).toBe("user rejected");
    expect(stdout.join("")).toMatch(/denied/i);
  });

  it("honors admin prefix and internal service headers from env", async () => {
    let accountHeader = "";
    let projectHeader = "";
    let internalServiceHeader = "";
    let internalSecretHeader = "";

    server.use(
      http.post(`${BASE_URL}/oauth2/bc-authorize/ari_test_123/deny`, async ({ request }) => {
        accountHeader = request.headers.get("x-account-id") ?? "";
        projectHeader = request.headers.get("x-project-id") ?? "";
        internalServiceHeader = request.headers.get("x-internal-service") ?? "";
        internalSecretHeader = request.headers.get("x-internal-service-secret") ?? "";
        return HttpResponse.json({ auth_req_id: "ari_test_123", status: "denied" });
      }),
    );

    const { stdout, exitCode } = await runCLI(
      [
        "ciba",
        "deny",
        "ari_test_123",
        "--reason",
        "user rejected",
      ],
      {
        ZID_ADMIN_PREFIX: "",
        ZID_INTERNAL_SERVICE: "highflame-admin",
        ZID_INTERNAL_SERVICE_SECRET: "dev-secret",
      },
    );

    expect(exitCode).toBeUndefined();
    expect(accountHeader).toBe("acct_test");
    expect(projectHeader).toBe("proj_test");
    expect(internalServiceHeader).toBe("highflame-admin");
    expect(internalSecretHeader).toBe("dev-secret");
    expect(stdout.join("")).toMatch(/denied/i);
  });
});

describe("zeroid ciba poll", () => {
  it("posts the CIBA grant to /oauth2/token and prints the token", async () => {
    let captured: Record<string, unknown> = {};

    server.use(
      http.post(`${BASE_URL}/oauth2/token`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(TOKEN_RESPONSE);
      }),
    );

    const { stdout, exitCode } = await runCLI([
      "ciba",
      "poll",
      "ari_test_123",
      "--client-id",
      "my-ciba-client",
    ]);

    expect(exitCode).toBeUndefined();
    expect(captured["grant_type"]).toBe("urn:openid:params:grant-type:ciba");
    expect(captured["auth_req_id"]).toBe("ari_test_123");
    expect(captured["client_id"]).toBe("my-ciba-client");
    expect(stdout.join("\n")).toContain(TOKEN_RESPONSE.access_token);
  });

  it("prints OAuth polling errors as JSON and exits 1", async () => {
    server.use(
      http.post(`${BASE_URL}/oauth2/token`, () =>
        HttpResponse.json(
          {
            error: "authorization_pending",
            error_description: "the user has not yet acted",
          },
          { status: 400 },
        ),
      ),
    );

    const { stdout, exitCode } = await runCLI([
      "ciba",
      "poll",
      "ari_test_123",
      "--client-id",
      "my-ciba-client",
      "--json",
    ]);

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(stdout.join(""));
    expect(parsed.error).toBe("authorization_pending");
  });

  it("with --watch keeps polling through authorization_pending", async () => {
    let attempts = 0;

    server.use(
      http.post(`${BASE_URL}/oauth2/token`, () => {
        attempts += 1;
        if (attempts === 1) {
          return HttpResponse.json(
            {
              error: "authorization_pending",
              error_description: "the user has not yet acted",
            },
            { status: 400 },
          );
        }
        return HttpResponse.json(TOKEN_RESPONSE);
      }),
    );

    const { stdout, exitCode } = await runCLI([
      "ciba",
      "poll",
      "ari_test_123",
      "--client-id",
      "my-ciba-client",
      "--watch",
      "--interval",
      "0",
    ]);

    expect(exitCode).toBeUndefined();
    expect(attempts).toBe(2);
    expect(stdout.join("\n")).toContain(TOKEN_RESPONSE.access_token);
  });
});
