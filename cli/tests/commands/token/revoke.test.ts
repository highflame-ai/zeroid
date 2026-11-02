/**
 * Tests for `zeroid token revoke`.
 *
 * RFC 7009 authenticates the client: the command requires client credentials
 * (flags or ZID_CLIENT_ID/ZID_CLIENT_SECRET) and posts them client_secret_post
 * style alongside the token.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { runCLI, BASE_URL } from "../../helpers.js";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const CREDS = ["--client-id", "cli-client", "--client-secret", "s3cret"];

describe("zeroid token revoke", () => {
  it("posts token and client credentials to /oauth2/token/revoke", async () => {
    let captured: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ revoked: true });
      }),
    );

    await runCLI(["token", "revoke", "eyJhbGc.test.sig", ...CREDS]);

    expect(captured["token"]).toBe("eyJhbGc.test.sig");
    expect(captured["client_id"]).toBe("cli-client");
    expect(captured["client_secret"]).toBe("s3cret");
  });

  it("reads client credentials from ZID_CLIENT_ID/ZID_CLIENT_SECRET", async () => {
    let captured: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ revoked: true });
      }),
    );

    const { exitCode } = await runCLI(["token", "revoke", "tok"], {
      ZID_CLIENT_ID: "env-client",
      ZID_CLIENT_SECRET: "env-secret",
    });

    expect(exitCode).toBeUndefined();
    expect(captured["client_id"]).toBe("env-client");
    expect(captured["client_secret"]).toBe("env-secret");
  });

  it("exits 1 with guidance when client credentials are missing", async () => {
    const { exitCode, stderr } = await runCLI(["token", "revoke", "tok"]);
    expect(exitCode).toBe(1);
    expect(stderr.join("")).toMatch(/client credentials/i);
    expect(stderr.join("")).toMatch(/agents deactivate/i);
  });

  it("prints success message", async () => {
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, () => HttpResponse.json({ revoked: true })),
    );
    const { stdout } = await runCLI(["token", "revoke", "eyJhbGc.test.sig", ...CREDS]);
    expect(stdout.join("")).toMatch(/revoked/i);
  });

  it("does not send tenant headers", async () => {
    let capturedHeaders = new Headers();
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, ({ request }) => {
        capturedHeaders = request.headers;
        return HttpResponse.json({ revoked: true });
      }),
    );
    await runCLI(["token", "revoke", "tok", ...CREDS]);
    expect(capturedHeaders.get("x-account-id")).toBeNull();
    expect(capturedHeaders.get("x-project-id")).toBeNull();
  });

  it("does not require ZID_API_KEY when only base url is configured", async () => {
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, () => HttpResponse.json({ revoked: true })),
    );
    const { exitCode } = await runCLI(
      ["token", "revoke", "eyJhbGc.test.sig", ...CREDS],
      { ZID_API_KEY: "", ZID_ACCOUNT_ID: "", ZID_PROJECT_ID: "" },
    );
    expect(exitCode).toBeUndefined();
  });

  it("outputs raw JSON with --json", async () => {
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, () => HttpResponse.json({ revoked: true })),
    );
    const { stdout, exitCode } = await runCLI([
      "token", "revoke", "--json", "eyJhbGc.test.sig", ...CREDS,
    ]);
    expect(exitCode).toBeUndefined();
    const parsed = JSON.parse(stdout.join("")) as { revoked: boolean };
    expect(parsed.revoked).toBe(true);
  });

  it("exits 1 on API error", async () => {
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, () =>
        HttpResponse.json({ title: "invalid_client" }, { status: 401 }),
      ),
    );
    const { exitCode } = await runCLI(["token", "revoke", "bad.token", ...CREDS]);
    expect(exitCode).toBe(1);
  });
});
