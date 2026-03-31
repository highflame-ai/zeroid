/**
 * Tests for `zid token revoke`.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { runCLI, BASE_URL } from "../../helpers.js";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("zid token revoke", () => {
  it("posts token to /oauth2/token/revoke", async () => {
    let captured: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ revoked: true });
      }),
    );

    await runCLI(["token", "revoke", "eyJhbGc.test.sig"]);

    expect(captured["token"]).toBe("eyJhbGc.test.sig");
  });

  it("prints success message", async () => {
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, () => HttpResponse.json({ revoked: true })),
    );
    const { stdout } = await runCLI(["token", "revoke", "eyJhbGc.test.sig"]);
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
    await runCLI(["token", "revoke", "tok"]);
    expect(capturedHeaders.get("x-account-id")).toBeNull();
    expect(capturedHeaders.get("x-project-id")).toBeNull();
  });

  it("outputs raw JSON with --json", async () => {
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, () => HttpResponse.json({ revoked: true })),
    );
    const { stdout, exitCode } = await runCLI(["token", "revoke", "--json", "eyJhbGc.test.sig"]);
    expect(exitCode).toBeUndefined();
    const parsed = JSON.parse(stdout.join("")) as { revoked: boolean };
    expect(parsed.revoked).toBe(true);
  });

  it("exits 1 on API error", async () => {
    server.use(
      http.post(`${BASE_URL}/oauth2/token/revoke`, () =>
        HttpResponse.json({ title: "Not Found" }, { status: 404 }),
      ),
    );
    const { exitCode } = await runCLI(["token", "revoke", "bad.token"]);
    expect(exitCode).toBe(1);
  });
});
