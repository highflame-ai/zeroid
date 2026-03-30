/**
 * Tests for `zid token verify`.
 *
 * Mocks `makeClient` directly so we control what `tokens.verify()` returns
 * without having to spread SDK internals or deal with real JWKS crypto.
 */

import { describe, expect, it, vi } from "vitest";
import { ZeroIDError } from "@highflame/sdk";
import { runCLI, makeJWT } from "../../helpers.js";

const VALID_IDENTITY = {
  sub: "wimse:agent:acct_test/proj_test/test-agent",
  iss: "http://zeroid.test",
  aud: ["http://zeroid.test"],
  iat: Math.floor(Date.now() / 1000) - 60,
  exp: Math.floor(Date.now() / 1000) + 840,
  jti: "jti_test",
  account_id: "acct_test",
  project_id: "proj_test",
  identity_type: "agent",
  trust_level: "first_party",
  scopes: ["repo:read"],
  hasScope: (s: string) => ["repo:read"].includes(s),
  hasTool: () => false,
  isDelegated: () => false,
  delegatedBy: () => undefined,
};

const DELEGATED_IDENTITY = {
  ...VALID_IDENTITY,
  isDelegated: () => true,
  delegatedBy: () => "wimse:agent:acct_test/proj_test/orchestrator",
};

// Mock makeClient so tests never touch the network or JWKS crypto.
vi.mock("../../../src/lib/client.js", () => ({
  makeClient: vi.fn(() => ({
    baseUrl: "http://zeroid.test",
    tokens: {
      verify: vi.fn(async (token: string) => {
        if (token === "expired.jwt.token") {
          throw new ZeroIDError("Token has expired", "token_expired");
        }
        if (token === "invalid.jwt.token") {
          throw new ZeroIDError("Invalid signature", "invalid_signature");
        }
        if (token === "delegated.jwt.token") {
          return DELEGATED_IDENTITY;
        }
        return VALID_IDENTITY;
      }),
    },
  })),
}));

describe("zid token verify — valid token", () => {
  it("exits 0 and prints identity details", async () => {
    const jwt = makeJWT();
    const { stdout, exitCode } = await runCLI(["token", "verify", jwt]);
    expect(exitCode).toBe(0);
    expect(stdout.join("\n")).toContain("valid");
    expect(stdout.join("\n")).toContain("acct_test");
    expect(stdout.join("\n")).toContain("first_party");
    expect(stdout.join("\n")).toContain("repo:read");
  });

  it("outputs raw JSON with --json", async () => {
    const jwt = makeJWT();
    const { stdout, exitCode } = await runCLI(["token", "verify", "--json", jwt]);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout.join("")) as Record<string, unknown>;
    expect(parsed["sub"]).toBe("wimse:agent:acct_test/proj_test/test-agent");
    expect(parsed["account_id"]).toBe("acct_test");
  });
});

describe("zid token verify — delegated token", () => {
  it("prints delegated_by when token carries act claim", async () => {
    const { stdout, exitCode } = await runCLI(["token", "verify", "delegated.jwt.token"]);
    expect(exitCode).toBe(0);
    expect(stdout.join("\n")).toContain("wimse:agent:acct_test/proj_test/orchestrator");
  });
});

describe("zid token verify — error paths", () => {
  it("exits 2 for an expired token", async () => {
    const { exitCode, stderr } = await runCLI(["token", "verify", "expired.jwt.token"]);
    expect(exitCode).toBe(2);
    expect(stderr.join("")).toMatch(/expired/i);
  });

  it("exits 1 for an invalid signature", async () => {
    const { exitCode, stderr } = await runCLI(["token", "verify", "invalid.jwt.token"]);
    expect(exitCode).toBe(1);
    expect(stderr.join("")).toMatch(/invalid/i);
  });
});
