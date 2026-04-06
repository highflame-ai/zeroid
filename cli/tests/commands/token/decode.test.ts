/**
 * Tests for `zid token decode`.
 *
 * Pure local operation — no network calls, no msw needed.
 */

import { describe, expect, it } from "vitest";
import { runCLI, makeJWT } from "../../helpers.js";

describe("zid token decode", () => {
  it("decodes a valid JWT and prints key claims", async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJWT({
      sub: "wimse:agent:acct_test/proj_test/my-agent",
      identity_type: "agent",
      trust_level: "first_party",
      grant_type: "api_key",
      scopes: ["repo:read", "pr:write"],
      exp: now + 600,
    });

    const { stdout, exitCode } = await runCLI(["token", "decode", jwt]);

    expect(exitCode).toBeUndefined();
    expect(stdout.join("\n")).toContain("wimse:agent:acct_test/proj_test/my-agent");
    expect(stdout.join("\n")).toContain("agent");
    expect(stdout.join("\n")).toContain("first_party");
    expect(stdout.join("\n")).toContain("repo:read pr:write");
  });

  it("outputs raw JSON with --json flag", async () => {
    const jwt = makeJWT({ sub: "wimse:agent:acct/proj/x", scopes: ["read"] });
    const { stdout, exitCode } = await runCLI(["token", "decode", "--json", jwt]);

    expect(exitCode).toBeUndefined();
    const parsed = JSON.parse(stdout.join("")) as { header: unknown; payload: unknown };
    expect(parsed).toHaveProperty("header");
    expect(parsed).toHaveProperty("payload");
    expect((parsed.payload as Record<string, unknown>)["sub"]).toBe("wimse:agent:acct/proj/x");
  });

  it("shows alg and kid from header", async () => {
    const jwt = makeJWT({ alg: "RS256", kid: "rsa-key-2025" });
    const { stdout } = await runCLI(["token", "decode", jwt]);
    const out = stdout.join("\n");
    expect(out).toContain("RS256");
    expect(out).toContain("rsa-key-2025");
  });

  it("shows delegation info when act claim present", async () => {
    const jwt = makeJWT({
      delegation_depth: 1,
      act: { sub: "wimse:agent:acct_test/proj_test/orchestrator" },
    });
    const { stdout } = await runCLI(["token", "decode", jwt]);
    expect(stdout.join("\n")).toContain("orchestrator");
    expect(stdout.join("\n")).toContain("delegation_depth");
  });

  it("shows custom claims not in the known set", async () => {
    const jwt = makeJWT({ extra: { my_custom_claim: "hello" } });
    const { stdout } = await runCLI(["token", "decode", jwt]);
    expect(stdout.join("\n")).toContain("my_custom_claim");
    expect(stdout.join("\n")).toContain("hello");
  });

  it("marks expired tokens in the exp line", async () => {
    const past = Math.floor(Date.now() / 1000) - 300;
    const jwt = makeJWT({ exp: past });
    const { stdout, exitCode } = await runCLI(["token", "decode", jwt]);
    // decode does not exit 1 on expired — it just shows the claims
    expect(exitCode).toBeUndefined();
    expect(stdout.join("\n")).toContain("ago");
  });

  it("exits 1 on a token with wrong number of parts", async () => {
    const { exitCode, stderr } = await runCLI(["token", "decode", "only.two"]);
    expect(exitCode).toBe(1);
    expect(stderr.join("")).toMatch(/malformed/i);
  });

  it("exits 1 when payload is not valid base64url JSON", async () => {
    const { exitCode, stderr } = await runCLI(["token", "decode", "aGVhZA.!!!.c2ln"]);
    expect(exitCode).toBe(1);
    expect(stderr.join("")).toMatch(/SyntaxError|invalid|unexpected/i);
  });

  it("exits 1 with a helpful message when no jwt is provided in a tty", async () => {
    const original = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
    Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });

    try {
      const { exitCode, stderr } = await runCLI(["token", "decode"]);
      expect(exitCode).toBe(1);
      expect(stderr.join("")).toMatch(/pipe it to stdin/i);
    } finally {
      if (original) {
        Object.defineProperty(process.stdin, "isTTY", original);
      } else {
        delete (process.stdin as { isTTY?: boolean }).isTTY;
      }
    }
  });
});
