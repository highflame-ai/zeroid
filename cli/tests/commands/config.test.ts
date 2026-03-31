/**
 * Tests for `zid config use-profile` and `zid config list-profiles`.
 *
 * Uses a temp HOME dir so reads/writes don't touch the real config file.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { runCLI } from "../helpers.js";

const TEST_HOME = vi.hoisted(
  () => `${process.env.TMPDIR ?? process.env.TEMP ?? "/tmp"}zid-config-cmd-test-${process.pid}`,
);
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: () => TEST_HOME };
});

// Import config functions after mock is in place so they use TEST_HOME.
const { setProfile } = await import("../../src/lib/config.js");

beforeEach(() => {
  mkdirSync(join(TEST_HOME, ".config", "zid"), { recursive: true });
});

afterEach(() => {
  rmSync(TEST_HOME, { recursive: true, force: true });
});

describe("zid config list-profiles", () => {
  it("prints a message when no profiles are configured", async () => {
    const { stdout } = await runCLI(["config", "list-profiles"], {
      // Clear auth env so it doesn't mask the empty config
      ZID_API_KEY: "",
    });
    expect(stdout.join("")).toMatch(/no profiles/i);
  });

  it("lists configured profiles and marks the active one", async () => {
    setProfile("dev", { base_url: "http://dev", account_id: "a", project_id: "p", api_key: "k1" });
    setProfile("prod", { base_url: "http://prod", account_id: "a", project_id: "p", api_key: "k2" });

    const { stdout } = await runCLI(["config", "list-profiles"]);
    const out = stdout.join("\n");
    expect(out).toContain("dev");
    expect(out).toContain("prod");
    // First profile saved is auto-activated
    expect(out).toContain("* dev");
  });
});

describe("zid config use-profile", () => {
  it("switches the active profile and prints confirmation", async () => {
    setProfile("dev", { base_url: "http://dev", account_id: "a", project_id: "p", api_key: "k1" });
    setProfile("prod", { base_url: "http://prod", account_id: "a", project_id: "p", api_key: "k2" });

    const { stdout, exitCode } = await runCLI(["config", "use-profile", "prod"]);
    expect(exitCode).toBeUndefined();
    expect(stdout.join("")).toContain("prod");

    // Verify it's now active by listing
    const { stdout: list } = await runCLI(["config", "list-profiles"]);
    expect(list.join("\n")).toContain("* prod");
  });

  it("exits 1 when the profile does not exist", async () => {
    const { exitCode, stderr } = await runCLI(["config", "use-profile", "ghost"]);
    expect(exitCode).toBe(1);
    expect(stderr.join("")).toMatch(/not found/i);
  });
});
