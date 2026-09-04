/**
 * Tests for `zeroid config use-profile` and `zeroid config list-profiles`.
 *
 * Isolation: each test gets a fresh ZID_CONFIG_DIR (the same knob production
 * code honors), so the direct setProfile() writes and the CLI reads land on
 * the same throwaway config file — no homedir mocking.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCLI } from "../helpers.js";
import { setProfile } from "../../src/lib/config.js";

let configDir: string;
let savedConfigDir: string | undefined;

beforeEach(() => {
  savedConfigDir = process.env.ZID_CONFIG_DIR;
  configDir = mkdtempSync(join(tmpdir(), "zeroid-config-cmd-test-"));
  process.env.ZID_CONFIG_DIR = configDir;
});

afterEach(() => {
  rmSync(configDir, { recursive: true, force: true });
  if (savedConfigDir === undefined) {
    delete process.env.ZID_CONFIG_DIR;
  } else {
    process.env.ZID_CONFIG_DIR = savedConfigDir;
  }
});

describe("zeroid config list-profiles", () => {
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

describe("zeroid config use-profile", () => {
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
