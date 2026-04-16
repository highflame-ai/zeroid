/**
 * Unit tests for lib/config.ts
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// vi.hoisted ensures TEST_HOME is defined before vi.mock factories run.
const TEST_HOME = vi.hoisted(
  () => `${process.env.TMPDIR ?? process.env.TEMP ?? "/tmp"}zeroid-config-test-${process.pid}`,
);

// Must mock before importing config (it resolves HOME at module load time).
// Use importOriginal to keep tmpdir and other exports from node:os intact.
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: () => TEST_HOME };
});

const {
  getProfile,
  setProfile,
  useProfile,
  listProfiles,
  requireBaseURL,
  requireProfile,
  requireTenantContext,
  resolveContext,
  getSelectedProfile,
  writeEnvFile,
  writeEnvFileIfPresent,
  updateProfileAPIKeyForIdentity,
} = await import("../../src/lib/config.js");

beforeEach(() => {
  mkdirSync(join(TEST_HOME, ".config", "zeroid"), { recursive: true });
  delete process.env["ZID_API_KEY"];
  delete process.env["ZID_ACCOUNT_ID"];
  delete process.env["ZID_PROJECT_ID"];
  delete process.env["ZID_BASE_URL"];
});

afterEach(() => {
  rmSync(TEST_HOME, { recursive: true, force: true });
});

describe("getProfile / setProfile", () => {
  it("returns undefined when no profile exists", () => {
    expect(getProfile("default")).toBeUndefined();
  });

  it("persists and retrieves a profile", () => {
    const p = { base_url: "http://localhost", account_id: "a", project_id: "p", api_key: "k" };
    setProfile("default", p);
    expect(getProfile("default")).toEqual(p);
  });

  it("auto-activates the first profile saved", () => {
    setProfile("staging", { base_url: "http://staging", account_id: "a", project_id: "p", api_key: "k" });
    // requireProfile() with no args should resolve to the auto-activated profile
    const active = requireProfile();
    expect(active.base_url).toBe("http://staging");
  });

  it("does not change the active profile when a second profile is added", () => {
    setProfile("dev", { base_url: "http://dev", account_id: "a", project_id: "p", api_key: "k1" });
    setProfile("prod", { base_url: "http://prod", account_id: "a", project_id: "p", api_key: "k2" });
    // dev was first, so it stays active
    expect(requireProfile().base_url).toBe("http://dev");
  });

  it("can store multiple named profiles", () => {
    setProfile("dev", { base_url: "http://dev", account_id: "a", project_id: "p", api_key: "k1" });
    setProfile("prod", { base_url: "http://prod", account_id: "a", project_id: "p", api_key: "k2" });
    expect(getProfile("dev")?.api_key).toBe("k1");
    expect(getProfile("prod")?.api_key).toBe("k2");
  });

  it("overwrites an existing profile", () => {
    setProfile("default", { base_url: "http://old", account_id: "a", project_id: "p", api_key: "old" });
    setProfile("default", { base_url: "http://new", account_id: "a", project_id: "p", api_key: "new" });
    expect(getProfile("default")?.api_key).toBe("new");
  });

  it("returns the selected saved profile", () => {
    setProfile("default", {
      base_url: "http://localhost",
      account_id: "a",
      project_id: "p",
      api_key: "k",
      identity_id: "agt_123",
    });
    expect(getSelectedProfile()).toEqual({
      name: "default",
      profile: {
        base_url: "http://localhost",
        account_id: "a",
        project_id: "p",
        api_key: "k",
        identity_id: "agt_123",
      },
    });
  });

  it("reads a legacy ~/.config/zid/config.json when the new path is absent", () => {
    const legacyDir = join(TEST_HOME, ".config", "zid");
    mkdirSync(legacyDir, { recursive: true });
    writeFileSync(
      join(legacyDir, "config.json"),
      JSON.stringify(
        {
          active_profile: "legacy",
          profiles: {
            legacy: {
              base_url: "http://legacy",
              account_id: "acct_legacy",
              project_id: "proj_legacy",
              api_key: "legacy_key",
            },
          },
        },
        null,
        2,
      ),
    );

    expect(getProfile()).toEqual({
      base_url: "http://legacy",
      account_id: "acct_legacy",
      project_id: "proj_legacy",
      api_key: "legacy_key",
    });
  });
});

describe("useProfile", () => {
  it("switches the active profile", () => {
    setProfile("dev", { base_url: "http://dev", account_id: "a", project_id: "p", api_key: "k" });
    setProfile("prod", { base_url: "http://prod", account_id: "a", project_id: "p", api_key: "k" });
    useProfile("prod");
    expect(requireProfile().base_url).toBe("http://prod");
  });

  it("throws if profile does not exist", () => {
    expect(() => useProfile("ghost")).toThrow(/not found/i);
  });
});

describe("listProfiles", () => {
  it("returns empty when no profiles configured", () => {
    expect(listProfiles()).toEqual([]);
  });

  it("marks the active profile", () => {
    setProfile("dev", { base_url: "http://dev", account_id: "a", project_id: "p", api_key: "k" });
    setProfile("prod", { base_url: "http://prod", account_id: "a", project_id: "p", api_key: "k" });
    useProfile("prod");
    const list = listProfiles();
    expect(list.find((p) => p.name === "prod")?.active).toBe(true);
    expect(list.find((p) => p.name === "dev")?.active).toBe(false);
  });
});

describe("requireProfile", () => {
  it("reads from env vars when set", () => {
    process.env["ZID_API_KEY"] = "env_key";
    process.env["ZID_ACCOUNT_ID"] = "env_acct";
    process.env["ZID_PROJECT_ID"] = "env_proj";
    const p = requireProfile();
    expect(p.api_key).toBe("env_key");
    expect(p.account_id).toBe("env_acct");
    expect(p.project_id).toBe("env_proj");
    expect(p.base_url).toBe("https://api.zeroid.io");
  });

  it("works with only ZID_API_KEY — account/project are optional", () => {
    process.env["ZID_API_KEY"] = "env_key";
    const p = requireProfile();
    expect(p.api_key).toBe("env_key");
    expect(p.account_id).toBeUndefined();
    expect(p.project_id).toBeUndefined();
  });

  it("uses ZID_BASE_URL env var when set", () => {
    process.env["ZID_API_KEY"] = "k";
    process.env["ZID_BASE_URL"] = "http://custom";
    expect(requireProfile().base_url).toBe("http://custom");
  });

  it("env vars take precedence over config file", () => {
    setProfile("default", { base_url: "http://file", account_id: "a", project_id: "p", api_key: "file_key" });
    process.env["ZID_API_KEY"] = "env_key";
    expect(requireProfile().api_key).toBe("env_key");
  });

  it("throws a helpful error when nothing is configured", () => {
    expect(() => requireProfile()).toThrow(/zeroid init/i);
  });
});

describe("resolveContext / requireTenantContext / requireBaseURL", () => {
  it("merges env vars over the saved profile", () => {
    setProfile("default", {
      base_url: "http://file",
      account_id: "acct_file",
      project_id: "proj_file",
      api_key: "file_key",
    });
    process.env["ZID_BASE_URL"] = "http://env";
    process.env["ZID_ACCOUNT_ID"] = "acct_env";

    expect(resolveContext()).toEqual({
      base_url: "http://env",
      account_id: "acct_env",
      project_id: "proj_file",
      api_key: "file_key",
    });
  });

  it("requires tenant context even when no api key is present", () => {
    process.env["ZID_ACCOUNT_ID"] = "acct_env";
    process.env["ZID_PROJECT_ID"] = "proj_env";

    expect(requireTenantContext(undefined, "zeroid init")).toEqual({
      base_url: "https://api.zeroid.io",
      account_id: "acct_env",
      project_id: "proj_env",
      api_key: undefined,
    });
  });

  it("throws a helpful error when tenant context is missing", () => {
    expect(() => requireTenantContext(undefined, "zeroid agents list")).toThrow(/tenant context/i);
  });

  it("falls back to the default base url when nothing is configured", () => {
    expect(requireBaseURL()).toBe("https://api.zeroid.io");
  });
});

describe("writeEnvFile", () => {
  it("writes ZID_API_KEY to .env.zeroid in cwd", async () => {
    const envPath = join(process.cwd(), ".env.zeroid");
    try {
      writeEnvFile("zid_sk_test123");
      const { readFileSync } = await import("node:fs");
      const contents = readFileSync(envPath, "utf8");
      expect(contents).toBe("ZID_API_KEY=zid_sk_test123\n");
      expect(statSync(envPath).mode & 0o777).toBe(0o600);
    } finally {
      rmSync(envPath, { force: true });
    }
  });
});

describe("updateProfileAPIKeyForIdentity", () => {
  it("updates the matching saved profile", () => {
    setProfile("default", {
      base_url: "http://localhost",
      account_id: "a",
      project_id: "p",
      api_key: "old",
      identity_id: "agt_123",
    });

    const updated = updateProfileAPIKeyForIdentity(undefined, "agt_123", "new");
    expect(updated).toBe("default");
    expect(getProfile("default")?.api_key).toBe("new");
  });

  it("does not update when the identity does not match", () => {
    setProfile("default", {
      base_url: "http://localhost",
      account_id: "a",
      project_id: "p",
      api_key: "old",
      identity_id: "agt_123",
    });

    const updated = updateProfileAPIKeyForIdentity(undefined, "agt_999", "new");
    expect(updated).toBeUndefined();
    expect(getProfile("default")?.api_key).toBe("old");
  });
});

describe("writeEnvFileIfPresent", () => {
  it("does nothing when .env.zeroid is absent", () => {
    expect(writeEnvFileIfPresent("zid_sk_new")).toBe(false);
  });

  it("updates .env.zeroid when the file already exists", async () => {
    const envPath = join(process.cwd(), ".env.zeroid");
    try {
      writeEnvFile("zid_sk_old");
      expect(writeEnvFileIfPresent("zid_sk_new")).toBe(true);
      const { readFileSync } = await import("node:fs");
      expect(readFileSync(envPath, "utf8")).toBe("ZID_API_KEY=zid_sk_new\n");
    } finally {
      rmSync(envPath, { force: true });
    }
  });
});
