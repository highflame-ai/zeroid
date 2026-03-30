/**
 * Config management — reads/writes ~/.config/zid/config.json.
 * Supports named profiles; "default" is used when no --profile is given.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface Profile {
  base_url: string;
  account_id: string;
  project_id: string;
  api_key: string;
}

interface ConfigFile {
  active_profile: string;
  profiles: Record<string, Profile>;
}

const CONFIG_DIR = join(homedir(), ".config", "zid");
const CONFIG_PATH = join(CONFIG_DIR, "config.json");

function _read(): ConfigFile {
  if (!existsSync(CONFIG_PATH)) {
    return { active_profile: "", profiles: {} };
  }
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as ConfigFile;
  } catch {
    throw new Error(
      `Config file is corrupted (${CONFIG_PATH}). Delete it and run "zid init" to start fresh.`,
    );
  }
}

function _write(cfg: ConfigFile): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", "utf8");
}

export function getProfile(name?: string): Profile | undefined {
  const cfg = _read();
  const key = name ?? cfg.active_profile;
  return cfg.profiles[key];
}

export function setProfile(name: string, profile: Profile): void {
  const cfg = _read();
  cfg.profiles[name] = profile;
  // Auto-activate the first profile ever saved, or when the active profile has been deleted.
  if (!cfg.active_profile || !cfg.profiles[cfg.active_profile]) {
    cfg.active_profile = name;
  }
  _write(cfg);
}

export function useProfile(name: string): void {
  const cfg = _read();
  if (!cfg.profiles[name]) {
    throw new Error(`Profile "${name}" not found`);
  }
  cfg.active_profile = name;
  _write(cfg);
}

export function listProfiles(): { name: string; active: boolean }[] {
  const cfg = _read();
  return Object.keys(cfg.profiles).map((name) => ({
    name,
    active: name === cfg.active_profile,
  }));
}

export function requireProfile(name?: string): Profile {
  // Env vars take precedence over config file — useful in CI.
  const fromEnv = profileFromEnv();
  if (fromEnv) return fromEnv;

  const profile = getProfile(name);
  if (!profile) {
    throw new Error(
      'No profile configured. Run "zid init" or set ZID_API_KEY, ZID_ACCOUNT_ID, ZID_PROJECT_ID env vars.',
    );
  }
  return profile;
}

function profileFromEnv(): Profile | undefined {
  const api_key = process.env["ZID_API_KEY"];
  const account_id = process.env["ZID_ACCOUNT_ID"];
  const project_id = process.env["ZID_PROJECT_ID"];
  const base_url = process.env["ZID_BASE_URL"] ?? "https://api.zeroid.io";
  if (api_key && account_id && project_id) {
    return { api_key, account_id, project_id, base_url };
  }
  return undefined;
}

/** Write api_key to .env.zeroid in the current working directory. */
export function writeEnvFile(apiKey: string): void {
  writeFileSync(join(process.cwd(), ".env.zeroid"), `ZID_API_KEY=${apiKey}\n`, "utf8");
}
