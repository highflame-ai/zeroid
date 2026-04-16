/**
 * Config management — reads/writes ~/.config/zid/config.json.
 * Supports named profiles; "default" is used when no --profile is given.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const DEFAULT_BASE_URL = "https://api.zeroid.io";

export interface ClientContext {
  base_url: string;
  /** Required for tenant-scoped operations (agents, creds, signals). */
  account_id?: string;
  /** Required for tenant-scoped operations (agents, creds, signals). */
  project_id?: string;
  api_key?: string;
  /** Optional identity metadata used for profile-aware UX flows. */
  identity_id?: string;
  external_id?: string;
  wimse_uri?: string;
}

export interface Profile extends ClientContext {
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
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
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
  const context = resolveContext(name);
  if (!context?.api_key) {
    throw new Error('No API key configured. Run "zid init" or set the ZID_API_KEY env var.');
  }
  return { ...context, api_key: context.api_key };
}

export function requireTenantContext(
  name?: string,
  command = "This command",
): ClientContext & { account_id: string; project_id: string } {
  const context = resolveContext(name);
  if (!context?.account_id || !context?.project_id) {
    throw new Error(
      `${command} requires tenant context. Set ZID_ACCOUNT_ID and ZID_PROJECT_ID, or use a profile created by "zid init".`,
    );
  }
  return {
    base_url: context.base_url,
    account_id: context.account_id,
    project_id: context.project_id,
    api_key: context.api_key,
  };
}

export function requireBaseURL(name?: string): string {
  return resolveContext(name)?.base_url ?? DEFAULT_BASE_URL;
}

export function getSelectedProfile(name?: string): { name: string; profile: Profile } | undefined {
  const cfg = _read();
  const key = name ?? cfg.active_profile;
  if (!key || !cfg.profiles[key]) {
    return undefined;
  }
  return { name: key, profile: cfg.profiles[key] };
}

export function updateProfileAPIKeyForIdentity(
  name: string | undefined,
  identityId: string,
  apiKey: string,
): string | undefined {
  const cfg = _read();
  const key = name ?? cfg.active_profile;
  if (!key) {
    return undefined;
  }

  const profile = cfg.profiles[key];
  if (!profile || profile.identity_id !== identityId) {
    return undefined;
  }

  cfg.profiles[key] = { ...profile, api_key: apiKey };
  _write(cfg);
  return key;
}

export function resolveContext(name?: string): ClientContext | undefined {
  const profile = getProfile(name);
  const env = contextFromEnv();

  if (!profile && !hasContext(env)) {
    return undefined;
  }

  return {
    base_url: env.base_url ?? profile?.base_url ?? DEFAULT_BASE_URL,
    account_id: env.account_id ?? profile?.account_id,
    project_id: env.project_id ?? profile?.project_id,
    api_key: env.api_key ?? profile?.api_key,
  };
}

function contextFromEnv(): Partial<ClientContext> {
  return {
    api_key: readEnv("ZID_API_KEY"),
    account_id: readEnv("ZID_ACCOUNT_ID"),
    project_id: readEnv("ZID_PROJECT_ID"),
    base_url: readEnv("ZID_BASE_URL"),
  };
}

function readEnv(name: string): string | undefined {
  const value = process.env[name];
  return value && value.trim() !== "" ? value : undefined;
}

function hasContext(context: Partial<ClientContext>): boolean {
  return Object.values(context).some((value) => value !== undefined);
}

/** Write api_key to .env.zeroid in the current working directory. */
export function writeEnvFile(apiKey: string): void {
  writeFileSync(join(process.cwd(), ".env.zeroid"), `ZID_API_KEY=${apiKey}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

export function writeEnvFileIfPresent(apiKey: string): boolean {
  const envPath = join(process.cwd(), ".env.zeroid");
  if (!existsSync(envPath)) {
    return false;
  }
  writeEnvFile(apiKey);
  return true;
}
