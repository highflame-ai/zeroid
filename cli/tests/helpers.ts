/**
 * Shared test helpers.
 *
 * - `makeProgram()` — fresh Commander program with all commands registered
 * - `runCLI()` — run a command and capture stdout/stderr without process.exit
 * - `AUTH_ENV` — env vars that satisfy requireProfile() in tests
 */

import { vi } from "vitest";
import { Command } from "commander";

import { registerInit } from "../src/commands/init.js";
import { registerDecode } from "../src/commands/token/decode.js";
import { registerVerify } from "../src/commands/token/verify.js";
import { registerIssue } from "../src/commands/token/issue.js";
import { registerTokenRevoke } from "../src/commands/token/revoke.js";
import { registerList } from "../src/commands/agents/list.js";
import { registerGet } from "../src/commands/agents/get.js";
import { registerRotateKey } from "../src/commands/agents/rotate-key.js";
import { registerDeactivate } from "../src/commands/agents/deactivate.js";
import { registerCredsList } from "../src/commands/creds/list.js";
import { registerSignal } from "../src/commands/signal.js";
import { registerConfig } from "../src/commands/config.js";

export const BASE_URL = "http://zeroid.test";

/** Env vars that satisfy requireProfile() without a config file. */
export const AUTH_ENV = {
  ZID_API_KEY: "zid_sk_test",
  ZID_ACCOUNT_ID: "acct_test",
  ZID_PROJECT_ID: "proj_test",
  ZID_BASE_URL: BASE_URL,
};

/** Result of running a CLI command in test. */
export interface RunResult {
  stdout: string[];
  stderr: string[];
  exitCode: number | undefined;
}

/** Build a fresh Commander program with every command registered. */
export function makeProgram(): Command {
  const program = new Command();
  program.name("zeroid").exitOverride(); // throws instead of process.exit on parse errors

  registerInit(program);
  registerSignal(program);
  registerConfig(program);

  const tokenCmd = program.command("token");
  registerIssue(tokenCmd);
  registerDecode(tokenCmd);
  registerVerify(tokenCmd);
  registerTokenRevoke(tokenCmd);

  const agentsCmd = program.command("agents");
  registerList(agentsCmd);
  registerGet(agentsCmd);
  registerRotateKey(agentsCmd);
  registerDeactivate(agentsCmd);

  const credsCmd = program.command("creds");
  registerCredsList(credsCmd);

  return program;
}

/**
 * Run a CLI command, capturing all output and the exit code.
 *
 * Sets AUTH_ENV automatically so requireProfile() is always satisfied.
 * Does NOT call process.exit — instead records the exit code.
 */
export async function runCLI(
  args: string[],
  extraEnv: Record<string, string> = {},
): Promise<RunResult> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  let exitCode: number | undefined;

  const logSpy = vi.spyOn(console, "log").mockImplementation((...a) => {
    stdout.push(a.map(String).join(" "));
  });
  const warnSpy = vi.spyOn(console, "warn").mockImplementation((...a) => {
    stderr.push(a.map(String).join(" "));
  });
  const errorSpy = vi.spyOn(console, "error").mockImplementation((...a) => {
    stderr.push(a.map(String).join(" "));
  });
  const exitSpy = vi.spyOn(process, "exit").mockImplementation((code?: number | string | null) => {
    exitCode = typeof code === "number" ? code : 0;
    throw new ExitError(exitCode);
  });

  // Save only the keys we are about to modify, then restore them individually
  // to avoid replacing the process.env object reference (which Node does not support).
  const keysToModify = Object.keys({ ...AUTH_ENV, ...extraEnv });
  const savedValues: Record<string, string | undefined> = {};
  for (const key of keysToModify) {
    savedValues[key] = process.env[key];
  }
  Object.assign(process.env, AUTH_ENV, extraEnv);

  const program = makeProgram();
  try {
    await program.parseAsync(["node", "zeroid", ...args]);
  } catch (err) {
    if (!(err instanceof ExitError)) {
      // Commander parse errors (missing required args etc.) throw CommanderError.
      stderr.push(err instanceof Error ? err.message : String(err));
      exitCode = 1;
    }
  } finally {
    for (const [key, value] of Object.entries(savedValues)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    logSpy.mockRestore();
    warnSpy.mockRestore();
    errorSpy.mockRestore();
    exitSpy.mockRestore();
  }

  return { stdout, stderr, exitCode };
}

/** Sentinel thrown by the mocked process.exit to stop execution. */
class ExitError extends Error {
  constructor(public readonly code: number) {
    super(`process.exit(${code})`);
  }
}

// ---------------------------------------------------------------------------
// JWT helpers — craft minimal unsigned JWTs for decode tests
// ---------------------------------------------------------------------------

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export interface FakeJWTOptions {
  sub?: string;
  iss?: string;
  exp?: number; // unix seconds
  iat?: number;
  account_id?: string;
  project_id?: string;
  identity_type?: string;
  trust_level?: string;
  grant_type?: string;
  scopes?: string[];
  delegation_depth?: number;
  act?: { sub: string; iss?: string };
  extra?: Record<string, unknown>;
  alg?: string;
  kid?: string;
}

/** Build a base64url-encoded JWT with a fake signature (for decode tests only). */
export function makeJWT(opts: FakeJWTOptions = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: opts.alg ?? "ES256", kid: opts.kid ?? "test-key-1" };
  const payload = {
    sub: opts.sub ?? "wimse:agent:acct_test/proj_test/test-agent",
    iss: opts.iss ?? BASE_URL,
    iat: opts.iat ?? now - 60,
    exp: opts.exp ?? now + 840,
    jti: "jti_test_abc",
    account_id: opts.account_id ?? "acct_test",
    project_id: opts.project_id ?? "proj_test",
    identity_type: opts.identity_type ?? "agent",
    trust_level: opts.trust_level ?? "first_party",
    grant_type: opts.grant_type ?? "api_key",
    ...(opts.scopes ? { scopes: opts.scopes } : {}),
    ...(opts.delegation_depth !== undefined ? { delegation_depth: opts.delegation_depth } : {}),
    ...(opts.act ? { act: opts.act } : {}),
    ...opts.extra,
  };
  return `${b64url(header)}.${b64url(payload)}.fakesig`;
}
