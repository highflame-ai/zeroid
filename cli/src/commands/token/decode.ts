/**
 * zid token decode <jwt> — decode a JWT and display claims (no signature verification).
 *
 * Accepts the token as an argument or from stdin:
 *   zid token decode eyJhbGc...
 *   pbpaste | zid token decode
 */

import { Command } from "commander";
import chalk from "chalk";
import { handleError, printJSON } from "../../lib/output.js";

function _base64urlDecode(s: string): string {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const b64 = padded + "=".repeat((4 - (padded.length % 4)) % 4);
  return Buffer.from(b64, "base64").toString("utf8");
}

function _decodeJWT(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT: expected 3 parts");
  }
  return {
    header: JSON.parse(_base64urlDecode(parts[0]!)) as Record<string, unknown>,
    payload: JSON.parse(_base64urlDecode(parts[1]!)) as Record<string, unknown>,
  };
}

function _formatTime(epoch: unknown): string {
  if (typeof epoch !== "number") return String(epoch);
  const d = new Date(epoch * 1000);
  const now = Date.now() / 1000;
  const delta = epoch - now;
  const abs = Math.abs(delta);
  let rel: string;
  if (abs < 60) rel = `${Math.round(abs)}s`;
  else if (abs < 3600) rel = `${Math.round(abs / 60)}m`;
  else rel = `${Math.round(abs / 3600)}h`;
  const label = delta < 0 ? `${rel} ago` : `in ${rel}`;
  return `${d.toISOString()} (${label})`;
}

export function registerDecode(tokenCmd: Command): void {
  tokenCmd
    .command("decode [jwt]")
    .description("Decode a JWT and display its claims (no signature check)")
    .option("--json", "Output raw JSON")
    .action(async (jwt: string | undefined, opts) => {
      try {
        let token = jwt;
        if (!token) {
          // Read from stdin if no argument given.
          const chunks: Buffer[] = [];
          for await (const chunk of process.stdin) {
            chunks.push(chunk as Buffer);
          }
          token = Buffer.concat(chunks).toString("utf8").trim();
        }
        if (!token) throw new Error("No JWT provided");

        const { header, payload } = _decodeJWT(token);

        if (opts.json) {
          printJSON({ header, payload });
          return;
        }

        console.log(chalk.bold("\nHeader"));
        console.log(`  alg:  ${header["alg"] ?? "-"}`);
        console.log(`  kid:  ${header["kid"] ?? "-"}`);

        console.log(chalk.bold("\nPayload"));
        const str = (k: string) => (typeof payload[k] === "string" ? (payload[k] as string) : "-");
        const num = (k: string) => (typeof payload[k] === "number" ? (payload[k] as number) : undefined);

        console.log(`  sub:              ${str("sub")}`);
        console.log(`  iss:              ${str("iss")}`);
        console.log(`  jti:              ${str("jti")}`);
        console.log(`  account_id:       ${str("account_id")}`);
        console.log(`  project_id:       ${str("project_id")}`);
        console.log(`  identity_type:    ${str("identity_type")}`);
        console.log(`  trust_level:      ${str("trust_level")}`);
        console.log(`  grant_type:       ${str("grant_type")}`);

        const iat = num("iat");
        const exp = num("exp");
        if (iat !== undefined) console.log(`  iat:              ${_formatTime(iat)}`);
        if (exp !== undefined) {
          const expired = exp < Date.now() / 1000;
          const label = _formatTime(exp);
          console.log(`  exp:              ${expired ? chalk.red(label) : chalk.green(label)}`);
        }

        const scopes = Array.isArray(payload["scopes"]) ? (payload["scopes"] as string[]).join(" ") : str("scopes");
        if (scopes && scopes !== "-") console.log(`  scopes:           ${scopes}`);

        const depth = num("delegation_depth");
        if (depth !== undefined) console.log(`  delegation_depth: ${depth}`);

        if (payload["act"] && typeof payload["act"] === "object") {
          const act = payload["act"] as Record<string, unknown>;
          console.log(`  act.sub:          ${act["sub"] ?? "-"}`);
        }

        // Print any extra claims not shown above.
        const known = new Set(["sub","iss","aud","iat","exp","nbf","jti","account_id","project_id",
          "identity_type","trust_level","grant_type","scopes","delegation_depth","act",
          "external_id","sub_type","status","name","owner_user_id","framework","version",
          "publisher","capabilities","session_id","task_id","task_type","allowed_tools",
          "workspace","environment"]);
        const extra = Object.entries(payload).filter(([k]) => !known.has(k));
        if (extra.length > 0) {
          console.log(chalk.bold("\nCustom claims"));
          for (const [k, v] of extra) {
            console.log(`  ${k}: ${JSON.stringify(v)}`);
          }
        }
        console.log();
      } catch (err) {
        handleError(err);
      }
    });
}
