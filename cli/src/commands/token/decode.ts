/**
 * zid token decode <jwt> — decode a JWT and display claims (no signature verification).
 *
 * Accepts the token as an argument or from stdin:
 *   zid token decode eyJhbGc...
 *   pbpaste | zid token decode
 */

import { Command } from "commander";
import chalk from "chalk";
import { handleError, printJSON, relativeTime } from "../../lib/output.js";

function _base64urlDecode(s: string): string {
  return Buffer.from(s, "base64url").toString("utf8");
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
  return `${d.toISOString()} (${relativeTime(d.toISOString())})`;
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
          if (process.stdin.isTTY) {
            throw new Error("No JWT provided. Pass it as an argument or pipe it to stdin.");
          }
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

        // Track every key printed so anything else falls through to "Custom claims".
        // COL is the width of the longest fixed claim key ("delegation_depth" = 16 chars).
        const COL = 16;
        const printed = new Set<string>();
        const print = (key: string, value: string) => {
          printed.add(key);
          console.log(`  ${key.padEnd(COL)}: ${value}`);
        };

        print("sub", str("sub"));
        print("iss", str("iss"));
        print("jti", str("jti"));
        if (payload["aud"] !== undefined) {
          const aud = Array.isArray(payload["aud"]) ? (payload["aud"] as string[]).join(", ") : str("aud");
          print("aud", aud);
        }
        print("account_id", str("account_id"));
        print("project_id", str("project_id"));
        if (payload["external_id"] !== undefined) print("external_id", str("external_id"));
        if (payload["name"] !== undefined)        print("name", str("name"));
        if (payload["status"] !== undefined)      print("status", str("status"));
        print("identity_type", str("identity_type"));
        if (payload["sub_type"] !== undefined)    print("sub_type", str("sub_type"));
        print("trust_level", str("trust_level"));
        print("grant_type", str("grant_type"));
        if (payload["owner_user_id"] !== undefined) print("owner_user_id", str("owner_user_id"));
        if (payload["framework"] !== undefined)   print("framework", str("framework"));
        if (payload["version"] !== undefined)     print("version", str("version"));
        if (payload["publisher"] !== undefined)   print("publisher", str("publisher"));

        const nbf = num("nbf");
        const iat = num("iat");
        const exp = num("exp");
        if (nbf !== undefined) print("nbf", _formatTime(nbf));
        if (iat !== undefined) print("iat", _formatTime(iat));
        if (exp !== undefined) {
          const expired = exp <= Date.now() / 1000;
          const label = _formatTime(exp);
          print("exp", expired ? chalk.red(label) : chalk.green(label));
        }

        if (payload["scopes"] !== undefined) {
          const scopes = Array.isArray(payload["scopes"]) ? (payload["scopes"] as string[]).join(" ") : str("scopes");
          print("scopes", scopes);
        }

        const depth = num("delegation_depth");
        if (depth !== undefined) print("delegation_depth", String(depth));

        if (payload["act"] && typeof payload["act"] === "object") {
          const act = payload["act"] as Record<string, unknown>;
          print("act", `{ sub: ${act["sub"] ?? "-"} }`);
        }

        if (payload["session_id"] !== undefined)  print("session_id", str("session_id"));
        if (payload["task_id"] !== undefined)     print("task_id", str("task_id"));
        if (payload["task_type"] !== undefined)   print("task_type", str("task_type"));
        if (payload["workspace"] !== undefined)   print("workspace", str("workspace"));
        if (payload["environment"] !== undefined) print("environment", str("environment"));

        if (payload["allowed_tools"] !== undefined) {
          const tools = Array.isArray(payload["allowed_tools"])
            ? (payload["allowed_tools"] as string[]).join(", ")
            : String(payload["allowed_tools"]);
          print("allowed_tools", tools);
        }

        if (payload["capabilities"] !== undefined) {
          const caps = Array.isArray(payload["capabilities"])
            ? (payload["capabilities"] as string[]).join(", ")
            : JSON.stringify(payload["capabilities"]);
          print("capabilities", caps);
        }

        // Print any remaining claims not shown above.
        const extra = Object.entries(payload).filter(([k]) => !printed.has(k));
        if (extra.length > 0) {
          console.log(chalk.bold("\nCustom claims"));
          let maxLen = 0;
          for (const [k] of extra) if (k.length > maxLen) maxLen = k.length;
          for (const [k, v] of extra) {
            const val = typeof v === "string" ? v : JSON.stringify(v);
            console.log(`  ${k.padEnd(maxLen)}: ${val}`);
          }
        }
        console.log();
      } catch (err) {
        handleError(err);
      }
    });
}
