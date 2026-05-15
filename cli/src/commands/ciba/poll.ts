/**
 * zeroid ciba poll <auth_req_id> — poll /oauth2/token for a CIBA token.
 */

import { Command } from "commander";
import { requireBaseURL } from "../../lib/config.js";
import { printError, printJSON, printSuccess, printWarning } from "../../lib/output.js";
import {
  CIBA_GRANT_TYPE,
  isNonTerminalPollError,
  postPublicJSON,
  type CibaOAuthError,
  type CibaTokenResponse,
  toCibaOAuthError,
} from "./api.js";

export function registerCibaPoll(cibaCmd: Command): void {
  cibaCmd
    .command("poll <auth-req-id>")
    .description("Poll the token endpoint with the CIBA grant (Core §10.1)")
    .requiredOption("--client-id <id>", "OAuth client that initiated the request")
    .option("--watch", "Keep polling until success or terminal error")
    .option("--interval <seconds>", "Polling interval for --watch", "5")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .addHelpText(
      "after",
      "\nCIBA Core references: §10.1 Token Request Using CIBA Grant Type, §11 Polling Error Responses.",
    )
    .action(async (authReqID: string, opts) => {
      const baseUrl = requireBaseURL(opts.profile as string | undefined);
      let intervalSeconds = parseInterval(opts.interval as string);

      for (;;) {
        const result = await pollOnce(baseUrl, authReqID, opts.clientId as string);
        if ("access_token" in result) {
          printToken(result, Boolean(opts.json));
          return;
        }

        if (!opts.watch || !isNonTerminalPollError(result.error)) {
          printPollError(result, Boolean(opts.json));
          process.exit(1);
        }

        if (!opts.json) {
          const suffix = result.error_description ? `: ${result.error_description}` : "";
          printWarning(`${result.error}${suffix}`);
        } else {
          printJSON(result);
        }

        if (result.error === "slow_down") {
          intervalSeconds += 5;
        }
        await sleep(intervalSeconds * 1000);
      }
    });
}

async function pollOnce(
  baseUrl: string,
  authReqID: string,
  clientID: string,
): Promise<CibaTokenResponse | CibaOAuthError> {
  try {
    return await postPublicJSON<CibaTokenResponse>(baseUrl, "/oauth2/token", {
      grant_type: CIBA_GRANT_TYPE,
      auth_req_id: authReqID,
      client_id: clientID,
    });
  } catch (err) {
    return toCibaOAuthError(err);
  }
}

function printToken(token: CibaTokenResponse, json: boolean): void {
  if (json) {
    printJSON(token);
    return;
  }

  printSuccess("CIBA token issued");
  console.log(`  access_token: ${token.access_token}`);
  console.log(`  token_type:   ${token.token_type ?? "Bearer"}`);
  console.log(`  expires_in:   ${token.expires_in}s`);
  if (token.scope) {
    console.log(`  scope:        ${token.scope}`);
  }
  if (token.refresh_token) {
    console.log(`  refresh_token: ${token.refresh_token}`);
  }
}

function printPollError(error: CibaOAuthError, json: boolean): void {
  if (json) {
    printJSON(error);
    return;
  }

  const suffix = error.error_description ? `: ${error.error_description}` : "";
  printError(`${error.error}${suffix}`);
}

function parseInterval(value: string): number {
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error("--interval must be a non-negative number of seconds");
  }
  return parsed;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
