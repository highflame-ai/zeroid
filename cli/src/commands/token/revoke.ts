/**
 * zeroid token revoke <jwt> — revoke a token.
 */

import { Command } from "commander";
import { makeBaseUrlClient } from "../../lib/client.js";
import { handleError, printJSON, printSuccess } from "../../lib/output.js";

export function registerTokenRevoke(tokenCmd: Command): void {
  tokenCmd
    .command("revoke <jwt>")
    .description("Revoke a token")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (jwt: string, opts) => {
      try {
        const client = makeBaseUrlClient(opts.profile as string | undefined);
        const result = await client.tokens.revoke(jwt);

        if (opts.json) {
          printJSON(result);
          return;
        }

        printSuccess("Token revoked");
      } catch (err) {
        handleError(err);
      }
    });
}
