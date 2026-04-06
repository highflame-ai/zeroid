/**
 * zid token verify <jwt> — verify a JWT against the live JWKS.
 *
 * Exit codes:
 *   0 — valid
 *   1 — invalid / error
 *   2 — expired
 */

import { Command } from "commander";
import chalk from "chalk";
import { ZeroIDError } from "@highflame/sdk";
import { makeBaseUrlClient } from "../../lib/client.js";
import { handleError, printJSON } from "../../lib/output.js";

export function registerVerify(tokenCmd: Command): void {
  tokenCmd
    .command("verify <jwt>")
    .description("Verify a JWT against the live JWKS (exit 0 = valid, 1 = invalid, 2 = expired)")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (jwt: string, opts) => {
      try {
        const client = makeBaseUrlClient(opts.profile as string | undefined);
        const identity = await client.tokens.verify(jwt);

        if (opts.json) {
          printJSON(identity);
        } else {
          console.log(chalk.green("✓") + "  Token is valid\n");
          console.log(`  sub:           ${identity.sub}`);
          console.log(`  identity_type: ${identity.identity_type ?? "-"}`);
          console.log(`  trust_level:   ${identity.trust_level ?? "-"}`);
          console.log(`  account_id:    ${identity.account_id}`);
          console.log(`  project_id:    ${identity.project_id}`);
          if (identity.scopes?.length) {
            console.log(`  scopes:        ${identity.scopes.join(" ")}`);
          }
          if (identity.exp > 0) {
            const exp = new Date(identity.exp * 1000);
            const remaining = Math.round((identity.exp - Date.now() / 1000) / 60);
            console.log(`  expires:       ${exp.toISOString()} (${remaining}m remaining)`);
          }
          const delegator = identity.delegatedBy();
          if (delegator) {
            console.log(`  delegated_by:  ${delegator}`);
          }
          console.log();
        }
      } catch (err: unknown) {
        if (err instanceof ZeroIDError && err.code === "token_expired") {
          console.error(chalk.red("✗") + "  Token has expired");
          process.exit(2);
        }
        handleError(err);
      }
      process.exit(0);
    });
}
