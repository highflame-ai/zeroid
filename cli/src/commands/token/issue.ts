/**
 * zid token issue — issue a short-lived token using the profile's api_key.
 *
 * Usage:
 *   zid token issue
 *   zid token issue --scope "repo:read"
 */

import { Command } from "commander";
import { requireProfile } from "../../lib/config.js";
import { makeClientFromProfile } from "../../lib/client.js";
import { handleError, printJSON, printSuccess } from "../../lib/output.js";

export function registerIssue(tokenCmd: Command): void {
  tokenCmd
    .command("issue")
    .description("Issue a token for the authenticated agent (api_key grant)")
    .option("--scope <scopes>", "Space-separated scopes to request", "")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (opts) => {
      try {
        const profile = requireProfile(opts.profile as string | undefined);
        const client = makeClientFromProfile(profile);
        const token = await client.tokens.issue({
          grant_type: "api_key",
          api_key: profile.api_key,
          scope: (opts.scope as string).trim() || undefined,
        });

        if (opts.json) {
          printJSON(token);
          return;
        }

        printSuccess("Token issued");
        console.log(`  access_token: ${token.access_token}`);
        console.log(`  token_type:   ${token.token_type}`);
        console.log(`  expires_in:   ${token.expires_in}s`);
        console.log();
      } catch (err) {
        handleError(err);
      }
    });
}
