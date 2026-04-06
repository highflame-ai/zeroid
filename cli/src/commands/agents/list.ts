/**
 * zid agents list — list registered agents.
 *
 * Usage:
 *   zid agents list
 *   zid agents list --json | jq '.[].wimse_uri'
 */

import { Command } from "commander";
import { makeTenantClient } from "../../lib/client.js";
import { handleError, printJSON, printTable, relativeTime } from "../../lib/output.js";

export function registerList(agentsCmd: Command): void {
  agentsCmd
    .command("list")
    .description("List registered agents")
    .option("--type <type>", "Filter by identity_type")
    .option("--limit <n>", "Max results", "50")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON array")
    .action(async (opts) => {
      try {
        const client = makeTenantClient(opts.profile as string | undefined, "zid agents list");
        const limit = parseInt(opts.limit as string, 10);
        const result = await client.agents.list({
          identity_type: opts.type as string | undefined,
          limit: Number.isNaN(limit) ? 50 : limit,
        });

        if (opts.json) {
          printJSON(result.agents);
          return;
        }

        if (result.agents.length === 0) {
          console.log("No agents found.");
          return;
        }

        printTable(
          ["NAME", "TYPE", "TRUST", "STATUS", "CREATED"],
          result.agents.map((a) => [
            a.name,
            a.identity_type,
            a.trust_level,
            a.status,
            relativeTime(a.created_at),
          ]),
        );
        console.log(`\n${result.agents.length} agent(s)`);
      } catch (err) {
        handleError(err);
      }
    });
}
