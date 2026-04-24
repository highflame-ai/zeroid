/**
 * zeroid creds list --agent <id> — list credentials for an agent.
 */

import { Command } from "commander";
import { makeTenantClient } from "../../lib/client.js";
import { handleError, printJSON, printTable, relativeTime } from "../../lib/output.js";

export function registerCredsList(credsCmd: Command): void {
  credsCmd
    .command("list")
    .description("List credentials for an agent")
    .requiredOption("--agent <id>", "Agent identity ID")
    .option("--active", "Show only non-revoked credentials")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (opts) => {
      try {
        const client = makeTenantClient(opts.profile as string | undefined, "zeroid creds list");
        const result = await client.credentials.list(opts.agent as string);
        const creds = (result.credentials ?? []).filter((c) => !opts.active || !c.is_revoked);

        if (opts.json) {
          printJSON(creds);
          return;
        }

        if (creds.length === 0) {
          console.log("No credentials found.");
          return;
        }

        printTable(
          ["ID", "STATUS", "SCOPES", "EXPIRES", "ISSUED"],
          creds.map((c) => [
            c.id,
            c.is_revoked ? "revoked" : "active",
            c.scopes.join(" ") || "-",
            relativeTime(c.expires_at),
            relativeTime(c.issued_at),
          ]),
        );
        console.log(`\n${creds.length} credential(s)`);
      } catch (err) {
        handleError(err);
      }
    });
}
