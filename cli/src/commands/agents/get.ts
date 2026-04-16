/**
 * zeroid agents get <id> — get an agent by ID.
 */

import { Command } from "commander";
import chalk from "chalk";
import { makeTenantClient } from "../../lib/client.js";
import { handleError, printJSON } from "../../lib/output.js";

export function registerGet(agentsCmd: Command): void {
  agentsCmd
    .command("get <id>")
    .description("Get an agent by ID")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (id: string, opts) => {
      try {
        const client = makeTenantClient(opts.profile as string | undefined, "zeroid agents get");
        const agent = await client.agents.get(id);

        if (opts.json) {
          printJSON(agent);
          return;
        }

        console.log(chalk.bold(`\n${agent.name}`));
        console.log(`  ID:            ${agent.id}`);
        console.log(`  WIMSE URI:     ${agent.wimse_uri}`);
        console.log(`  External ID:   ${agent.external_id}`);
        console.log(`  Type:          ${agent.identity_type}`);
        console.log(`  Sub-type:      ${agent.sub_type || "-"}`);
        console.log(`  Trust:         ${agent.trust_level}`);
        console.log(`  Status:        ${agent.status}`);
        console.log(`  Framework:     ${agent.framework || "-"}`);
        console.log(`  Description:   ${agent.description || "-"}`);
        console.log(`  Created:       ${agent.created_at}`);
        console.log();
      } catch (err) {
        handleError(err);
      }
    });
}
