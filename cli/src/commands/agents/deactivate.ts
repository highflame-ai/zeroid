/**
 * zeroid agents deactivate <id> — deactivate an agent (soft, reversible).
 * zeroid agents activate <id>   — re-activate a deactivated agent.
 */

import { Command } from "commander";
import { makeTenantClient } from "../../lib/client.js";
import { handleError, printJSON, printSuccess } from "../../lib/output.js";

export function registerDeactivate(agentsCmd: Command): void {
  agentsCmd
    .command("deactivate <id>")
    .description("Deactivate an agent (reversible — does not delete)")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (id: string, opts) => {
      try {
        const client = makeTenantClient(opts.profile as string | undefined, "zeroid agents deactivate");
        const agent = await client.agents.deactivate(id);
        if (opts.json) { printJSON(agent); return; }
        printSuccess(`Agent ${agent.name} deactivated`);
      } catch (err) {
        handleError(err);
      }
    });

  agentsCmd
    .command("activate <id>")
    .description("Activate a previously deactivated agent")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (id: string, opts) => {
      try {
        const client = makeTenantClient(opts.profile as string | undefined, "zeroid agents activate");
        const agent = await client.agents.activate(id);
        if (opts.json) { printJSON(agent); return; }
        printSuccess(`Agent ${agent.name} activated`);
      } catch (err) {
        handleError(err);
      }
    });
}
