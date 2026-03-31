/**
 * zid agents rotate-key <id> — rotate an agent's API key.
 */

import { Command } from "commander";
import { makeClient } from "../../lib/client.js";
import { handleError, printJSON, printSuccess, printWarning } from "../../lib/output.js";

export function registerRotateKey(agentsCmd: Command): void {
  agentsCmd
    .command("rotate-key <id>")
    .description("Rotate an agent's API key — revokes old key and issues a new one")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (id: string, opts) => {
      try {
        const client = makeClient(opts.profile as string | undefined);
        const result = await client.agents.rotateKey(id);

        if (opts.json) {
          printJSON(result);
          return;
        }

        printSuccess(`API key rotated for agent ${result.identity.name}`);
        console.log(`  New API key: ${result.api_key}`);
        printWarning("Store the new API key securely — it will not be shown again.");
      } catch (err) {
        handleError(err);
      }
    });
}
