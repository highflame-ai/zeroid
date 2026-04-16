/**
 * zeroid agents rotate-key <id> — rotate an agent's API key.
 */

import { Command } from "commander";
import { makeTenantClient } from "../../lib/client.js";
import {
  getSelectedProfile,
  updateProfileAPIKeyForIdentity,
  writeEnvFileIfPresent,
} from "../../lib/config.js";
import { handleError, printJSON, printSuccess, printWarning } from "../../lib/output.js";

export function registerRotateKey(agentsCmd: Command): void {
  agentsCmd
    .command("rotate-key <id>")
    .description("Rotate an agent's API key — revokes old key and issues a new one")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (id: string, opts) => {
      try {
        const selectedProfile = getSelectedProfile(opts.profile as string | undefined);
        const client = makeTenantClient(opts.profile as string | undefined, "zeroid agents rotate-key");
        const result = await client.agents.rotateKey(id);
        const updatedProfileName = updateProfileAPIKeyForIdentity(
          selectedProfile?.name,
          result.identity.id,
          result.api_key,
        );
        const refreshedEnvFile =
          updatedProfileName !== undefined && writeEnvFileIfPresent(result.api_key);

        if (opts.json) {
          printJSON(result);
          return;
        }

        printSuccess(`API key rotated for agent ${result.identity.name}`);
        console.log(`  New API key: ${result.api_key}`);
        if (updatedProfileName) {
          printSuccess(`Updated profile "${updatedProfileName}" with the new API key`);
        } else if (selectedProfile) {
          printWarning(
            `Profile "${selectedProfile.name}" was not updated automatically because it does not match agent ${id}.`,
          );
        }
        if (refreshedEnvFile) {
          printSuccess("Updated .env.zeroid in the current directory");
        }
        printWarning("Store the new API key securely — it will not be shown again.");
      } catch (err) {
        handleError(err);
      }
    });
}
