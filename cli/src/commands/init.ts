/**
 * zid init — register a new agent and write the api_key to .env.zeroid.
 *
 * Usage:
 *   zid init --name "github-mcp-server" --type mcp_server --scope "repo:read pr:write"
 */

import { Command } from "commander";
import type { IdentityType, SubType } from "@highflame/sdk";
import { makeTenantClient } from "../lib/client.js";
import { setProfile, writeEnvFile } from "../lib/config.js";
import { handleError, printJSON, printSuccess, printWarning } from "../lib/output.js";

export function registerInit(program: Command): void {
  program
    .command("init")
    .description("Register a new agent and write credentials to .env.zeroid")
    .requiredOption("--name <name>", "Human-readable agent name")
    .requiredOption("--owner <owner_id>", "User ID of the agent owner")
    .option("--id <external_id>", "External ID (defaults to --name)")
    .option(
      "--type <type>",
      "Identity type: agent | application | mcp_server | service",
      "agent",
    )
    .option("--sub-type <sub_type>", "Sub-type: orchestrator | tool_agent | code_agent | ...")
    .option("--framework <framework>", "Framework name (e.g. langchain, mcp)")
    .option("--description <desc>", "Short description")
    .option("--profile <profile>", "Config profile to use")
    .option("--save-profile <name>", "Save credentials under this profile name", "default")
    .option("--json", "Output raw JSON")
    .action(async (opts) => {
      try {
        const client = makeTenantClient(opts.profile as string | undefined, "zid init");
        const result = await client.agents.register({
          name: opts.name as string,
          external_id: (opts.id as string | undefined) ?? (opts.name as string),
          identity_type: opts.type as IdentityType,
          sub_type: opts.subType as SubType | undefined,
          framework: opts.framework as string | undefined,
          description: opts.description as string | undefined,
          created_by: opts.owner as string,
        });

        // Side effects always happen regardless of output format.
        writeEnvFile(result.api_key);
        setProfile(opts.saveProfile as string, {
          base_url: client.baseUrl,
          account_id: result.identity.account_id,
          project_id: result.identity.project_id,
          api_key: result.api_key,
        });

        if (opts.json) {
          printJSON(result);
          return;
        }

        printSuccess(`Agent registered: ${result.identity.name}`);
        console.log(`  WIMSE URI:  ${result.identity.wimse_uri}`);
        console.log(`  ID:         ${result.identity.id}`);
        console.log(`  Type:       ${result.identity.identity_type}`);
        console.log(`  Trust:      ${result.identity.trust_level}`);
        console.log(`  API key:    ${result.api_key}`);
        printSuccess("API key written to .env.zeroid");
        printSuccess(`Profile "${opts.saveProfile as string}" saved to ~/.config/zid/config.json`);
        printWarning("Store the API key securely — it will not be shown again.");
      } catch (err) {
        handleError(err);
      }
    });
}
