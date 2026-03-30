/**
 * zid config — manage CLI profiles.
 *
 * Usage:
 *   zid config use-profile prod
 *   zid config list-profiles
 */

import { Command } from "commander";
import { useProfile, listProfiles } from "../lib/config.js";
import { handleError, printSuccess } from "../lib/output.js";

export function registerConfig(program: Command): void {
  const configCmd = program
    .command("config")
    .description("Manage CLI profiles");

  configCmd
    .command("use-profile <name>")
    .description("Switch the active profile")
    .action((name: string) => {
      try {
        useProfile(name);
        printSuccess(`Switched to profile "${name}"`);
      } catch (err) {
        handleError(err);
      }
    });

  configCmd
    .command("list-profiles")
    .description("List all configured profiles")
    .action(() => {
      try {
        const profiles = listProfiles();
        if (profiles.length === 0) {
          console.log('No profiles configured. Run "zid init" to get started.');
          return;
        }
        for (const p of profiles) {
          console.log(`  ${p.active ? "* " : "  "}${p.name}`);
        }
      } catch (err) {
        handleError(err);
      }
    });
}
