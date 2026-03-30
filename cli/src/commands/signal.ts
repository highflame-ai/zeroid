/**
 * zid signal — ingest a CAE signal for an agent.
 *
 * Usage:
 *   zid signal --agent <id> --type anomalous_behavior --severity high \
 *     --source "security-monitor" --reason "unexpected outbound call"
 */

import { Command } from "commander";
import type { SignalType, SignalSeverity } from "@highflame/sdk";
import { makeClient } from "../lib/client.js";
import { handleError, printJSON, printSuccess } from "../lib/output.js";

export function registerSignal(program: Command): void {
  program
    .command("signal")
    .description("Ingest a CAE signal for an agent")
    .requiredOption("--agent <id>", "Agent identity ID")
    .requiredOption(
      "--type <type>",
      "Signal type: credential_change | session_revoked | ip_change | anomalous_behavior | policy_violation | retirement | owner_change",
    )
    .requiredOption("--severity <level>", "Severity: low | medium | high | critical")
    .requiredOption("--source <source>", "Source of the signal (e.g. zid-cli, siem, monitor)")
    .option("--reason <text>", "Human-readable reason (stored in payload.reason)")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (opts) => {
      try {
        const client = makeClient(opts.profile as string | undefined);
        const payload: Record<string, unknown> | undefined =
          opts.reason ? { reason: opts.reason as string } : undefined;

        const signal = await client.signals.ingest({
          identity_id: opts.agent as string,
          signal_type: opts.type as SignalType,
          severity: opts.severity as SignalSeverity,
          source: opts.source as string,
          payload,
        });

        if (opts.json) {
          printJSON(signal);
          return;
        }

        printSuccess(`Signal ingested (${signal.id})`);
        console.log(`  Type:     ${signal.signal_type}`);
        console.log(`  Severity: ${signal.severity}`);
        console.log(`  Agent:    ${signal.identity_id}`);
      } catch (err) {
        handleError(err);
      }
    });
}
