/**
 * zeroid ciba deny <auth_req_id> — deny a pending CIBA request.
 */

import { Command } from "commander";
import { makeTenantClient } from "../../lib/client.js";
import { handleError, printJSON, printSuccess } from "../../lib/output.js";
import { type CibaResolveResponse, postTenantJSON } from "./api.js";

export function registerCibaDeny(cibaCmd: Command): void {
  cibaCmd
    .command("deny <auth-req-id>")
    .description("Deny a pending CIBA request (admin-side simulation)")
    .option("--reason <text>", "Operator note to send with the denial when supported by the server")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .addHelpText(
      "after",
      "\nCIBA Core references: §8 End-User Consent/Authorization, §12 Push Error Payload.",
    )
    .action(async (authReqID: string, opts) => {
      try {
        const client = makeTenantClient(opts.profile as string | undefined, "zeroid ciba deny");
        const response = await postTenantJSON<CibaResolveResponse>(
          client,
          `/api/v1/oauth2/bc-authorize/${encodeURIComponent(authReqID)}/deny`,
          { reason: nonEmpty(opts.reason as string | undefined) },
        );

        if (opts.json) {
          printJSON(response);
          return;
        }

        printSuccess(`CIBA request denied (${response.auth_req_id})`);
      } catch (err) {
        handleError(err);
      }
    });
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}
