/**
 * zeroid ciba init — initiate an OpenID CIBA backchannel auth request.
 */

import { Command } from "commander";
import { requireTenantContext } from "../../lib/config.js";
import { handleError, printJSON, printSuccess } from "../../lib/output.js";
import { type CibaInitResponse, postPublicJSON } from "./api.js";

export function registerCibaInit(cibaCmd: Command): void {
  cibaCmd
    .command("init")
    .description("Initiate a CIBA backchannel authentication request (Core §7)")
    .requiredOption("--client-id <id>", "OAuth client initiating the CIBA request")
    .requiredOption("--login-hint <hint>", "User identifier to send to the backchannel notifier")
    .option("--scope <scopes>", "Space-separated scopes to request", "")
    .option("--binding-message <text>", "Human-readable context shown to the approving user")
    .option("--requested-expiry <seconds>", "Requested auth request lifetime in seconds")
    .option("--client-notification-token <token>", "Bearer token required for ping/push clients")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .addHelpText(
      "after",
      "\nCIBA Core references: §7 Backchannel Authentication Endpoint, §7.3 Successful Authentication Request Acknowledgement.",
    )
    .action(async (opts) => {
      try {
        const context = requireTenantContext(opts.profile as string | undefined, "zeroid ciba init");
        const requestedExpiry = parsePositiveInt(opts.requestedExpiry as string | undefined);

        const response = await postPublicJSON<CibaInitResponse>(context.base_url, "/oauth2/bc-authorize", {
          client_id: opts.clientId as string,
          account_id: context.account_id,
          project_id: context.project_id,
          login_hint: opts.loginHint as string,
          scope: nonEmpty(opts.scope as string | undefined),
          binding_message: nonEmpty(opts.bindingMessage as string | undefined),
          requested_expiry: requestedExpiry,
          client_notification_token: nonEmpty(opts.clientNotificationToken as string | undefined),
        });

        if (opts.json) {
          printJSON(response);
          return;
        }

        printSuccess("CIBA request initiated");
        console.log(`  auth_req_id: ${response.auth_req_id}`);
        console.log(`  expires_in:  ${response.expires_in}s`);
        console.log(`  interval:    ${response.interval}s`);
      } catch (err) {
        handleError(err);
      }
    });
}

function parsePositiveInt(value: string | undefined): number | undefined {
  if (value === undefined || value.trim() === "") {
    return undefined;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error("--requested-expiry must be a positive integer");
  }
  return parsed;
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}
