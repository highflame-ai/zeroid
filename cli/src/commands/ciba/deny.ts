/**
 * zeroid ciba deny <auth_req_id> — deny a pending CIBA request.
 */

import { Command } from "commander";
import { requireTenantContext } from "../../lib/config.js";
import { handleError, printJSON, printSuccess } from "../../lib/output.js";
import {
  buildCibaAdminPath,
  type CibaResolveResponse,
  postTenantJSON,
  resolveCibaAdminRequest,
} from "./api.js";

export function registerCibaDeny(cibaCmd: Command): void {
  cibaCmd
    .command("deny <auth-req-id>")
    .description("Deny a pending CIBA request (admin-side simulation)")
    .option("--reason <text>", "Operator note to send with the denial when supported by the server")
    .option("--admin-base-url <url>", "Admin API base URL (defaults to profile base URL)")
    .option(
      "--admin-prefix <path>",
      'Admin route prefix before /oauth2/bc-authorize (default: /api/v1; use "" for AuthN)',
    )
    .option("--internal-service <name>", "Internal service name header for protected admin routes")
    .option("--internal-service-secret <secret>", "Internal service secret header")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .addHelpText(
      "after",
      "\nCIBA Core references: §8 End-User Consent/Authorization, §12 Push Error Payload.",
    )
    .action(async (authReqID: string, opts) => {
      try {
        const context = requireTenantContext(opts.profile as string | undefined, "zeroid ciba deny");
        const admin = resolveCibaAdminRequest(context, {
          adminBaseUrl: opts.adminBaseUrl as string | undefined,
          adminPrefix: opts.adminPrefix as string | undefined,
          internalService: opts.internalService as string | undefined,
          internalServiceSecret: opts.internalServiceSecret as string | undefined,
        });
        const response = await postTenantJSON<CibaResolveResponse>(
          context,
          buildCibaAdminPath(admin, `/oauth2/bc-authorize/${encodeURIComponent(authReqID)}/deny`),
          { reason: nonEmpty(opts.reason as string | undefined) },
          { baseUrl: admin.baseUrl, headers: admin.headers },
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
