/**
 * zeroid ciba approve <auth_req_id> — approve a pending CIBA request.
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

export function registerCibaApprove(cibaCmd: Command): void {
  cibaCmd
    .command("approve <auth-req-id>")
    .description("Approve a pending CIBA request (admin-side simulation)")
    .requiredOption("--subject-id <id>", "Approved end-user identifier; becomes token sub")
    .option("--subject-email <email>", "Approved user's email")
    .option("--subject-name <name>", "Approved user's display name")
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
      "\nCIBA Core references: §8 End-User Consent/Authorization, §10 Getting the Authentication Result.",
    )
    .action(async (authReqID: string, opts) => {
      try {
        const context = requireTenantContext(
          opts.profile as string | undefined,
          "zeroid ciba approve",
        );
        const admin = resolveCibaAdminRequest(context, {
          adminBaseUrl: opts.adminBaseUrl as string | undefined,
          adminPrefix: opts.adminPrefix as string | undefined,
          internalService: opts.internalService as string | undefined,
          internalServiceSecret: opts.internalServiceSecret as string | undefined,
        });
        const response = await postTenantJSON<CibaResolveResponse>(
          context,
          buildCibaAdminPath(
            admin,
            `/oauth2/bc-authorize/${encodeURIComponent(authReqID)}/approve`,
          ),
          {
            subject_id: opts.subjectId as string,
            subject_email: nonEmpty(opts.subjectEmail as string | undefined),
            subject_name: nonEmpty(opts.subjectName as string | undefined),
          },
          { baseUrl: admin.baseUrl, headers: admin.headers },
        );

        if (opts.json) {
          printJSON(response);
          return;
        }

        printSuccess(`CIBA request approved (${response.auth_req_id})`);
      } catch (err) {
        handleError(err);
      }
    });
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}
