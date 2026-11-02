/**
 * zeroid token revoke <jwt> — revoke a token.
 *
 * RFC 7009 authenticates the *client*, and production servers refuse an
 * unauthenticated revocation with 401 invalid_client. The SDK's
 * tokens.revoke cannot carry client credentials yet, so this command posts
 * the form itself.
 */

import { Command } from "commander";
import { requireBaseURL } from "../../lib/config.js";
import { handleError, printJSON, printSuccess } from "../../lib/output.js";

export function registerTokenRevoke(tokenCmd: Command): void {
  tokenCmd
    .command("revoke <jwt>")
    .description("Revoke a token (RFC 7009 — authenticates the OAuth client)")
    .option("--client-id <id>", "OAuth client id (or ZID_CLIENT_ID)")
    .option("--client-secret <secret>", "OAuth client secret (or ZID_CLIENT_SECRET)")
    .option("--profile <profile>", "Config profile to use")
    .option("--json", "Output raw JSON")
    .action(async (jwt: string, opts) => {
      try {
        const clientId = (opts.clientId as string | undefined) ?? process.env.ZID_CLIENT_ID;
        const clientSecret =
          (opts.clientSecret as string | undefined) ?? process.env.ZID_CLIENT_SECRET;
        if (!clientId || !clientSecret) {
          throw new Error(
            "token revoke requires OAuth client credentials (--client-id/--client-secret " +
              "or ZID_CLIENT_ID/ZID_CLIENT_SECRET) — RFC 7009 authenticates the client. " +
              "To kill an agent's access without an OAuth client, use `zeroid agents deactivate`.",
          );
        }

        const baseUrl = requireBaseURL(opts.profile as string | undefined);
        const response = await fetch(`${baseUrl}/oauth2/token/revoke`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: jwt, client_id: clientId, client_secret: clientSecret }),
        });
        if (!response.ok) {
          const detail = await response.text();
          throw new Error(`revocation failed (${response.status}): ${detail}`);
        }
        const result = await response.json().catch(() => ({}));

        if (opts.json) {
          printJSON(result);
          return;
        }

        printSuccess("Token revoked");
      } catch (err) {
        handleError(err);
      }
    });
}
