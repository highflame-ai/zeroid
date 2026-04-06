/**
 * Builds a ZeroIDClient from the active profile or env vars.
 */

import { ZeroIDClient } from "@highflame/sdk";
import {
  requireBaseURL,
  requireProfile,
  requireTenantContext,
  type ClientContext,
  type Profile,
} from "./config.js";

export function makeClientFromContext(context: ClientContext): ZeroIDClient {
  return new ZeroIDClient({
    baseUrl: context.base_url,
    accountId: context.account_id,
    projectId: context.project_id,
    apiKey: context.api_key,
  });
}

export function makeClientFromProfile(profile: Profile): ZeroIDClient {
  return makeClientFromContext(profile);
}

export function makeClient(profileName?: string): ZeroIDClient {
  return makeClientFromProfile(requireProfile(profileName));
}

export function makeTenantClient(profileName?: string, command?: string): ZeroIDClient {
  return makeClientFromContext(requireTenantContext(profileName, command));
}

export function makeBaseUrlClient(profileName?: string): ZeroIDClient {
  return new ZeroIDClient({ baseUrl: requireBaseURL(profileName) });
}
