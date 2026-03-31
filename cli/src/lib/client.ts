/**
 * Builds a ZeroIDClient from the active profile or env vars.
 */

import { ZeroIDClient } from "@highflame/sdk";
import { requireProfile, type Profile } from "./config.js";

export function makeClientFromProfile(profile: Profile): ZeroIDClient {
  return new ZeroIDClient({
    baseUrl: profile.base_url,
    accountId: profile.account_id,
    projectId: profile.project_id,
    apiKey: profile.api_key,
  });
}

export function makeClient(profileName?: string): ZeroIDClient {
  return makeClientFromProfile(requireProfile(profileName));
}
