import { ZeroIDAPIError, ZeroIDClient } from "@highflame/sdk";

export const CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";

export interface CibaInitResponse {
  auth_req_id: string;
  expires_in: number;
  interval: number;
}

export interface CibaResolveResponse {
  auth_req_id: string;
  status: "approved" | "denied" | string;
}

export interface CibaTokenResponse {
  access_token: string;
  token_type?: string;
  expires_in: number;
  scope?: string;
  refresh_token?: string;
  jti?: string;
  iat?: number;
  account_id?: string;
  project_id?: string;
  [key: string]: unknown;
}

export interface CibaOAuthError {
  error: string;
  error_description?: string;
  status?: number;
}

export function toCibaOAuthError(err: unknown): CibaOAuthError {
  if (err instanceof ZeroIDAPIError) {
    return {
      error: err.code || err.title,
      error_description: err.detail || undefined,
      status: err.status,
    };
  }
  if (err instanceof Error) {
    return { error: "client_error", error_description: err.message };
  }
  return { error: "client_error", error_description: String(err) };
}

export function isNonTerminalPollError(error: string): boolean {
  return error === "authorization_pending" || error === "slow_down";
}

export async function postPublicJSON<T>(
  client: ZeroIDClient,
  path: string,
  body: Record<string, unknown>,
): Promise<T> {
  return client._postJSON<T>(path, body, undefined, false);
}

export async function postTenantJSON<T>(
  client: ZeroIDClient,
  path: string,
  body: Record<string, unknown>,
): Promise<T> {
  return client._postJSON<T>(path, body);
}
