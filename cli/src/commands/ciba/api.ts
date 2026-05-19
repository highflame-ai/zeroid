export const CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";

export interface CibaTenantContext {
  base_url: string;
  account_id: string;
  project_id: string;
}

export interface CibaAdminCommandOptions {
  adminBaseUrl?: string;
  adminPrefix?: string;
  internalService?: string;
  internalServiceSecret?: string;
}

export interface CibaAdminRequestConfig {
  baseUrl: string;
  prefix: string;
  headers: Record<string, string>;
}

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

export class CibaHTTPError extends Error {
  constructor(
    public readonly status: number,
    public readonly title: string,
    public readonly detail?: string,
    public readonly code?: string,
  ) {
    super(detail ? `[${status}] ${title}: ${detail}` : `[${status}] ${title}`);
    this.name = "CibaHTTPError";
  }
}

export function toCibaOAuthError(err: unknown): CibaOAuthError {
  if (err instanceof CibaHTTPError) {
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
  baseUrl: string,
  path: string,
  body: Record<string, unknown>,
): Promise<T> {
  return postJSON<T>(baseUrl, path, body);
}

export async function postTenantJSON<T>(
  context: CibaTenantContext,
  path: string,
  body: Record<string, unknown>,
  options: { baseUrl?: string; headers?: Record<string, string | undefined> } = {},
): Promise<T> {
  return postJSON<T>(options.baseUrl ?? context.base_url, path, body, cleanHeaders({
    "X-Account-ID": context.account_id,
    "X-Project-ID": context.project_id,
    ...options.headers,
  }));
}

export function resolveCibaAdminRequest(
  context: CibaTenantContext,
  opts: CibaAdminCommandOptions,
): CibaAdminRequestConfig {
  const internalService = nonEmpty(opts.internalService) ?? readEnv("ZID_INTERNAL_SERVICE");
  const internalServiceSecret =
    nonEmpty(opts.internalServiceSecret) ?? readEnv("ZID_INTERNAL_SERVICE_SECRET");

  if (internalServiceSecret && !internalService) {
    throw new Error(
      "--internal-service-secret requires --internal-service or ZID_INTERNAL_SERVICE",
    );
  }

  return {
    baseUrl: nonEmpty(opts.adminBaseUrl) ?? readEnv("ZID_ADMIN_BASE_URL") ?? context.base_url,
    prefix: readOptionOrEnvAllowEmpty(opts.adminPrefix, "ZID_ADMIN_PREFIX") ?? "/api/v1",
    headers: cleanHeaders({
      "X-Internal-Service": internalService,
      "X-Internal-Service-Secret": internalServiceSecret,
    }),
  };
}

export function buildCibaAdminPath(config: CibaAdminRequestConfig, path: string): string {
  return joinPath(config.prefix, path);
}

async function postJSON<T>(
  baseUrl: string,
  path: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<T> {
  const response = await fetch(`${trimTrailingSlash(baseUrl)}${ensureLeadingSlash(path)}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw await parseErrorResponse(response);
  }

  if (response.status === 204) {
    return {} as T;
  }

  const text = await response.text();
  if (!text.trim()) {
    return {} as T;
  }

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new CibaHTTPError(response.status, "Invalid JSON response", text);
  }
}

async function parseErrorResponse(response: Response): Promise<CibaHTTPError> {
  const text = await response.text();
  let title = response.statusText || "Request failed";
  let detail: string | undefined;
  let code: string | undefined;

  if (text.trim()) {
    try {
      const parsed = JSON.parse(text) as unknown;
      if (isRecord(parsed)) {
        code = readString(parsed, "error") ?? readString(parsed, "code");
        title = code ?? readString(parsed, "title") ?? readString(parsed, "message") ?? title;
        detail =
          readString(parsed, "error_description") ??
          readString(parsed, "detail") ??
          readString(parsed, "message");
      }
    } catch {
      detail = text;
    }
  }

  return new CibaHTTPError(response.status, title, detail, code);
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function ensureLeadingSlash(value: string): string {
  return value.startsWith("/") ? value : `/${value}`;
}

function joinPath(prefix: string, path: string): string {
  const cleanPrefix = prefix.trim().replace(/\/+$/, "");
  if (!cleanPrefix) {
    return ensureLeadingSlash(path);
  }
  return `${ensureLeadingSlash(cleanPrefix)}${ensureLeadingSlash(path)}`;
}

function cleanHeaders(headers: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value !== undefined && value !== "") {
      out[key] = value;
    }
  }
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.trim() ? value : undefined;
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function readEnv(name: string): string | undefined {
  return nonEmpty(process.env[name]);
}

function readOptionOrEnvAllowEmpty(value: string | undefined, envName: string): string | undefined {
  if (value !== undefined) {
    return value;
  }
  if (Object.prototype.hasOwnProperty.call(process.env, envName)) {
    return process.env[envName] ?? "";
  }
  return undefined;
}
