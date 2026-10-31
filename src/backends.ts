import type { BackendConfig, Env } from "./types.js";

const API_PATH = /^\/api\/([^/]+)(\/.*)?$/;
const RESOURCE_METADATA_PREFIX = "/.well-known/oauth-protected-resource";

export function parseBackends(env: Env): Record<string, BackendConfig> {
  return JSON.parse(env.BACKENDS);
}

export function backendPathAfterName(pathname: string): string {
  return API_PATH.exec(pathname)?.[2] ?? "";
}

/** The backend an API or resource metadata path belongs to, if any. */
export function backendNameFromPath(pathname: string): string | null {
  const apiPath = pathname.startsWith(`${RESOURCE_METADATA_PREFIX}/`)
    ? pathname.slice(RESOURCE_METADATA_PREFIX.length)
    : pathname;
  return API_PATH.exec(apiPath)?.[1] ?? null;
}
