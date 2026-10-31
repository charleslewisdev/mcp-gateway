import type { BackendConfig, Env } from "./types.js";

const API_PATH = /^\/api\/([^/]+)(\/.*)?$/;

export function parseBackendPath(
  pathname: string
): { name: string; remainingPath: string } | null {
  const match = API_PATH.exec(pathname);
  return match ? { name: match[1], remainingPath: match[2] ?? "" } : null;
}

export function findBackend(env: Env, name: string): BackendConfig | null {
  const backends: Record<string, BackendConfig> = JSON.parse(env.BACKENDS);
  return Object.hasOwn(backends, name) ? backends[name] : null;
}
