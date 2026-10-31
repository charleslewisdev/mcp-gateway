import { hashSync } from "bcryptjs";
import type { Env } from "../src/types.js";

export const ORIGIN = "https://gateway.test";
export const RESOURCE = `${ORIGIN}/api/bramble`;
export const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
export const USERNAME = "owner";
export const PASSWORD = "correct horse";
// Fixture pair from RFC 7636 appendix B.
export const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

export function memoryKv(): KVNamespace {
  const store = new Map<string, string>();
  return {
    async get(key: string, options?: { type?: string }) {
      const value = store.get(key) ?? null;
      return value !== null && options?.type === "json"
        ? JSON.parse(value)
        : value;
    },
    async put(key: string, value: string) {
      store.set(key, value);
    },
    async delete(key: string) {
      store.delete(key);
    },
    async list({ prefix = "" }: { prefix?: string } = {}) {
      const keys = [...store.keys()]
        .filter((name) => name.startsWith(prefix))
        .map((name) => ({ name }));
      return { keys, list_complete: true, cursor: "" };
    },
  } as unknown as KVNamespace;
}

export function limiter(allowed: number): RateLimit {
  const seen = new Map<string, number>();
  return {
    async limit({ key }: { key: string }) {
      const count = (seen.get(key) ?? 0) + 1;
      seen.set(key, count);
      return { success: count <= allowed };
    },
  } as RateLimit;
}

export function testEnv(overrides: Partial<Env> = {}): Env {
  return {
    OAUTH_KV: memoryKv(),
    USERNAME,
    PASSWORD_HASH: hashSync(PASSWORD, 4),
    BACKENDS: JSON.stringify({
      bramble: { url: "https://bramble.test", token: "bramble-key" },
      homeassistant: { url: "https://ha.test/base/", token: "ha-key" },
    }),
    ALLOWED_REDIRECT_HOSTS: "claude.ai, claude.com, localhost",
    LOGIN_IP_LIMITER: limiter(1000),
    LOGIN_GLOBAL_LIMITER: limiter(1000),
    ...overrides,
  } as Env;
}
