import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export interface BackendConfig {
  url: string;
  token: string;
}

export interface Env {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  USERNAME: string;
  PASSWORD_HASH: string;
  BACKENDS: string; // JSON string: Record<string, BackendConfig>
}
