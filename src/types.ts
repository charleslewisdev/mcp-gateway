import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export interface BackendConfig {
  url: string;
  token: string;
}

export interface GrantProps {
  username: string;
  credentialId: string; // see credentialId() in credentials.ts
}

export interface Env {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  USERNAME: string;
  PASSWORD_HASH: string;
  BACKENDS: string; // JSON string: Record<string, BackendConfig>
  ALLOWED_REDIRECT_HOSTS: string; // Comma-separated hostnames
  LOGIN_IP_LIMITER: RateLimit;
  LOGIN_GLOBAL_LIMITER: RateLimit;
}
