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
  USERNAME: string;
  PASSWORD_HASH: string;
  BACKENDS: string; // JSON string: Record<string, BackendConfig>
  ALLOWED_REDIRECT_HOSTS: string; // Comma-separated hostnames
  LOGIN_IP_LIMITER: RateLimit;
  LOGIN_GLOBAL_LIMITER: RateLimit;
  REGISTER_LIMITER: RateLimit;
}
