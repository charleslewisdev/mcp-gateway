import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { authHandler } from "./auth-handler.js";
import { proxyHandler } from "./proxy-handler.js";
import type { Env } from "./types.js";

export default new OAuthProvider<Env>({
  apiRoute: "/api/",
  apiHandler: proxyHandler,
  defaultHandler: authHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register",
  accessTokenTTL: 3600,
  refreshTokenTTL: 2592000, // 30 days
  allowPlainPKCE: false,
});
