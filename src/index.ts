import {
  OAuthAuthorizationServer,
  OAuthError,
  OAuthResourceServer,
} from "@cloudflare/workers-oauth-provider";
import { handleAuthorize } from "./auth-handler.js";
import { backendNameFromPath, parseBackends } from "./backends.js";
import { credentialId } from "./credentials.js";
import { createProxyHandler } from "./proxy-handler.js";
import type { BackendConfig, Env, GrantProps } from "./types.js";

function resourceFor(origin: string, backendName: string): string {
  return `${origin}/api/${backendName}`;
}

function createAuthorizationServer(
  origin: string,
  backends: Record<string, BackendConfig>,
  env: Env
): OAuthAuthorizationServer<Env> {
  return new OAuthAuthorizationServer<Env>({
    issuer: origin,
    // Each backend is its own OAuth resource, so a token works for one backend
    resources: Object.keys(backends).map((name) => resourceFor(origin, name)),
    clientRegistrationEndpoint: "/oauth/register",
    accessTokenTTL: 3600,
    refreshTokenTTL: 2592000, // 30 days
    clientRegistrationCallback: async ({ request }) => {
      const key = request.headers.get("CF-Connecting-IP") ?? "unknown";
      const { success } = await env.REGISTER_LIMITER.limit({ key });
      if (!success) {
        return {
          code: "too_many_requests",
          description: "Too many registrations",
          status: 429,
        };
      }
    },
    tokenExchangeCallback: async ({ props }) => {
      if ((props as GrantProps).credentialId !== (await credentialId(env))) {
        throw new OAuthError("invalid_grant", {
          description: "Credentials have changed",
        });
      }
    },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    let backends: Record<string, BackendConfig>;
    let authorizationServer: OAuthAuthorizationServer<Env>;
    try {
      backends = parseBackends(env);
      authorizationServer = createAuthorizationServer(url.origin, backends, env);
    } catch (err) {
      console.error("Invalid configuration:", err);
      return new Response("Server misconfiguration", { status: 500 });
    }

    if (url.pathname === "/authorize") {
      const oauth = authorizationServer.getOAuthApi(env);
      return handleAuthorize(request, env, oauth);
    }

    const backendName = backendNameFromPath(url.pathname);
    if (backendName === null) {
      return authorizationServer.fetch(request, env, ctx);
    }
    if (!Object.hasOwn(backends, backendName)) {
      return new Response("Unknown backend", { status: 404 });
    }

    const resource = new OAuthResourceServer<Env, GrantProps>({
      resourceMetadata: {
        resource: resourceFor(url.origin, backendName),
        authorization_servers: [url.origin],
      },
      validateToken: (env) => (resource, token) =>
        authorizationServer.validateToken<GrantProps>(resource, token, env),
      handler: createProxyHandler(backendName, backends[backendName]),
    });
    return resource.fetch(request, env, ctx);
  },
};
