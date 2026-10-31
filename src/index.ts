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

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    let backends: Record<string, BackendConfig>;
    try {
      backends = parseBackends(env);
    } catch {
      return new Response("Server misconfiguration: invalid BACKENDS", {
        status: 500,
      });
    }

    // Each backend is its own OAuth resource, so a token works for one backend
    const resourceFor = (name: string) => `${url.origin}/api/${name}`;
    const authorizationServer = new OAuthAuthorizationServer<Env>({
      issuer: url.origin,
      resources: Object.keys(backends).map(resourceFor),
      clientRegistrationEndpoint: "/oauth/register",
      accessTokenTTL: 3600,
      refreshTokenTTL: 2592000, // 30 days
      tokenExchangeCallback: async ({ props, env }) => {
        if ((props as GrantProps).credentialId !== (await credentialId(env))) {
          throw new OAuthError("invalid_grant", {
            description: "Credentials have changed",
          });
        }
      },
    });

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
        resource: resourceFor(backendName),
        authorization_servers: [url.origin],
      },
      validateToken: (env) => (resource, token) =>
        authorizationServer.validateToken<GrantProps>(resource, token, env),
      handler: createProxyHandler(backendName, backends[backendName]),
    });
    return resource.fetch(request, env, ctx);
  },
};
