import type { OAuthResourceHandler } from "@cloudflare/workers-oauth-provider";
import { backendPathAfterName } from "./backends.js";
import { credentialId } from "./credentials.js";
import type { BackendConfig, Env, GrantProps } from "./types.js";

// Request headers a backend receives. Anything else, such as Cookie or a
// forwarded identity header, stops here.
const FORWARDED_HEADERS = [
  "accept",
  "content-type",
  "last-event-id",
  "mcp-protocol-version",
  "mcp-session-id",
  "user-agent",
];

/**
 * API handler — proxies authenticated MCP requests to one backend.
 *
 * Route pattern: /api/:backend/*
 * Everything after the backend name is forwarded to the backend URL.
 */
export function createProxyHandler(
  backendName: string,
  backend: BackendConfig
): OAuthResourceHandler<Env, GrantProps> {
  return {
    async fetch(request, env, ctx) {
      if (ctx.props.credentialId !== (await credentialId(env))) {
        return new Response("Credentials have changed", {
          status: 401,
          headers: { "WWW-Authenticate": 'Bearer error="invalid_token"' },
        });
      }

      const url = new URL(request.url);

      // Build the target URL.
      // backend.url is the full base (e.g. "https://bramble.example.com")
      // remainingPath is whatever comes after /api/{backend} (e.g. "/mcp")
      const base = backend.url.replace(/\/$/, "");
      const targetUrl = new URL(base + backendPathAfterName(url.pathname));
      targetUrl.search = url.search;

      const headers = new Headers();
      for (const name of FORWARDED_HEADERS) {
        const value = request.headers.get(name);
        if (value !== null) headers.set(name, value);
      }
      // The OAuth Bearer token stops here; the backend gets its own API key
      headers.set("Authorization", `Bearer ${backend.token}`);

      const proxyRequest = new Request(targetUrl.toString(), {
        method: request.method,
        headers,
        body: request.body,
        // @ts-expect-error — duplex needed for streaming request bodies in Workers
        duplex: "half",
      });

      try {
        const response = await fetch(proxyRequest);

        // The OAuth library adds the rest of the CORS headers; this one lets
        // browser clients read mcp-session-id
        const proxyResponse = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
        proxyResponse.headers.set(
          "Access-Control-Expose-Headers",
          "mcp-session-id"
        );
        return proxyResponse;
      } catch (err) {
        console.error(`Failed to reach backend "${backendName}":`, err);
        return new Response(`Failed to reach backend "${backendName}"`, {
          status: 502,
        });
      }
    },
  };
}
