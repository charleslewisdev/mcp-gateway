import type { BackendConfig, Env } from "./types.js";

/**
 * API handler — proxies authenticated MCP requests to the configured backend.
 *
 * Route pattern: /:backend/*
 * The first path segment after the apiRoute prefix identifies the backend.
 * Everything after it is forwarded to the backend URL.
 */
export const proxyHandler = {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);

    // Parse backends config
    let backends: Record<string, BackendConfig>;
    try {
      backends = JSON.parse(env.BACKENDS);
    } catch {
      return new Response("Server misconfiguration: invalid BACKENDS", {
        status: 500,
      });
    }

    // Extract backend name from path: /api/{backend}/...
    // The apiRoute is "/api/" so url.pathname starts with /api/
    const pathAfterApi = url.pathname.replace(/^\/api\//, "");
    const slashIndex = pathAfterApi.indexOf("/");
    const backendName =
      slashIndex === -1 ? pathAfterApi : pathAfterApi.slice(0, slashIndex);
    const remainingPath = slashIndex === -1 ? "" : pathAfterApi.slice(slashIndex);

    const backend = backends[backendName];
    if (!backend) {
      return new Response(
        `Unknown backend: ${backendName}. Available: ${Object.keys(backends).join(", ")}`,
        { status: 404 }
      );
    }

    // Build the target URL.
    // backend.url is the full base (e.g. "https://bramble.example.com/mcp")
    // remainingPath is whatever comes after /api/{backend} (e.g. "" or "/sse")
    const base = backend.url.replace(/\/$/, "");
    const targetUrl = new URL(base + remainingPath);
    targetUrl.search = url.search;

    const headers = new Headers(request.headers);
    // Replace the OAuth Bearer token with the backend's API key
    headers.set("Authorization", `Bearer ${backend.token}`);
    // Remove host header so fetch uses the target
    headers.delete("host");

    const proxyRequest = new Request(targetUrl.toString(), {
      method: request.method,
      headers,
      body: request.body,
      // @ts-expect-error — duplex needed for streaming request bodies in Workers
      duplex: "half",
    });

    try {
      return await fetch(proxyRequest);
    } catch (err) {
      return new Response(
        `Failed to reach backend "${backendName}": ${err instanceof Error ? err.message : String(err)}`,
        { status: 502 }
      );
    }
  },
};
