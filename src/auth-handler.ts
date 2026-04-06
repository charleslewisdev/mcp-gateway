import { compare } from "bcryptjs";
import { renderLoginPage } from "./login-page.js";
import type { Env } from "./types.js";

/**
 * Handles the /authorize endpoint — renders login form (GET) and
 * verifies credentials (POST), then completes the OAuth flow.
 */
export const authHandler = {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);

    if (url.pathname === "/authorize") {
      if (request.method === "GET") {
        return handleAuthorizeGet(request, env);
      }
      if (request.method === "POST") {
        return handleAuthorizePost(request, env);
      }
    }

    return new Response("Not found", { status: 404 });
  },
};

async function handleAuthorizeGet(
  request: Request,
  env: Env
): Promise<Response> {
  try {
    const oauthReq = await env.OAUTH_PROVIDER.parseAuthRequest(request);
    const client = await env.OAUTH_PROVIDER.lookupClient(oauthReq.clientId);

    // Serialize the original query string so we can replay it after login
    const oauthParams = new URL(request.url).search;

    return new Response(
      renderLoginPage({
        clientName: client?.clientName ?? undefined,
        oauthParams,
      }),
      { headers: { "Content-Type": "text/html;charset=UTF-8" } }
    );
  } catch (err) {
    return new Response(`Authorization error: ${err instanceof Error ? err.message : String(err)}`, { status: 400 });
  }
}

async function handleAuthorizePost(
  request: Request,
  env: Env
): Promise<Response> {
  const formData = await request.formData();
  const username = formData.get("username") as string | null;
  const password = formData.get("password") as string | null;
  const oauthParams = formData.get("oauthParams") as string | null;

  if (!username || !password || !oauthParams) {
    return loginError("Missing credentials", oauthParams ?? "");
  }

  // Verify credentials
  if (
    username !== env.USERNAME ||
    !(await compare(password, env.PASSWORD_HASH))
  ) {
    return loginError("Invalid username or password", oauthParams);
  }

  // Replay the original OAuth authorize request to parse it.
  // oauthParams is the original query string (e.g. "?client_id=...&redirect_uri=...").
  // We build a synthetic GET request with those params so the library can parse them.
  try {
    const authorizeUrl = new URL(request.url);
    authorizeUrl.search = oauthParams;
    const syntheticRequest = new Request(authorizeUrl.toString(), {
      method: "GET",
    });
    const oauthReq =
      await env.OAUTH_PROVIDER.parseAuthRequest(syntheticRequest);

    // Complete the authorization — issue the grant
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthReq,
      userId: username,
      metadata: { label: "mcp-gateway" },
      scope: oauthReq.scope,
      props: { username },
    });

    return Response.redirect(redirectTo, 302);
  } catch (err) {
    return loginError(
      `Authorization failed: ${err instanceof Error ? err.message : String(err)}`,
      oauthParams
    );
  }
}

function loginError(message: string, oauthParams: string): Response {
  return new Response(renderLoginPage({ error: message, oauthParams }), {
    status: 401,
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}
