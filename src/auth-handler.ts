import type { AuthRequest } from "@cloudflare/workers-oauth-provider";
import { compare } from "bcryptjs";
import { findBackend, parseBackendPath } from "./backends.js";
import { credentialId } from "./credentials.js";
import { LOGIN_PAGE_HEADERS, renderLoginPage } from "./login-page.js";
import type { Env, GrantProps } from "./types.js";

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

interface VerifiedAuthRequest {
  oauthReq: AuthRequest;
  page: { clientName?: string; redirectHost: string; backend: string; oauthParams: string };
}

/**
 * Parses an authorize request and applies the gateway's policy. Registration is
 * open, so the client's name proves nothing: the checks here are what stop a
 * self-registered client from collecting a code.
 */
async function verifyAuthRequest(
  request: Request,
  env: Env,
  oauthParams: string
): Promise<VerifiedAuthRequest> {
  const authorizeUrl = new URL(request.url);
  authorizeUrl.search = oauthParams;
  const oauthReq = await env.OAUTH_PROVIDER.parseAuthRequest(
    new Request(authorizeUrl.toString())
  );

  if (!oauthReq.codeChallenge || oauthReq.codeChallengeMethod !== "S256") {
    throw new Error("PKCE with S256 is required");
  }

  const redirectHost = new URL(oauthReq.redirectUri).hostname;
  if (!allowedRedirectHosts(env).includes(redirectHost)) {
    throw new Error(`Redirect host not allowed: ${redirectHost}`);
  }

  const client = await env.OAUTH_PROVIDER.lookupClient(oauthReq.clientId);
  return {
    oauthReq,
    page: {
      clientName: client?.clientName,
      redirectHost,
      backend: requestedBackend(oauthReq, authorizeUrl.origin, env),
      oauthParams,
    },
  };
}

function allowedRedirectHosts(env: Env): string[] {
  return (env.ALLOWED_REDIRECT_HOSTS ?? "")
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * The library binds a token to the resource named here, so requiring one is
 * what keeps a grant to a single backend.
 */
function requestedBackend(
  oauthReq: AuthRequest,
  origin: string,
  env: Env
): string {
  const resource =
    typeof oauthReq.resource === "string" ? new URL(oauthReq.resource) : null;
  const backend = resource && parseBackendPath(resource.pathname);
  if (
    resource?.origin !== origin ||
    !backend ||
    !findBackend(env, backend.name)
  ) {
    throw new Error("The resource parameter must name a configured backend");
  }
  return backend.name;
}

async function handleAuthorizeGet(
  request: Request,
  env: Env
): Promise<Response> {
  try {
    const { page } = await verifyAuthRequest(
      request,
      env,
      new URL(request.url).search
    );
    return loginPage(page);
  } catch (err) {
    return authorizationError(err);
  }
}

async function handleAuthorizePost(
  request: Request,
  env: Env
): Promise<Response> {
  const formData = await request.formData();
  const username = formData.get("username") as string | null;
  const password = formData.get("password") as string | null;
  const oauthParams = (formData.get("oauthParams") as string | null) ?? "";

  let verified: VerifiedAuthRequest;
  try {
    verified = await verifyAuthRequest(request, env, oauthParams);
  } catch (err) {
    return authorizationError(err);
  }
  const { oauthReq, page } = verified;

  if (!username || !password) {
    return loginPage(page, "Missing credentials", 401);
  }

  if (!(await underLoginLimit(request, env))) {
    return loginPage(page, "Too many attempts. Try again in a minute.", 429, {
      "Retry-After": "60",
    });
  }

  // Run bcrypt for every username so timing doesn't reveal which one is valid
  const passwordMatches = await compare(password, env.PASSWORD_HASH);
  if (!passwordMatches || username !== env.USERNAME) {
    return loginPage(page, "Invalid username or password", 401);
  }

  try {
    // Complete the authorization — issue the grant
    const props: GrantProps = {
      username,
      credentialId: await credentialId(env),
    };
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthReq,
      userId: username,
      metadata: { label: "mcp-gateway" },
      scope: oauthReq.scope,
      props,
    });

    return Response.redirect(redirectTo, 302);
  } catch (err) {
    return authorizationError(err);
  }
}

async function underLoginLimit(request: Request, env: Env): Promise<boolean> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const [perIp, global] = await Promise.all([
    env.LOGIN_IP_LIMITER.limit({ key: ip }),
    env.LOGIN_GLOBAL_LIMITER.limit({ key: "login" }),
  ]);
  return perIp.success && global.success;
}

function loginPage(
  page: VerifiedAuthRequest["page"],
  error?: string,
  status = 200,
  headers: Record<string, string> = {}
): Response {
  return new Response(renderLoginPage({ ...page, error }), {
    status,
    headers: { ...LOGIN_PAGE_HEADERS, ...headers },
  });
}

function authorizationError(err: unknown): Response {
  const message = err instanceof Error ? err.message : String(err);
  return new Response(`Authorization error: ${message}`, { status: 400 });
}
