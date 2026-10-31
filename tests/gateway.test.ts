import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hashSync } from "bcryptjs";
import worker from "../src/index.js";
import type { Env } from "../src/types.js";
import {
  CHALLENGE,
  ORIGIN,
  PASSWORD,
  REDIRECT_URI,
  RESOURCE,
  USERNAME,
  VERIFIER,
  limiter,
  testEnv,
} from "./helpers.js";

const compare = vi.hoisted(() => vi.fn());
vi.mock("bcryptjs", async (importOriginal) => {
  const original = await importOriginal<any>();
  const actual = original.default ?? original;
  compare.mockImplementation(actual.compare);
  const mocked = { ...actual, compare };
  return { ...mocked, default: mocked };
});

const ctx = {
  waitUntil() {},
  passThroughOnException() {},
} as unknown as ExecutionContext;

function call(path: string, env: Env, init?: RequestInit): Promise<Response> {
  return (worker as any).fetch(new Request(ORIGIN + path, init), env, ctx);
}

async function register(env: Env, redirectUri = REDIRECT_URI): Promise<string> {
  const response = await call("/oauth/register", env, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Claude",
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: "none",
    }),
  });
  expect(response.status).toBe(201);
  return ((await response.json()) as { client_id: string }).client_id;
}

function authorizeQuery(
  clientId: string,
  overrides: Record<string, string | null> = {}
): string {
  const params: Record<string, string | null> = {
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    state: "state-1",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    resource: RESOURCE,
    ...overrides,
  };
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== null) query.set(key, value);
  }
  return `?${query}`;
}

function login(
  env: Env,
  query: string,
  credentials: { username?: string; password?: string } = {},
  headers: Record<string, string> = {}
): Promise<Response> {
  const body = new URLSearchParams({
    username: credentials.username ?? USERNAME,
    password: credentials.password ?? PASSWORD,
    oauthParams: query,
  });
  return call("/authorize", env, { method: "POST", body, headers });
}

async function connect(
  env: Env,
  resource = RESOURCE
): Promise<{ access_token: string; refresh_token: string; clientId: string }> {
  const clientId = await register(env);
  const redirect = await login(env, authorizeQuery(clientId, { resource }));
  expect(redirect.status).toBe(302);
  const code = new URL(redirect.headers.get("Location")!).searchParams.get(
    "code"
  )!;
  const response = await call("/oauth/token", env, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      code_verifier: VERIFIER,
      resource,
    }),
  });
  expect(response.status).toBe(200);
  const tokens = (await response.json()) as {
    access_token: string;
    refresh_token: string;
  };
  return { ...tokens, clientId };
}

function refresh(env: Env, clientId: string, refreshToken: string) {
  return call("/oauth/token", env, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
    }),
  });
}

function bearer(token: string, headers: Record<string, string> = {}) {
  return { headers: { Authorization: `Bearer ${token}`, ...headers } };
}

let backendFetch: ReturnType<typeof vi.fn>;

beforeEach(() => {
  compare.mockClear();
  backendFetch = vi.fn(async () => new Response("from backend"));
  vi.stubGlobal("fetch", backendFetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("authorization flow", () => {
  it("leads a client from a 401 to the backend's resource and the issuer", async () => {
    const env = testEnv();

    const challenge = await call("/api/bramble/mcp", env);
    const header = challenge.headers.get("WWW-Authenticate")!;
    const metadataUrl = /resource_metadata="([^"]+)"/.exec(header)![1];
    const metadata = await call(new URL(metadataUrl).pathname, env);
    const body = (await metadata.json()) as {
      resource: string;
      authorization_servers: string[];
    };
    const server = await call("/.well-known/oauth-authorization-server", env);
    const serverBody = (await server.json()) as {
      issuer: string;
      registration_endpoint: string;
      code_challenge_methods_supported: string[];
    };

    expect(challenge.status).toBe(401);
    expect(body.resource).toBe(RESOURCE);
    expect(body.authorization_servers).toEqual([ORIGIN]);
    expect(serverBody.issuer).toBe(ORIGIN);
    expect(serverBody.registration_endpoint).toBe(`${ORIGIN}/oauth/register`);
    expect(serverBody.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("connects a client and proxies with the backend's key", async () => {
    const env = testEnv();
    const { access_token } = await connect(env);

    const response = await call(
      "/api/bramble/mcp?session=1",
      env,
      bearer(access_token)
    );

    expect(await response.text()).toBe("from backend");
    const sent = backendFetch.mock.calls[0][0] as Request;
    expect(sent.url).toBe("https://bramble.test/mcp?session=1");
    expect(sent.headers.get("Authorization")).toBe("Bearer bramble-key");
  });

  it("shows where the code will be sent, on a page that cannot be framed", async () => {
    const env = testEnv();
    const clientId = await register(env);

    const page = await call(`/authorize${authorizeQuery(clientId)}`, env);

    expect(await page.clone().text()).toContain("claude.ai");
    expect(await page.clone().text()).toContain("bramble");
    expect(page.headers.get("X-Frame-Options")).toBe("DENY");
    expect(page.headers.get("Content-Security-Policy")).toContain(
      "frame-ancestors 'none'"
    );
  });

  it("refuses a redirect host outside the allowlist before asking for a password", async () => {
    const env = testEnv();
    const redirectUri = "https://attacker.test/callback";
    const clientId = await register(env, redirectUri);
    const query = authorizeQuery(clientId, { redirect_uri: redirectUri });

    const page = await call(`/authorize${query}`, env);
    const submit = await login(env, query);

    expect(page.status).toBe(400);
    expect(await page.text()).not.toContain("password");
    expect(submit.status).toBe(400);
    expect(submit.headers.get("Location")).toBeNull();
  });

  it("limits registrations from one address", async () => {
    const env = testEnv({ REGISTER_LIMITER: limiter(1) });
    const registration = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": "203.0.113.9",
      },
      body: JSON.stringify({ redirect_uris: [REDIRECT_URI] }),
    };

    await call("/oauth/register", env, registration);
    const blocked = await call("/oauth/register", env, registration);

    expect(blocked.status).toBe(429);
  });

  it("shows a redirect port so it can't pass for the default", async () => {
    const env = testEnv();
    const redirectUri = "https://claude.ai:8443/callback";
    const clientId = await register(env, redirectUri);

    const page = await call(
      `/authorize${authorizeQuery(clientId, { redirect_uri: redirectUri })}`,
      env
    );

    expect(await page.text()).toContain("claude.ai:8443");
  });

  it("refuses every redirect host when the allowlist is unset", async () => {
    const env = testEnv({ ALLOWED_REDIRECT_HOSTS: undefined as never });
    const clientId = await register(env);

    const page = await call(`/authorize${authorizeQuery(clientId)}`, env);

    expect(page.status).toBe(400);
  });

  it.each(["http://localhost:33418/cb", "http://[::1]:33418/cb"])(
    "accepts the loopback redirect %s",
    async (redirectUri) => {
    const env = testEnv({ ALLOWED_REDIRECT_HOSTS: "localhost,[::1]" });
    const clientId = await register(env, redirectUri);

    const page = await call(
      `/authorize${authorizeQuery(clientId, { redirect_uri: redirectUri })}`,
      env
    );

    expect(page.status).toBe(200);
    }
  );

  it.each([
    ["no challenge", { code_challenge: null, code_challenge_method: null }],
    ["plain challenge", { code_challenge_method: "plain" }],
    ["a defaulted method", { code_challenge_method: null }],
  ])("refuses %s", async (_name, overrides) => {
    const env = testEnv();
    const clientId = await register(env);
    const query = authorizeQuery(clientId, overrides);

    const page = await call(`/authorize${query}`, env);
    const submit = await login(env, query);

    expect(page.status).toBe(400);
    expect(submit.status).toBe(400);
  });

  it.each([
    ["no resource", null],
    ["the bare origin", ORIGIN],
    ["an unknown backend", `${ORIGIN}/api/nope`],
    ["an inherited property name", `${ORIGIN}/api/constructor`],
    ["another origin", "https://other.test/api/bramble"],
  ])("refuses %s as the resource", async (_name, resource) => {
    const env = testEnv();
    const clientId = await register(env);

    const page = await call(
      `/authorize${authorizeQuery(clientId, { resource })}`,
      env
    );

    expect(page.status).toBe(400);
  });
});

describe("login", () => {
  it.each([
    ["a missing password", { username: USERNAME }],
    ["a missing username", { password: PASSWORD }],
    ["a file as the password", { username: USERNAME, password: new File(["x"], "p") }],
  ])("rejects %s without running bcrypt", async (_name, fields) => {
    const env = testEnv();
    const clientId = await register(env);
    const body = new FormData();
    body.set("oauthParams", authorizeQuery(clientId));
    for (const [key, value] of Object.entries(fields)) body.set(key, value);

    const response = await call("/authorize", env, { method: "POST", body });

    expect(response.status).toBe(401);
    expect(compare).not.toHaveBeenCalled();
  });

  it("refuses a login with no authorization request", async () => {
    const response = await login(testEnv(), "");

    expect(response.status).toBe(400);
    expect(response.headers.get("Location")).toBeNull();
  });

  it("rejects a wrong password", async () => {
    const env = testEnv();
    const clientId = await register(env);

    const response = await login(env, authorizeQuery(clientId), {
      password: "wrong",
    });

    expect(response.status).toBe(401);
  });

  it("checks the password even when the username is wrong", async () => {
    const env = testEnv();
    const clientId = await register(env);

    const response = await login(env, authorizeQuery(clientId), {
      username: "stranger",
    });

    expect(response.status).toBe(401);
    expect(compare).toHaveBeenCalledOnce();
  });

  it("stops guessing from one address without running bcrypt", async () => {
    const env = testEnv({ LOGIN_IP_LIMITER: limiter(2) });
    const clientId = await register(env);
    const query = authorizeQuery(clientId);
    const from = { "CF-Connecting-IP": "203.0.113.9" };

    await login(env, query, { password: "wrong" }, from);
    await login(env, query, { password: "wrong" }, from);
    compare.mockClear();
    const blocked = await login(env, query, {}, from);
    const other = await login(env, query, {}, {
      "CF-Connecting-IP": "203.0.113.10",
    });

    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("Retry-After")).toBe("60");
    expect(other.status).toBe(302);
    expect(compare).toHaveBeenCalledOnce();
  });

  it("doesn't let one address use up the shared limit", async () => {
    const env = testEnv({
      LOGIN_IP_LIMITER: limiter(1),
      LOGIN_GLOBAL_LIMITER: limiter(2),
    });
    const clientId = await register(env);
    const query = authorizeQuery(clientId);
    const attacker = { "CF-Connecting-IP": "203.0.113.66" };

    for (let attempt = 0; attempt < 5; attempt++) {
      await login(env, query, { password: "wrong" }, attacker);
    }
    const owner = await login(env, query, {}, {
      "CF-Connecting-IP": "198.51.100.1",
    });

    expect(owner.status).toBe(302);
  });

  it("stops guessing spread across addresses", async () => {
    const env = testEnv({ LOGIN_GLOBAL_LIMITER: limiter(1) });
    const clientId = await register(env);
    const query = authorizeQuery(clientId);

    await login(env, query, { password: "wrong" }, {
      "CF-Connecting-IP": "203.0.113.1",
    });
    const blocked = await login(env, query, {}, {
      "CF-Connecting-IP": "203.0.113.2",
    });

    expect(blocked.status).toBe(429);
  });
});

describe("proxy", () => {
  it("answers 404 for an unknown backend or an inherited property name", async () => {
    const env = testEnv();

    const unknown = await call("/api/nope/mcp", env);
    const inherited = await call("/api/constructor/mcp", env);

    expect(unknown.status).toBe(404);
    expect(await unknown.text()).toBe("Unknown backend");
    expect(inherited.status).toBe(404);
  });

  it.each([["invalid JSON", "{"], ["null", "null"], ["no backends", "{}"]])(
    "answers a clean 500 when BACKENDS is %s",
    async (_name, BACKENDS) => {
      const response = await call("/api/bramble/mcp", testEnv({ BACKENDS }));

      expect(response.status).toBe(500);
      expect(await response.text()).toContain("Server misconfiguration");
    }
  );

  it("keeps a token to the backend it was granted for", async () => {
    const env = testEnv();
    const { access_token } = await connect(env);

    const response = await call(
      "/api/homeassistant/mcp",
      env,
      bearer(access_token)
    );

    expect(response.status).toBe(401);
    expect(backendFetch).not.toHaveBeenCalled();
  });

  it("hands redirects to the client instead of carrying the backend key along", async () => {
    const env = testEnv();
    const { access_token } = await connect(env);

    await call("/api/bramble/mcp", env, bearer(access_token));

    expect((backendFetch.mock.calls[0][0] as Request).redirect).toBe("manual");
  });

  it("forwards only the headers MCP needs", async () => {
    const env = testEnv();
    const { access_token } = await connect(env);

    await call(
      "/api/bramble/mcp",
      env,
      bearer(access_token, {
        Accept: "text/event-stream",
        "Content-Type": "application/json",
        Cookie: "session=stolen",
        "Mcp-Protocol-Version": "2025-06-18",
        "Mcp-Session-Id": "session-1",
        "X-Forwarded-User": "admin",
      })
    );

    const sent = (backendFetch.mock.calls[0][0] as Request).headers;
    expect(sent.get("Accept")).toBe("text/event-stream");
    expect(sent.get("Content-Type")).toBe("application/json");
    expect(sent.get("Mcp-Protocol-Version")).toBe("2025-06-18");
    expect(sent.get("Mcp-Session-Id")).toBe("session-1");
    expect(sent.get("Cookie")).toBeNull();
    expect(sent.get("X-Forwarded-User")).toBeNull();
  });

  it("exposes mcp-session-id to browser clients", async () => {
    const env = testEnv();
    const { access_token } = await connect(env);

    const response = await call(
      "/api/bramble/mcp",
      env,
      bearer(access_token, { Origin: "https://claude.ai" })
    );

    expect(response.headers.get("Access-Control-Expose-Headers")).toContain(
      "mcp-session-id"
    );
  });

  it("answers browser preflights before authentication", async () => {
    const response = await call("/api/bramble/mcp", testEnv(), {
      method: "OPTIONS",
      headers: {
        Origin: "https://claude.ai",
        "Access-Control-Request-Headers": "mcp-session-id",
      },
    });

    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://claude.ai"
    );
  });

  it("does not describe backends in its error responses", async () => {
    const env = testEnv();
    const { access_token } = await connect(env);
    backendFetch.mockRejectedValue(new Error("connect to 10.0.0.5 failed"));

    const failed = await call(
      "/api/bramble/mcp",
      env,
      bearer(access_token)
    );

    expect(failed.status).toBe(502);
    expect(await failed.text()).not.toContain("10.0.0.5");
  });

  it("stops serving existing tokens once the password changes", async () => {
    const env = testEnv();
    const { access_token, refresh_token, clientId } = await connect(env);

    env.PASSWORD_HASH = hashSync("a new password", 4);
    const api = await call("/api/bramble/mcp", env, bearer(access_token));
    const renewed = await refresh(env, clientId, refresh_token);

    expect(api.status).toBe(401);
    expect(api.headers.get("WWW-Authenticate")).toContain("invalid_token");
    expect(api.headers.get("WWW-Authenticate")).toContain(
      `resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/api/bramble"`
    );
    expect(backendFetch).not.toHaveBeenCalled();
    expect(renewed.status).toBe(400);
  });
});
