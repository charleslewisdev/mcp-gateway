# mcp-gateway

OAuth 2.1 proxy for self-hosted MCP servers. Deploy on Cloudflare Workers, connect from Claude.ai.

**Problem:** Claude.ai MCP connectors require full OAuth 2.1 (Authorization Code + PKCE + Dynamic Client Registration). Most self-hosted MCP servers use simple API keys. No working bridge exists.

**Solution:** A Cloudflare Worker that handles the entire OAuth 2.1 flow with simple username/password auth, then proxies authenticated MCP requests to your backend with the correct Bearer token.

```
Claude.ai  ──OAuth 2.1──▶  mcp-gateway (Cloudflare Worker)  ──Bearer token──▶  your MCP server
```

## Features

- Full OAuth 2.1: Authorization Code + PKCE, Dynamic Client Registration, token refresh
- Simple password auth (bcrypt) — no external IdP required
- Multi-backend routing — one deployment proxies to multiple MCP servers
- Streamable HTTP transport passthrough
- Cloudflare Workers free tier compatible

## Quick Start

### Prerequisites

- [Cloudflare account](https://dash.cloudflare.com/sign-up) (free)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) (`npm i -g wrangler`)
- A self-hosted MCP server with an API key

### 1. Clone and install

```bash
git clone https://github.com/charleslewisdev/mcp-gateway.git
cd mcp-gateway
npm install
```

### 2. Create KV namespace

```bash
wrangler kv namespace create OAUTH_KV
```

Copy the output `id` into `wrangler.jsonc`.

### 3. Configure secrets

```bash
# Your login credentials
wrangler secret put USERNAME
wrangler secret put PASSWORD_HASH

# Generate a bcrypt hash for your password:
# npx bcryptjs-cli hash "your-password"
# Or: node -e "import('bcryptjs').then(b=>b.hash('your-password',10).then(console.log))"

# Backend configuration (JSON)
wrangler secret put BACKENDS
# Example value:
# {"bramble":{"url":"https://bramble.example.com/mcp","token":"your-api-key"}}
```

### 4. Deploy

```bash
wrangler deploy
```

### 5. Configure DNS (optional)

Point a custom domain to your Worker in the Cloudflare dashboard (Workers & Pages > your worker > Settings > Domains & Routes).

### 6. Connect from Claude.ai

In Claude.ai, add a new MCP connector:
- **URL:** `https://your-worker.your-domain.com/api/bramble/mcp`

Claude.ai will handle the OAuth flow automatically — you'll see the login page, enter your credentials, and you're connected.

## Configuration

### Backend routing

The `BACKENDS` secret is a JSON object mapping path prefixes to backend configs:

```json
{
  "bramble": {
    "url": "https://bramble.example.com/mcp",
    "token": "brk_your_api_key"
  },
  "homeassistant": {
    "url": "https://ha.example.com/mcp",
    "token": "ha_your_api_key"
  }
}
```

Each backend is accessible at `/api/{name}/...` — the Worker strips the prefix and forwards to the configured URL with the Bearer token.

### Environment variables

| Variable | Description |
|---|---|
| `USERNAME` | Login username |
| `PASSWORD_HASH` | bcrypt hash of the login password |
| `BACKENDS` | JSON object mapping backend names to `{url, token}` |

### OAuth endpoints (auto-configured)

| Endpoint | Purpose |
|---|---|
| `/.well-known/oauth-authorization-server` | OAuth metadata discovery |
| `/.well-known/oauth-protected-resource` | Resource metadata |
| `/oauth/register` | Dynamic Client Registration |
| `/oauth/token` | Token exchange and refresh |
| `/authorize` | Login page |
| `/api/{backend}/...` | Authenticated proxy to backend |

## How it works

1. Claude.ai discovers OAuth metadata at `/.well-known/oauth-authorization-server`
2. Claude.ai registers itself as a client via Dynamic Client Registration (`/oauth/register`)
3. User is redirected to `/authorize` — sees a login form
4. User enters credentials — Worker verifies against bcrypt hash
5. Worker issues an authorization code, Claude.ai exchanges it for tokens
6. Claude.ai sends MCP requests to `/api/{backend}/...` with the OAuth Bearer token
7. Worker validates the token, swaps it for the backend's API key, and proxies the request

## Tech

- [Cloudflare Workers](https://workers.cloudflare.com/) — serverless runtime
- [`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider) — OAuth 2.1 implementation
- [Cloudflare KV](https://developers.cloudflare.com/kv/) — token and client storage
- [bcryptjs](https://github.com/dcodeIO/bcrypt.js) — password verification

## License

MIT
