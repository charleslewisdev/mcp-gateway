// No form-action here: Chrome applies it to the redirect back to the client too.
export const LOGIN_PAGE_HEADERS = {
  "Content-Type": "text/html;charset=UTF-8",
  "Cache-Control": "no-store",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
};

export function renderLoginPage(opts: {
  error?: string;
  clientName?: string;
  redirectHost: string;
  backend: string;
  oauthParams: string;
}): string {
  const { error, clientName, redirectHost, backend, oauthParams } = opts;
  const displayName = clientName || "An application";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Gateway — Sign In</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }

    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 2.5rem 2rem;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    }

    .logo {
      text-align: center;
      margin-bottom: 0.5rem;
      font-size: 2rem;
    }

    h1 {
      text-align: center;
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 0.25rem;
    }

    .subtitle {
      text-align: center;
      font-size: 0.875rem;
      color: #94a3b8;
      margin-bottom: 0.5rem;
    }

    .redirect-host {
      text-align: center;
      font-size: 0.8125rem;
      color: #94a3b8;
      margin-bottom: 2rem;
    }

    .redirect-host strong { color: #e2e8f0; }

    .client-name {
      color: #38bdf8;
      font-weight: 500;
    }

    .error {
      background: #450a0a;
      border: 1px solid #dc2626;
      color: #fca5a5;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      font-size: 0.875rem;
      margin-bottom: 1.5rem;
    }

    label {
      display: block;
      font-size: 0.8125rem;
      font-weight: 500;
      color: #94a3b8;
      margin-bottom: 0.375rem;
    }

    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 0.625rem 0.875rem;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      color: #e2e8f0;
      font-size: 0.9375rem;
      outline: none;
      transition: border-color 0.15s;
      margin-bottom: 1rem;
    }

    input:focus {
      border-color: #38bdf8;
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
    }

    button {
      width: 100%;
      padding: 0.75rem;
      background: #2563eb;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 0.9375rem;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.15s;
      margin-top: 0.5rem;
    }

    button:hover { background: #1d4ed8; }
    button:active { background: #1e40af; }

    .footer {
      text-align: center;
      margin-top: 1.5rem;
      font-size: 0.75rem;
      color: #475569;
    }

    .footer a {
      color: #64748b;
      text-decoration: none;
    }

    .footer a:hover { color: #94a3b8; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">&#x1f512;</div>
    <h1>MCP Gateway</h1>
    <p class="subtitle"><span class="client-name">${escapeHtml(displayName)}</span> wants to connect to ${escapeHtml(backend)}</p>
    <p class="redirect-host">Access goes to <strong>${escapeHtml(redirectHost)}</strong>. The name above is self-reported, so check this host.</p>

    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}

    <form method="POST" action="/authorize">
      <input type="hidden" name="oauthParams" value="${escapeHtml(oauthParams)}">

      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autocomplete="username" autofocus>

      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="current-password">

      <button type="submit">Sign in</button>
    </form>

    <div class="footer">
      Powered by <a href="https://github.com/charleslewisdev/mcp-gateway" target="_blank">mcp-gateway</a>
    </div>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
