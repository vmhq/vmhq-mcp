/** HTML views for the OAuth authorization flow (login form + success page). */
import { canonicalRedirectUri } from "./redirectUri.js";

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const FORM_SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
} as const;

const SUCCESS_PAGE_CSP = {
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
} as const;

const ERROR_MESSAGES: Record<string, string> = {
  "1": "Invalid token. Please try again.",
  client_not_found: "This client is no longer registered. Please remove this MCP server from Claude.ai and re-add it to trigger fresh registration.",
  invalid_redirect_uri: "The redirect URI is not registered for this client.",
  invalid_pkce: "PKCE validation failed. The client must use S256 code challenge method.",
};

export function renderAuthorizeForm(p: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  state: string;
  scope: string;
  resource: string;
  error?: string;
}): Response {
  const errorMsg = p.error ? (ERROR_MESSAGES[p.error] ?? "An error occurred. Please try again.") : "";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize — vmhq-mcp</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#0f0f0f;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:2rem;width:100%;max-width:420px}
    h1{margin:0 0 .5rem;font-size:1.25rem}
    p{margin:0 0 1.5rem;color:#888;font-size:.9rem}
    label{display:block;margin-bottom:.4rem;font-size:.85rem;color:#aaa}
    input[type=password]{width:100%;box-sizing:border-box;padding:.6rem .8rem;border-radius:8px;border:1px solid #333;background:#111;color:#e0e0e0;font-size:1rem;outline:none}
    input[type=password]:focus{border-color:#555}
    button{margin-top:1rem;width:100%;padding:.7rem;border-radius:8px;border:none;background:#3b82f6;color:#fff;font-size:1rem;cursor:pointer}
    button:hover{background:#2563eb}
    .error{background:#3f1212;border:1px solid #7f2020;border-radius:8px;color:#fca5a5;font-size:.9rem;padding:.75rem 1rem;margin-bottom:1.25rem;line-height:1.4}
  </style>
</head>
<body>
  <div class="card">
    <h1>vmhq-mcp</h1>
    <p>Enter your access token to authorize this connection.</p>
    ${errorMsg ? `<div class="error">${escapeHtml(errorMsg)}</div>` : ""}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${escapeHtml(p.clientId)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(p.redirectUri)}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(p.codeChallenge)}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(p.codeChallengeMethod)}">
      <input type="hidden" name="state" value="${escapeHtml(p.state)}">
      <input type="hidden" name="scope" value="${escapeHtml(p.scope)}">
      <input type="hidden" name="resource" value="${escapeHtml(p.resource)}">
      <label for="token">Access Token</label>
      <input type="password" id="token" name="token" autofocus placeholder="vmhq_…" autocomplete="current-password">
      <button type="submit">Authorize</button>
    </form>
  </div>
</body>
</html>`;

  return new Response(html, {
    status: errorMsg ? 400 : 200,
    headers: { "Content-Type": "text/html; charset=utf-8", ...FORM_SECURITY_HEADERS },
  });
}

export function buildAuthorizationRedirectUrl(redirectUri: string, code: string, state: string): string {
  const target = canonicalRedirectUri(redirectUri);
  const redirect = new URL(target);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);
  return redirect.toString();
}

/** HTML success page with auto-redirect (works better in OAuth popups than a bare 303). */
export function renderAuthorizeSuccess(redirectUrl: string): Response {
  const href = escapeHtml(redirectUrl);
  const jsUrl = JSON.stringify(redirectUrl);
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="0;url=${href}">
  <title>Authorized — vmhq-mcp</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#0f0f0f;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:2rem;width:100%;max-width:420px;text-align:center}
    h1{margin:0 0 .5rem;font-size:1.25rem;color:#86efac}
    p{margin:0 0 1.25rem;color:#888;font-size:.9rem;line-height:1.5}
    a{color:#3b82f6;text-decoration:none;font-weight:500}
    a:hover{text-decoration:underline}
  </style>
</head>
<body>
  <div class="card">
    <h1>Connected</h1>
    <p>Authorization succeeded. Returning you to Claude…</p>
    <p><a href="${href}">Continue to Claude</a> if you are not redirected automatically.</p>
  </div>
  <script>setTimeout(function(){window.location.replace(${jsUrl});},100);</script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", ...SUCCESS_PAGE_CSP },
  });
}
