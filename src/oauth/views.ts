/** HTML views for the OAuth authorization flow (error + success pages). */
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

/**
 * Error page shown when the authorization flow cannot proceed (bad client,
 * redirect URI, PKCE, or an identity-provider failure). Always a 400.
 */
export function renderAuthorizeError(message: string): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorization error — vmhq-mcp</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#0f0f0f;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:2rem;width:100%;max-width:420px}
    h1{margin:0 0 .5rem;font-size:1.25rem;color:#fca5a5}
    p{margin:0;color:#aaa;font-size:.95rem;line-height:1.5}
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorization error</h1>
    <p>${escapeHtml(message)}</p>
  </div>
</body>
</html>`;

  return new Response(html, {
    status: 400,
    headers: { "Content-Type": "text/html; charset=utf-8", ...FORM_SECURITY_HEADERS },
  });
}

/**
 * Intermediate consent page shown before bouncing the user to PocketID. Instead
 * of an immediate 302 redirect, the user lands on a branded page and clicks a
 * single "Sign in with PocketID" button that links to the PocketID auth URL.
 */
export function renderAuthorizeConsent(
  authUrl: string,
  opts: { clientName?: string } = {},
): Response {
  const href = escapeHtml(authUrl);
  const app = opts.clientName ? escapeHtml(opts.clientName) : "";
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in — vmhq-mcp</title>
  <style>
    body{font-family:system-ui,-apple-system,sans-serif;background:#0c0c0c;color:#ededed;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .card{display:flex;flex-direction:column;align-items:center;gap:1.5rem;padding:2rem;width:100%;max-width:380px;text-align:center}
    h1{margin:0;font-size:1.6rem;font-weight:600;letter-spacing:-.01em}
    p{margin:0;color:#8a8a8a;font-size:.9rem;line-height:1.5}
    .btn{display:block;width:100%;box-sizing:border-box;padding:.8rem 1rem;background:#000;color:#fff;border:1px solid #2a2a2a;border-radius:8px;font-size:.95rem;font-weight:500;text-decoration:none;transition:border-color .15s,background .15s}
    .btn:hover{background:#161616;border-color:#3a3a3a}
  </style>
</head>
<body>
  <div class="card">
    <h1>VMHQ</h1>
    ${app ? `<p>${app} wants to connect to your MCP server.</p>` : ""}
    <a class="btn" href="${href}">Sign in with PocketID</a>
  </div>
</body>
</html>`;

  return new Response(html, {
    status: 200,
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
