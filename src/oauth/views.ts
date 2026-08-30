/** HTML views for the OAuth authorization flow (error + success pages). */
import { canonicalRedirectUri, isRegistrableRedirectUri, redirectTargetLabel } from "./redirectUri.js";

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

export type ConsentDetails = {
  /** Where the authorization code will be delivered if the user continues. */
  redirectUri: string;
  /** Name the client claims for itself at registration. Never verified. */
  clientName?: string;
  /** What this token will be able to reach, one line per capability. */
  grants?: string[];
  /**
   * Whether a destination allowlist is actually being enforced. False means
   * MCP_ALLOWED_REDIRECT_HOSTS is unset, so any registered client can ask for
   * a code and the destination above is the only thing worth reading.
   */
  allowlisted?: boolean;
};

/**
 * Consent page shown before bouncing the user to PocketID.
 *
 * This page is the last thing between a stranger's registered client and a
 * token that can reach everything below. Registration is public and accepts any
 * HTTPS host, and the client name is whatever the registrant typed, so the page
 * leads with the destination the code would actually be delivered to and with
 * what the token would be able to do — not with the name the client claims.
 */
export function renderAuthorizeConsent(authUrl: string, details: ConsentDetails): Response {
  const href = escapeHtml(authUrl);
  const destination = escapeHtml(redirectTargetLabel(details.redirectUri));
  const app = details.clientName ? escapeHtml(details.clientName) : "";
  const grants = (details.grants ?? []).map((grant) => `<li>${escapeHtml(grant)}</li>`).join("");
  const unenforced = details.allowlisted === false;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize access — vmhq-mcp</title>
  <style>
    body{font-family:system-ui,-apple-system,sans-serif;background:#0c0c0c;color:#ededed;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1.5rem}
    .card{display:flex;flex-direction:column;gap:1.25rem;padding:2rem;width:100%;max-width:420px}
    h1{margin:0;font-size:1.45rem;font-weight:600;letter-spacing:-.01em;text-align:center}
    p{margin:0;color:#8a8a8a;font-size:.9rem;line-height:1.5}
    .dest{background:#141414;border:1px solid #2a2a2a;border-radius:8px;padding:.9rem 1rem}
    .dest .label{display:block;color:#8a8a8a;font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.3rem}
    .dest .host{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:1rem;color:#fff;word-break:break-all}
    .claim{color:#8a8a8a;font-size:.85rem}
    .claim strong{color:#ededed;font-weight:500}
    ul{margin:0;padding-left:1.1rem;color:#b0b0b0;font-size:.85rem;line-height:1.6}
    .warn{background:#2a1414;border:1px solid #5c2020;border-radius:8px;padding:.85rem 1rem;color:#fca5a5;font-size:.85rem;line-height:1.5}
    .btn{display:block;width:100%;box-sizing:border-box;padding:.8rem 1rem;background:#000;color:#fff;border:1px solid #2a2a2a;border-radius:8px;font-size:.95rem;font-weight:500;text-decoration:none;text-align:center;transition:border-color .15s,background .15s}
    .btn:hover{background:#161616;border-color:#3a3a3a}
    .foot{color:#6a6a6a;font-size:.8rem;text-align:center}
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize access</h1>
    <div class="dest">
      <span class="label">Access will be sent to</span>
      <span class="host">${destination}</span>
    </div>
    ${app ? `<p class="claim">This client calls itself <strong>${app}</strong>. That name is self-reported and has not been verified — trust the destination above, not the name.</p>` : ""}
    ${unenforced ? `<div class="warn">No destination allowlist is configured, so any client that registered with this server can request access. Check the destination above before continuing.</div>` : ""}
    ${grants ? `<div><p style="margin-bottom:.4rem">Continuing grants it:</p><ul>${grants}</ul></div>` : ""}
    <a class="btn" href="${href}">Continue to PocketID</a>
    <p class="foot">If you did not start this from your MCP client, close this page.</p>
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
  // Defense in depth: never emit an auto-redirect page to a scheme that
  // registration would reject (protects against legacy persisted state).
  if (!isRegistrableRedirectUri(redirectUrl)) {
    return renderAuthorizeError("The redirect target is not allowed.");
  }
  const href = escapeHtml(redirectUrl);
  // JSON.stringify does not escape "/", so a URL containing "</script>" would
  // terminate the inline <script> block. Escape "<" as < for safe embedding.
  const jsUrl = JSON.stringify(redirectUrl).replace(/</g, "\\u003c");
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
