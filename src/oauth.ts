/**
 * OAuth 2.0 + PKCE server implementation for MCP.
 *
 * Standards: RFC 6749 (Authorization Code), RFC 7636 (PKCE),
 *            RFC 7591 (Dynamic Client Registration), RFC 8414 (AS Metadata),
 *            RFC 9728 (Protected Resource Metadata), RFC 8252 (Native Apps)
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { log } from "./logger.js";

// ── Public config ──────────────────────────────────────────────────────────

export type OAuthConfig = {
  publicUrl?: string;
  iconUrl?: string;
};

// ── Storage types ──────────────────────────────────────────────────────────

type OAuthClient = {
  id: string;
  redirectUris: string[];
  name?: string;
};

type AuthCode = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  expiresAt: number;
};

// ── In-memory state ────────────────────────────────────────────────────────

const clients = new Map<string, OAuthClient>();
const codes = new Map<string, AuthCode>();
// token SHA-256 hash → expiresAt timestamp (ms since epoch)
const tokens = new Map<string, number>();

// ── Constants ──────────────────────────────────────────────────────────────

const STATE_PATH = process.env.MCP_OAUTH_STATE_PATH ?? "./data/oauth-state.json";
const CODE_TTL_MS = 5 * 60 * 1000;          // 5 minutes
const TOKEN_TTL_S = 60 * 60 * 24 * 90;      // 90 days

// ── Crypto ─────────────────────────────────────────────────────────────────

function digest(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function constantTimeEqual(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

// ── State persistence ──────────────────────────────────────────────────────

function loadState(): void {
  try {
    const raw = readFileSync(STATE_PATH, "utf-8");
    const data = JSON.parse(raw) as {
      clients?: Array<[string, OAuthClient]>;
      tokens?: Array<[string, number]>;
    };

    if (Array.isArray(data.clients)) {
      for (const [id, c] of data.clients) clients.set(id, c);
    }

    const now = Date.now();
    if (Array.isArray(data.tokens)) {
      for (const [h, exp] of data.tokens) {
        if (exp > now) tokens.set(h, exp);
      }
    }
  } catch {
    // First run — no state file yet
  }
}

function saveState(): void {
  try {
    mkdirSync(dirname(STATE_PATH), { recursive: true });
    const tmp = `${STATE_PATH}.tmp`;
    writeFileSync(tmp, JSON.stringify({ clients: [...clients.entries()], tokens: [...tokens.entries()] }), "utf-8");
    chmodSync(tmp, 0o600);
    renameSync(tmp, STATE_PATH);
    chmodSync(STATE_PATH, 0o600);
  } catch (err) {
    log("error", "oauth_state_persist_failed", { error: err instanceof Error ? err.message : String(err) });
  }
}

export function pruneExpiredOAuthState(now = Date.now()): void {
  let dirty = false;
  for (const [code, c] of codes) {
    if (c.expiresAt <= now) { codes.delete(code); dirty = true; }
  }
  for (const [h, exp] of tokens) {
    if (exp <= now) { tokens.delete(h); dirty = true; }
  }
  if (dirty) saveState();
}

loadState();
setInterval(() => pruneExpiredOAuthState(), 60 * 60 * 1000).unref?.();

// ── URL helpers ────────────────────────────────────────────────────────────

function root(config: OAuthConfig, req: Request): string {
  return config.publicUrl?.replace(/\/$/, "") ?? new URL(req.url).origin;
}

export function mcpUrl(config: OAuthConfig, req: Request): string {
  return `${root(config, req)}/mcp`;
}

// ── Shared headers ─────────────────────────────────────────────────────────

export const OAUTH_CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const FORM_HEADERS = {
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

// ── Discovery metadata ─────────────────────────────────────────────────────

export function unauthorized(config: OAuthConfig, req: Request): Response {
  const base = root(config, req);
  return Response.json(
    { error: "unauthorized" },
    {
      status: 401,
      headers: {
        "WWW-Authenticate": `Bearer realm="${base}", resource_metadata="${base}/.well-known/oauth-protected-resource"`,
        ...OAUTH_CORS_HEADERS,
      },
    },
  );
}

export function protectedResourceMetadata(config: OAuthConfig, req: Request): Response {
  const base = root(config, req);
  return Response.json(
    {
      resource: `${base}/mcp`,
      authorization_servers: [base],
      bearer_methods_supported: ["header"],
      scopes_supported: ["mcp"],
    },
    { headers: OAUTH_CORS_HEADERS },
  );
}

export function authorizationServerMetadata(config: OAuthConfig, req: Request): Response {
  const base = root(config, req);
  return Response.json(
    {
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      revocation_endpoint: `${base}/oauth/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["mcp"],
      ...(config.iconUrl ? { logo_uri: config.iconUrl } : {}),
    },
    { headers: OAUTH_CORS_HEADERS },
  );
}

// ── Redirect URI validation (RFC 8252) ────────────────────────────────────

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isValidRedirectUri(uri: string): boolean {
  try {
    const u = new URL(uri);

    // No credentials or fragments allowed in any redirect URI
    if (u.username || u.password || u.hash) return false;

    // RFC 8252 §8.3: loopback must use http (any port)
    if (LOOPBACK.has(u.hostname)) return u.protocol === "http:";

    // RFC 8252 §7.1: private-use URI schemes (non http/https)
    if (u.protocol !== "http:" && u.protocol !== "https:") return true;

    // All other http (non-loopback) are rejected
    if (u.protocol !== "https:") return false;

    // https with wildcard or 0.0.0.0 are rejected
    if (u.hostname === "0.0.0.0" || u.hostname.includes("*")) return false;

    return true;
  } catch {
    return false;
  }
}

// ── Dynamic Client Registration (RFC 7591) ─────────────────────────────────

export async function registerClient(req: Request): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return Response.json({ error: "invalid_request" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }

  const redirectUris = Array.isArray(body.redirect_uris)
    ? (body.redirect_uris as unknown[]).filter(
        (u): u is string => typeof u === "string" && isValidRedirectUri(u),
      )
    : [];

  if (redirectUris.length === 0) {
    return Response.json({ error: "invalid_redirect_uris" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }

  const id = `vmhq_${randomBytes(18).toString("base64url")}`;
  clients.set(id, {
    id,
    redirectUris,
    name: typeof body.client_name === "string" ? body.client_name : undefined,
  });
  saveState();

  log("info", "oauth_client_registered", { clientId: id, redirectUriCount: redirectUris.length });

  return Response.json(
    {
      client_id: id,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "mcp",
    },
    { headers: OAUTH_CORS_HEADERS },
  );
}

// ── Authorization form ─────────────────────────────────────────────────────

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function authorizeForm(req: Request, _config: OAuthConfig): Response {
  const p = new URL(req.url).searchParams;
  const error = p.get("error");
  const msgs: Record<string, string> = {
    "1": "Invalid token. Please try again.",
    client_not_found: "Client not found. The application may need to re-register.",
    invalid_redirect_uri: "The redirect URI is not allowed. It must use HTTPS and must not be a localhost address.",
    invalid_pkce: "PKCE validation failed. The client must use S256 code challenge method.",
  };
  const errMsg = error ? (msgs[error] ?? "An error occurred. Please try again.") : "";

  const hidden = (["client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state"] as const)
    .map((k) => `<input type="hidden" name="${k}" value="${esc(p.get(k) ?? "")}">`)
    .join("\n      ");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Authorize — vmhq-mcp</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:#0f0f0f;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:2rem;width:100%;max-width:380px}
    h1{font-size:1.25rem;margin-bottom:.5rem}
    p{color:#888;font-size:.9rem;margin-bottom:1.5rem}
    label{display:block;margin-bottom:.4rem;font-size:.85rem;color:#aaa}
    input[type=password]{width:100%;padding:.6rem .8rem;border-radius:8px;border:1px solid #333;background:#111;color:#e0e0e0;font-size:1rem;outline:none}
    input[type=password]:focus{border-color:#555}
    button{margin-top:1rem;width:100%;padding:.7rem;border-radius:8px;border:none;background:#3b82f6;color:#fff;font-size:1rem;cursor:pointer}
    button:hover{background:#2563eb}
    .err{color:#f87171;font-size:.85rem;margin-bottom:1rem}
  </style>
</head>
<body>
  <div class="card">
    <h1>vmhq-mcp</h1>
    <p>Enter your access token to authorize this connection.</p>
    ${errMsg ? `<div class="err">${esc(errMsg)}</div>` : ""}
    <form method="POST" action="/oauth/authorize">
      ${hidden}
      <label for="token">Access Token</label>
      <input type="password" id="token" name="token" autofocus placeholder="vmhq_…" autocomplete="current-password">
      <button type="submit">Authorize</button>
    </form>
  </div>
</body>
</html>`;

  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8", ...FORM_HEADERS } });
}

// ── Authorization endpoint (POST) ──────────────────────────────────────────

export async function authorize(req: Request, accessToken: string, _config: OAuthConfig): Promise<Response> {
  const fd = await req.formData();
  const get = (k: string) => String(fd.get(k) ?? "");

  const token = get("token");
  const clientId = get("client_id");
  const redirectUri = get("redirect_uri");
  const codeChallenge = get("code_challenge");
  const codeChallengeMethod = get("code_challenge_method");
  const state = fd.get("state") as string | null;

  const errorRedirect = (reason: string): Response => {
    const qs = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, code_challenge: codeChallenge, code_challenge_method: codeChallengeMethod, error: reason });
    if (state) qs.set("state", state);
    return new Response(null, { status: 303, headers: { Location: `/oauth/authorize?${qs}` } });
  };

  if (!constantTimeEqual(token, accessToken)) {
    log("info", "oauth_authorize_invalid_token", { clientId });
    return errorRedirect("1");
  }

  const client = clients.get(clientId);
  if (!client) {
    log("error", "oauth_authorize_client_not_found", { clientId });
    return errorRedirect("client_not_found");
  }

  if (!client.redirectUris.includes(redirectUri) || !isValidRedirectUri(redirectUri)) {
    log("error", "oauth_authorize_invalid_redirect_uri", { clientId, redirectUri });
    return errorRedirect("invalid_redirect_uri");
  }

  if (!codeChallenge || codeChallengeMethod !== "S256") {
    log("error", "oauth_authorize_invalid_pkce", { clientId });
    return errorRedirect("invalid_pkce");
  }

  pruneExpiredOAuthState();

  const code = randomBytes(24).toString("base64url");
  codes.set(code, { clientId, redirectUri, codeChallenge, expiresAt: Date.now() + CODE_TTL_MS });

  const dest = new URL(redirectUri);
  dest.searchParams.set("code", code);
  if (state) dest.searchParams.set("state", state);

  log("info", "oauth_authorization_code_issued", { clientId });

  return Response.redirect(dest.toString(), 303);
}

// ── Token endpoint (RFC 6749 §4.1.3 + RFC 7636) ───────────────────────────

async function parseBody(req: Request): Promise<Record<string, string>> {
  const ct = req.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
    return Object.fromEntries(Object.entries(body).map(([k, v]) => [k, String(v ?? "")]));
  }
  const fd = await req.formData();
  return Object.fromEntries([...fd.entries()].map(([k, v]) => [k, String(v)]));
}

export async function exchangeToken(req: Request): Promise<Response> {
  const p = await parseBody(req);

  if (p.grant_type !== "authorization_code") {
    return Response.json({ error: "unsupported_grant_type" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }

  const authCode = codes.get(p.code ?? "");
  codes.delete(p.code ?? ""); // always single-use, including failed attempts

  if (!authCode || authCode.expiresAt < Date.now()) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }

  if (authCode.clientId !== p.client_id || authCode.redirectUri !== p.redirect_uri) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }

  // Verify PKCE S256: SHA-256(code_verifier) == code_challenge
  if (digest(p.code_verifier ?? "") !== authCode.codeChallenge) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }

  const token = `vmhq_mcp_${randomBytes(32).toString("base64url")}`;
  tokens.set(digest(token), Date.now() + TOKEN_TTL_S * 1000);
  saveState();

  log("info", "oauth_access_token_issued", { clientId: p.client_id, expiresIn: TOKEN_TTL_S });

  return Response.json(
    { access_token: token, token_type: "Bearer", expires_in: TOKEN_TTL_S, scope: "mcp" },
    { headers: OAUTH_CORS_HEADERS },
  );
}

// ── Token revocation (RFC 7009) ────────────────────────────────────────────

export async function revokeToken(req: Request): Promise<Response> {
  const p = await parseBody(req);
  if (!p.token) {
    return Response.json({ error: "invalid_request" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }
  const existed = tokens.delete(digest(p.token));
  if (existed) saveState();
  return Response.json({}, { headers: OAUTH_CORS_HEADERS });
}

// ── Token validation ───────────────────────────────────────────────────────

export function isOAuthAccessToken(token: string): boolean {
  if (!token) return false;
  const h = digest(token);
  const exp = tokens.get(h);
  if (exp === undefined) return false;
  if (exp <= Date.now()) {
    tokens.delete(h);
    saveState();
    return false;
  }
  return true;
}
