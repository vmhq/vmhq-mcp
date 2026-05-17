/**
 * OAuth 2.1 implementation for MCP servers.
 *
 * Standards implemented:
 *   RFC 6749  – OAuth 2.0
 *   RFC 7636  – PKCE
 *   RFC 8252  – OAuth 2.0 for Native Apps (loopback port-agnostic matching)
 *   RFC 8414  – Authorization Server Metadata
 *   RFC 8707  – Resource Indicators
 *   RFC 9728  – OAuth 2.0 Protected Resource Metadata
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { log } from "./logger.js";

// ─── Public config ────────────────────────────────────────────────────────────

export type OAuthConfig = {
  publicUrl?: string;
  iconUrl?: string;
};

// ─── Internal types ───────────────────────────────────────────────────────────

type RegisteredClient = {
  clientId: string;
  clientIdIssuedAt: number;
  redirectUris: string[];
  clientName?: string;
};

type AuthorizationCode = {
  clientId: string;
  /** Exact redirect URI used in the authorize request (stored for validation) */
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  /** RFC 8707 resource indicator (optional) */
  resource?: string;
  expiresAt: number;
};

type StoredToken = {
  clientId: string;
  scopes: string[];
  resource?: string;
  expiresAt: number;
};

// ─── In-memory state ──────────────────────────────────────────────────────────

const clients = new Map<string, RegisteredClient>();
const codes = new Map<string, AuthorizationCode>();
/** token SHA-256 hash → StoredToken */
const accessTokens = new Map<string, StoredToken>();

// ─── Persistence ──────────────────────────────────────────────────────────────

const STATE_PATH = process.env.MCP_OAUTH_STATE_PATH ?? "./data/oauth-state.json";
const CODE_TTL_MS = 5 * 60 * 1000;          // 5 min
const TOKEN_TTL_S = 60 * 60 * 24 * 90;      // 90 days

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function constantTimeEqual(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

function loadState(): void {
  try {
    const raw = readFileSync(STATE_PATH, "utf-8");
    const saved = JSON.parse(raw) as {
      clients?: Array<[string, RegisteredClient]>;
      authorizationCodes?: Array<[string, AuthorizationCode]>;
      accessTokens?: Array<[string, StoredToken | number]>;
    };

    if (Array.isArray(saved.clients)) {
      for (const [id, c] of saved.clients) clients.set(id, c);
    }

    const now = Date.now();
    if (Array.isArray(saved.authorizationCodes)) {
      for (const [code, ac] of saved.authorizationCodes) {
        if (ac.expiresAt > now) codes.set(code, ac);
      }
    }

    if (Array.isArray(saved.accessTokens)) {
      for (const [hash, data] of saved.accessTokens) {
        // Backwards-compat: old format stored just a number (expiresAt)
        if (typeof data === "number") {
          if (data > now) {
            accessTokens.set(hash, { clientId: "legacy", scopes: ["mcp"], expiresAt: data });
          }
        } else if (typeof data === "object" && data !== null && data.expiresAt > now) {
          accessTokens.set(hash, data);
        }
      }
    }
  } catch {
    // Fresh start — no persisted state yet
  }
}

function saveState(): void {
  try {
    mkdirSync(dirname(STATE_PATH), { recursive: true });
    const payload = {
      clients: [...clients.entries()],
      authorizationCodes: [...codes.entries()],
      accessTokens: [...accessTokens.entries()],
    };
    const tmp = `${STATE_PATH}.tmp`;
    writeFileSync(tmp, JSON.stringify(payload), "utf-8");
    chmodSync(tmp, 0o600);
    renameSync(tmp, STATE_PATH);
    chmodSync(STATE_PATH, 0o600);
  } catch (err) {
    log("error", "oauth_state_persist_failed", { error: err instanceof Error ? err.message : String(err) });
  }
}

export function pruneExpiredOAuthState(now = Date.now()): void {
  let dirty = false;

  for (const [code, ac] of codes) {
    if (ac.expiresAt <= now) { codes.delete(code); dirty = true; }
  }
  for (const [hash, tok] of accessTokens) {
    if (tok.expiresAt <= now) { accessTokens.delete(hash); dirty = true; }
  }

  if (dirty) saveState();
}

/** Reload clients, authorization codes, and tokens from disk (for tests and hot recovery). */
export function reloadPersistedOAuthState(): void {
  clients.clear();
  codes.clear();
  accessTokens.clear();
  loadState();
}

loadState();
setInterval(() => pruneExpiredOAuthState(), 60 * 60 * 1000).unref?.();

// ─── URL helpers ──────────────────────────────────────────────────────────────

function baseUrl(config: OAuthConfig, req: Request): string {
  return config.publicUrl ? config.publicUrl.replace(/\/$/, "") : new URL(req.url).origin;
}

export function mcpUrl(config: OAuthConfig, req: Request): string {
  return `${baseUrl(config, req)}/mcp`;
}

// ─── CORS headers (required for browser-based OAuth discovery) ────────────────

export const OAUTH_CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
} as const;

// ─── Redirect URI validation ──────────────────────────────────────────────────

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Claude.ai web connector callback (https://claude.com/docs/connectors/building/authentication). */
export const CLAUDE_WEB_AUTH_CALLBACK = "https://claude.ai/api/mcp/auth_callback";

/** Legacy/wrong URIs some clients register; map to the canonical Claude web callback. */
const REDIRECT_URI_ALIASES: Record<string, string> = {
  "https://claude.ai/callback": CLAUDE_WEB_AUTH_CALLBACK,
};

export function canonicalRedirectUri(uri: string): string {
  return REDIRECT_URI_ALIASES[uri] ?? uri;
}

function expandRedirectUris(uris: string[]): string[] {
  const out = new Set<string>();
  for (const uri of uris) {
    out.add(uri);
    out.add(canonicalRedirectUri(uri));
    for (const [alias, target] of Object.entries(REDIRECT_URI_ALIASES)) {
      if (uri === target) out.add(alias);
    }
  }
  return [...out];
}

/**
 * Returns true if a redirect URI is allowed for registration.
 * Accepts: loopback http, private-use schemes (native apps), HTTPS.
 */
function isRegistrableRedirectUri(uri: string): boolean {
  try {
    const p = new URL(uri);
    if (p.username || p.password || p.hash) return false;

    // RFC 8252 §8.3 – loopback: must use http (not https)
    if (LOOPBACK.has(p.hostname)) return p.protocol === "http:";

    // RFC 8252 §7.1 – private-use URI schemes (e.g. claude://, myapp://)
    if (p.protocol !== "https:" && p.protocol !== "http:") return true;

    // Standard HTTPS
    return p.protocol === "https:" && p.hostname !== "0.0.0.0" && !p.hostname.includes("*");
  } catch {
    return false;
  }
}

/**
 * RFC 8252 §7.3 – when matching redirect URIs at authorize time, loopback
 * addresses must accept any port (native clients bind an ephemeral port).
 * All other URIs require an exact match.
 */
function redirectUriMatches(requested: string, registered: string): boolean {
  if (requested === registered) return true;
  if (canonicalRedirectUri(requested) === canonicalRedirectUri(registered)) return true;
  try {
    const req = new URL(requested);
    const reg = new URL(registered);
    if (!LOOPBACK.has(req.hostname)) return false;
    // Same scheme, host, path and search — ignore port
    return (
      req.protocol === reg.protocol &&
      req.hostname === reg.hostname &&
      req.pathname === reg.pathname &&
      req.search === reg.search
    );
  } catch {
    return false;
  }
}

// ─── OAuth endpoints ──────────────────────────────────────────────────────────

const FORM_SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
} as const;

/** 401 response with RFC 9728 WWW-Authenticate header */
export function unauthorized(config: OAuthConfig, req: Request): Response {
  const root = baseUrl(config, req);
  return Response.json(
    { error: "unauthorized" },
    {
      status: 401,
      headers: {
        "WWW-Authenticate": `Bearer realm="${root}", resource_metadata="${root}/.well-known/oauth-protected-resource"`,
        ...OAUTH_CORS_HEADERS,
      },
    },
  );
}

/** RFC 9728 – /.well-known/oauth-protected-resource */
export function protectedResourceMetadata(config: OAuthConfig, req: Request): Response {
  const root = baseUrl(config, req);
  return Response.json(
    {
      resource: `${root}/mcp`,
      authorization_servers: [root],
      bearer_methods_supported: ["header"],
      scopes_supported: ["mcp"],
    },
    { headers: OAUTH_CORS_HEADERS },
  );
}

/** RFC 8414 – /.well-known/oauth-authorization-server */
export function authorizationServerMetadata(config: OAuthConfig, req: Request): Response {
  const root = baseUrl(config, req);
  return Response.json(
    {
      issuer: root,
      authorization_endpoint: `${root}/oauth/authorize`,
      token_endpoint: `${root}/oauth/token`,
      registration_endpoint: `${root}/oauth/register`,
      revocation_endpoint: `${root}/oauth/revoke`,
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

/** RFC 7591 – dynamic client registration */
export async function registerClient(req: Request): Promise<Response> {
  let body: Record<string, unknown> = {};
  try { body = await req.json() as Record<string, unknown>; } catch { /* empty body */ }

  const redirectUris = expandRedirectUris(
    Array.isArray(body.redirect_uris)
      ? (body.redirect_uris as unknown[]).filter((u): u is string => typeof u === "string" && isRegistrableRedirectUri(u))
      : [],
  );

  if (redirectUris.length === 0) {
    return Response.json({ error: "invalid_redirect_uris" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }

  const clientId = `vmhq_${randomBytes(18).toString("base64url")}`;
  const clientIdIssuedAt = Math.floor(Date.now() / 1000);
  const client: RegisteredClient = {
    clientId,
    clientIdIssuedAt,
    redirectUris,
    clientName: typeof body.client_name === "string" ? body.client_name : undefined,
  };
  clients.set(clientId, client);
  saveState();

  log("info", "oauth_client_registered", { clientId, redirectUriCount: redirectUris.length });

  return Response.json(
    {
      client_id: clientId,
      client_id_issued_at: clientIdIssuedAt,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "mcp",
      ...(client.clientName ? { client_name: client.clientName } : {}),
    },
    { status: 201, headers: OAUTH_CORS_HEADERS },
  );
}

// ─── Authorization form ───────────────────────────────────────────────────────

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const ERROR_MESSAGES: Record<string, string> = {
  "1": "Invalid token. Please try again.",
  client_not_found: "This client is no longer registered. Please remove this MCP server from Claude.ai and re-add it to trigger fresh registration.",
  invalid_redirect_uri: "The redirect URI is not registered for this client.",
  invalid_pkce: "PKCE validation failed. The client must use S256 code challenge method.",
};

function renderAuthorizeForm(p: {
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

const SUCCESS_PAGE_CSP = {
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
} as const;

function buildAuthorizationRedirectUrl(redirectUri: string, code: string, state: string): string {
  const target = canonicalRedirectUri(redirectUri);
  const redirect = new URL(target);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);
  return redirect.toString();
}

/** HTML success page with auto-redirect (works better in OAuth popups than a bare 303). */
function renderAuthorizeSuccess(redirectUrl: string): Response {
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

export function authorizeForm(req: Request, _config: OAuthConfig): Response {
  const url = new URL(req.url);
  const get = (k: string) => url.searchParams.get(k) ?? "";
  return renderAuthorizeForm({
    clientId: get("client_id"),
    redirectUri: get("redirect_uri"),
    codeChallenge: get("code_challenge"),
    codeChallengeMethod: get("code_challenge_method"),
    state: get("state"),
    scope: get("scope"),
    resource: get("resource"),
    error: get("error") || undefined,
  });
}

// ─── POST /oauth/authorize ────────────────────────────────────────────────────

async function parseFormOrJson(req: Request): Promise<Record<string, string>> {
  const ct = req.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    const body = await req.json().catch(() => ({})) as Record<string, unknown>;
    return Object.fromEntries(Object.entries(body).map(([k, v]) => [k, String(v ?? "")]));
  }
  const form = await req.formData();
  return Object.fromEntries([...form.entries()].map(([k, v]) => [k, String(v)]));
}

export async function authorize(req: Request, serverToken: string, _config: OAuthConfig): Promise<Response> {
  const form = await parseFormOrJson(req);
  const {
    token = "",
    client_id: clientId = "",
    redirect_uri: redirectUri = "",
    code_challenge: codeChallenge = "",
    code_challenge_method: codeChallengeMethod = "",
    state = "",
    scope = "mcp",
    resource = "",
  } = form;

  const formCtx = { clientId, redirectUri, codeChallenge, codeChallengeMethod, state, scope, resource };

  // 1. Validate the server secret the user typed
  if (!constantTimeEqual(token, serverToken)) {
    log("info", "oauth_authorize_invalid_token", { clientId });
    return renderAuthorizeForm({ ...formCtx, error: "1" });
  }

  // 2. Client must exist and redirect URI must be registered (port-agnostic for loopback)
  const client = clients.get(clientId);
  if (!client) {
    log("error", "oauth_authorize_client_not_found", { clientId });
    return renderAuthorizeForm({ ...formCtx, error: "client_not_found" });
  }
  const matchedUri = client.redirectUris.find((r) => redirectUriMatches(redirectUri, r));
  if (!matchedUri || !isRegistrableRedirectUri(redirectUri)) {
    log("error", "oauth_authorize_invalid_redirect_uri", { clientId, redirectUri });
    return renderAuthorizeForm({ ...formCtx, error: "invalid_redirect_uri" });
  }

  // 3. PKCE: must be S256
  if (!codeChallenge || codeChallengeMethod !== "S256") {
    log("error", "oauth_authorize_invalid_pkce", { clientId });
    return renderAuthorizeForm({ ...formCtx, error: "invalid_pkce" });
  }

  // 4. Issue authorization code
  pruneExpiredOAuthState();

  const code = randomBytes(24).toString("base64url");
  const scopes = scope ? scope.split(/\s+/).filter(Boolean) : ["mcp"];

  codes.set(code, {
    clientId,
    redirectUri,
    codeChallenge,
    scopes,
    resource: resource || undefined,
    expiresAt: Date.now() + CODE_TTL_MS,
  });
  saveState();

  const redirectUrl = buildAuthorizationRedirectUrl(redirectUri, code, state);

  log("info", "oauth_authorization_code_issued", { clientId, redirectHost: new URL(redirectUrl).host });
  return renderAuthorizeSuccess(redirectUrl);
}

// ─── POST /oauth/token ────────────────────────────────────────────────────────

export async function exchangeToken(req: Request): Promise<Response> {
  const params = await parseFormOrJson(req);
  const {
    grant_type: grantType = "",
    code = "",
    redirect_uri: redirectUri = "",
    client_id: clientId = "",
    code_verifier: codeVerifier = "",
    resource = "",
  } = params;

  if (grantType !== "authorization_code") {
    return Response.json({ error: "unsupported_grant_type" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }

  const ac = codes.get(code);
  // Single-use: delete immediately (even on failure)
  if (codes.delete(code)) saveState();

  if (!ac) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }
  if (ac.expiresAt < Date.now()) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }
  if (ac.clientId !== clientId) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }
  // RFC 8252 §7.3: match redirect URI port-agnostic for loopback
  if (!redirectUriMatches(redirectUri, ac.redirectUri)) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }
  // PKCE S256 verification
  if (sha256(codeVerifier) !== ac.codeChallenge) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }
  // RFC 8707: if resource was bound at authorize time it must match token request
  if (ac.resource && resource && ac.resource !== resource) {
    return Response.json({ error: "invalid_target" }, { status: 400, headers: OAUTH_CORS_HEADERS });
  }

  const accessToken = `vmhq_mcp_${randomBytes(32).toString("base64url")}`;
  const expiresAt = Date.now() + TOKEN_TTL_S * 1000;
  accessTokens.set(sha256(accessToken), {
    clientId,
    scopes: ac.scopes,
    resource: ac.resource,
    expiresAt,
  });
  saveState();

  log("info", "oauth_access_token_issued", { clientId, expiresIn: TOKEN_TTL_S });

  return Response.json(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_TTL_S,
      scope: ac.scopes.join(" "),
    },
    { headers: OAUTH_CORS_HEADERS },
  );
}

// ─── POST /oauth/revoke ───────────────────────────────────────────────────────

export async function revokeToken(req: Request): Promise<Response> {
  const params = await parseFormOrJson(req);
  const token = params.token ?? "";
  if (!token) return Response.json({ error: "invalid_request" }, { status: 400, headers: OAUTH_CORS_HEADERS });

  const existed = accessTokens.delete(sha256(token));
  if (existed) saveState();

  return Response.json({}, { headers: OAUTH_CORS_HEADERS });
}

// ─── Token verification ───────────────────────────────────────────────────────

/**
 * Returns true if the token is a valid, non-expired OAuth access token.
 * Use `verifyAccessToken` when you need the full AuthInfo.
 */
export function isOAuthAccessToken(token: string): boolean {
  if (!token) return false;
  const hash = sha256(token);
  const stored = accessTokens.get(hash);
  if (!stored) return false;
  if (stored.expiresAt <= Date.now()) {
    accessTokens.delete(hash);
    saveState();
    return false;
  }
  return true;
}

/**
 * Verifies an OAuth access token and returns structured AuthInfo.
 * Returns undefined if the token is invalid or expired.
 */
export function verifyAccessToken(token: string): AuthInfo | undefined {
  if (!token) return undefined;
  const hash = sha256(token);
  const stored = accessTokens.get(hash);
  if (!stored) return undefined;
  if (stored.expiresAt <= Date.now()) {
    accessTokens.delete(hash);
    saveState();
    return undefined;
  }
  return {
    token,
    clientId: stored.clientId,
    scopes: stored.scopes,
    expiresAt: Math.floor(stored.expiresAt / 1000),
    ...(stored.resource ? { resource: new URL(stored.resource) } : {}),
  };
}
