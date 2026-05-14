import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { log } from "./logger.js";

export type OAuthConfig = {
  publicUrl?: string;
  iconUrl?: string;
};

type Client = {
  clientId: string;
  redirectUris: string[];
  clientName?: string;
};

type AuthorizationCode = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  expiresAt: number;
};

const clients = new Map<string, Client>();
const codes = new Map<string, AuthorizationCode>();
// token SHA-256 hash → expiresAt (ms since epoch)
const accessTokens = new Map<string, number>();

const STATE_PATH = process.env.MCP_OAUTH_STATE_PATH ?? "./data/oauth-state.json";
const AUTHORIZATION_CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 90;

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function constantTimeEqual(a: string, b: string): boolean {
  const hashA = createHash("sha256").update(a).digest();
  const hashB = createHash("sha256").update(b).digest();
  return timingSafeEqual(hashA, hashB);
}

function loadState(): void {
  try {
    const raw = readFileSync(STATE_PATH, "utf-8");
    const state = JSON.parse(raw) as {
      clients?: Array<[string, Client]>;
      accessTokens?: Array<[string, number]>;
    };

    if (Array.isArray(state.clients)) {
      for (const [id, client] of state.clients) {
        clients.set(id, client);
      }
    }

    const now = Date.now();
    if (Array.isArray(state.accessTokens)) {
      for (const [tokenHash, expiresAt] of state.accessTokens) {
        if (expiresAt > now) {
          accessTokens.set(tokenHash, expiresAt);
        }
      }
    }
  } catch {
    // No state file yet — fresh start
  }
}

function saveState(): void {
  try {
    mkdirSync(dirname(STATE_PATH), { recursive: true });
    const state = {
      clients: [...clients.entries()],
      accessTokens: [...accessTokens.entries()],
    };
    const tmpPath = `${STATE_PATH}.tmp`;
    writeFileSync(tmpPath, JSON.stringify(state), "utf-8");
    chmodSync(tmpPath, 0o600);
    renameSync(tmpPath, STATE_PATH);
    chmodSync(STATE_PATH, 0o600);
  } catch (err) {
    log("error", "oauth_state_persist_failed", { error: err instanceof Error ? err.message : String(err) });
  }
}

export function pruneExpiredOAuthState(now = Date.now()): void {
  let changed = false;

  for (const [code, authorizationCode] of codes.entries()) {
    if (authorizationCode.expiresAt <= now) {
      codes.delete(code);
      changed = true;
    }
  }

  for (const [tokenHash, expiresAt] of accessTokens.entries()) {
    if (expiresAt <= now) {
      accessTokens.delete(tokenHash);
      changed = true;
    }
  }

  if (changed) {
    saveState();
  }
}

loadState();
setInterval(() => pruneExpiredOAuthState(), 60 * 60 * 1000).unref?.();

function baseUrl(config: OAuthConfig, req: Request): string {
  if (config.publicUrl) {
    return config.publicUrl.replace(/\/$/, "");
  }

  const url = new URL(req.url);
  return url.origin;
}

export function mcpUrl(config: OAuthConfig, req: Request): string {
  return `${baseUrl(config, req)}/mcp`;
}

export function isOAuthAccessToken(token: string): boolean {
  if (!token) return false;

  const tokenHash = sha256(token);
  const expiresAt = accessTokens.get(tokenHash);
  if (expiresAt === undefined) return false;
  if (expiresAt <= Date.now()) {
    accessTokens.delete(tokenHash);
    saveState();
    return false;
  }
  return true;
}

export function unauthorized(config: OAuthConfig, req: Request): Response {
  const root = baseUrl(config, req);

  return Response.json(
    { error: "unauthorized" },
    {
      status: 401,
      headers: {
        "WWW-Authenticate": `Bearer resource_metadata="${root}/.well-known/oauth-protected-resource"`,
      },
    },
  );
}

export function protectedResourceMetadata(config: OAuthConfig, req: Request): Response {
  const root = baseUrl(config, req);

  return Response.json({
    resource: mcpUrl(config, req),
    authorization_servers: [root],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"],
  });
}

export function authorizationServerMetadata(config: OAuthConfig, req: Request): Response {
  const root = baseUrl(config, req);

  return Response.json({
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
  });
}

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isValidRedirectUri(uri: string): boolean {
  try {
    const parsed = new URL(uri);

    // RFC 8252 §8.3: loopback redirect URIs use http with 127.0.0.1/localhost/[::1]
    if (LOOPBACK_HOSTNAMES.has(parsed.hostname)) {
      return parsed.protocol === "http:" && !parsed.username && !parsed.password && !parsed.hash;
    }

    // Private-use URI schemes for native apps (RFC 8252 §7.1)
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return !parsed.username && !parsed.password && !parsed.hash;
    }

    // Standard HTTPS redirect URIs
    if (parsed.protocol !== "https:") return false;
    if (parsed.hostname === "0.0.0.0") return false;
    if (parsed.username || parsed.password) return false;
    if (parsed.hostname.includes("*")) return false;
    if (parsed.hash) return false;
    return true;
  } catch {
    return false;
  }
}

export async function registerClient(req: Request, _accessToken?: string): Promise<Response> {
  const body = await req.json().catch(() => ({}));
  const redirectUris = Array.isArray(body.redirect_uris)
    ? body.redirect_uris.filter((uri: unknown): uri is string => typeof uri === "string" && isValidRedirectUri(uri))
    : [];

  if (redirectUris.length === 0) {
    return Response.json({ error: "invalid_redirect_uris" }, { status: 400 });
  }

  const clientId = `vmhq_${randomBytes(18).toString("base64url")}`;
  clients.set(clientId, {
    clientId,
    redirectUris,
    clientName: typeof body.client_name === "string" ? body.client_name : undefined,
  });
  saveState();

  log("info", "oauth_client_registered", { clientId, redirectUriCount: redirectUris.length });

  return Response.json({
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: redirectUris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code"],
    response_types: ["code"],
    scope: "mcp",
  });
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

export function authorizeForm(req: Request, config: OAuthConfig): Response {
  const url = new URL(req.url);
  const clientId = url.searchParams.get("client_id") ?? "";
  const redirectUri = url.searchParams.get("redirect_uri") ?? "";
  const codeChallenge = url.searchParams.get("code_challenge") ?? "";
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? "";
  const state = url.searchParams.get("state") ?? "";
  const error = url.searchParams.get("error");

  const errorMessages: Record<string, string> = {
    "1": "Invalid token. Please try again.",
    "client_not_found": "Client not found. The application may need to re-register.",
    "invalid_redirect_uri": "The redirect URI is not allowed. It must use HTTPS and must not be a localhost address.",
    "invalid_pkce": "PKCE validation failed. The client must use S256 code challenge method.",
  };
  const errorMessage = error ? (errorMessages[error] ?? "An error occurred. Please try again.") : "";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline'; form-action 'self'">
  <title>Authorize — vmhq-mcp</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f0f0f; color: #e0e0e0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px; padding: 2rem; width: 100%; max-width: 380px; }
    h1 { margin: 0 0 0.5rem; font-size: 1.25rem; }
    p { margin: 0 0 1.5rem; color: #888; font-size: 0.9rem; }
    label { display: block; margin-bottom: 0.4rem; font-size: 0.85rem; color: #aaa; }
    input[type="password"] { width: 100%; box-sizing: border-box; padding: 0.6rem 0.8rem; border-radius: 8px; border: 1px solid #333; background: #111; color: #e0e0e0; font-size: 1rem; outline: none; }
    input[type="password"]:focus { border-color: #555; }
    button { margin-top: 1rem; width: 100%; padding: 0.7rem; border-radius: 8px; border: none; background: #3b82f6; color: #fff; font-size: 1rem; cursor: pointer; }
    button:hover { background: #2563eb; }
    .error { color: #f87171; font-size: 0.85rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>vmhq-mcp</h1>
    <p>Enter your access token to authorize this connection.</p>
    ${errorMessage ? `<div class="error">${escapeHtml(errorMessage)}</div>` : ""}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${escapeHtml(clientId)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(codeChallenge)}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(codeChallengeMethod)}">
      <input type="hidden" name="state" value="${escapeHtml(state)}">
      <label for="token">Access Token</label>
      <input type="password" id="token" name="token" autofocus placeholder="vmhq_…" autocomplete="current-password">
      <button type="submit">Authorize</button>
    </form>
  </div>
</body>
</html>`;

  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8", ...SECURITY_HEADERS } });
}

export async function authorize(req: Request, accessToken: string, config: OAuthConfig): Promise<Response> {
  const form = await req.formData();
  const token = String(form.get("token") ?? "");
  const clientId = String(form.get("client_id") ?? "");
  const redirectUri = String(form.get("redirect_uri") ?? "");
  const codeChallenge = String(form.get("code_challenge") ?? "");
  const codeChallengeMethod = String(form.get("code_challenge_method") ?? "");
  const state = form.get("state") as string | null;

  if (!constantTimeEqual(token, accessToken)) {
    log("info", "oauth_authorize_invalid_token", { clientId });
    const params = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, code_challenge: codeChallenge, code_challenge_method: codeChallengeMethod, error: "1" });
    if (state) params.set("state", state);
    const errorRedirectOrigin = config.publicUrl ? new URL(config.publicUrl).origin : new URL(req.url).origin;
    return Response.redirect(new URL(`/oauth/authorize?${params}`, errorRedirectOrigin).toString(), 303);
  }

  const client = clients.get(clientId);

  if (!client || !client.redirectUris.includes(redirectUri) || !isValidRedirectUri(redirectUri)) {
    if (!client) {
      log("error", "oauth_authorize_client_not_found", { clientId });
    } else if (!isValidRedirectUri(redirectUri)) {
      log("error", "oauth_authorize_invalid_redirect_uri", { clientId, redirectUri });
    } else {
      log("error", "oauth_authorize_redirect_uri_not_registered", { clientId, redirectUri, registered: client.redirectUris });
    }
    const params = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, code_challenge: codeChallenge, code_challenge_method: codeChallengeMethod, error: !client ? "client_not_found" : "invalid_redirect_uri" });
    if (state) params.set("state", state);
    const errorRedirectOrigin = config.publicUrl ? new URL(config.publicUrl).origin : new URL(req.url).origin;
    return Response.redirect(new URL(`/oauth/authorize?${params}`, errorRedirectOrigin).toString(), 303);
  }

  if (!codeChallenge || codeChallengeMethod !== "S256") {
    log("error", "oauth_authorize_invalid_pkce", { clientId });
    const params = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, code_challenge: codeChallenge, code_challenge_method: codeChallengeMethod, error: "invalid_pkce" });
    if (state) params.set("state", state);
    const errorRedirectOrigin = config.publicUrl ? new URL(config.publicUrl).origin : new URL(req.url).origin;
    return Response.redirect(new URL(`/oauth/authorize?${params}`, errorRedirectOrigin).toString(), 303);
  }

  pruneExpiredOAuthState();

  const code = randomBytes(24).toString("base64url");
  codes.set(code, {
    clientId,
    redirectUri,
    codeChallenge,
    expiresAt: Date.now() + AUTHORIZATION_CODE_TTL_MS,
  });

  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) {
    redirect.searchParams.set("state", state);
  }

  log("info", "oauth_authorization_code_issued", { clientId, redirectUri: redirect.toString() });

  return Response.redirect(redirect.toString(), 303);
}

function s256(verifier: string): string {
  return sha256(verifier);
}

async function parseFormOrJson(req: Request): Promise<Record<string, string>> {
  const contentType = req.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const body = await req.json().catch(() => ({})) as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(body).map(([k, v]) => [k, String(v ?? "")])
    );
  }
  const form = await req.formData();
  return Object.fromEntries([...form.entries()].map(([k, v]) => [k, String(v)]));
}

export async function exchangeToken(req: Request): Promise<Response> {
  const params = await parseFormOrJson(req);
  const grantType = params.grant_type ?? "";
  const code = params.code ?? "";
  const redirectUri = params.redirect_uri ?? "";
  const clientId = params.client_id ?? "";
  const codeVerifier = params.code_verifier ?? "";
  const authorizationCode = codes.get(code);

  if (grantType !== "authorization_code" || !authorizationCode) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  // Authorization codes are single-use, including failed exchange attempts.
  codes.delete(code);

  if (authorizationCode.expiresAt < Date.now()) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  if (authorizationCode.clientId !== clientId || authorizationCode.redirectUri !== redirectUri) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  if (s256(codeVerifier) !== authorizationCode.codeChallenge) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  const accessToken = `vmhq_mcp_${randomBytes(32).toString("base64url")}`;
  accessTokens.set(sha256(accessToken), Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000);
  saveState();

  log("info", "oauth_access_token_issued", { clientId, expiresIn: ACCESS_TOKEN_TTL_SECONDS });

  return Response.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    scope: "mcp",
  });
}

export async function revokeToken(req: Request): Promise<Response> {
  const params = await parseFormOrJson(req);
  const token = params.token ?? "";

  if (!token) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  const existed = accessTokens.delete(sha256(token));

  if (existed) {
    saveState();
  }

  return Response.json({});
}
