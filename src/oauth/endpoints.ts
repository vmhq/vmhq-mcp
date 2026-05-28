/**
 * OAuth 2.1 HTTP endpoint handlers and token verification.
 *
 * Standards implemented:
 *   RFC 6749  – OAuth 2.0
 *   RFC 7591  – Dynamic Client Registration
 *   RFC 7636  – PKCE
 *   RFC 8414  – Authorization Server Metadata
 *   RFC 8707  – Resource Indicators
 *   RFC 9728  – OAuth 2.0 Protected Resource Metadata
 */
import { randomBytes } from "node:crypto";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { log } from "../logger.js";
import {
  accessTokens,
  clients,
  codes,
  CODE_TTL_MS,
  constantTimeEqual,
  pruneExpiredOAuthState,
  saveState,
  sha256,
  TOKEN_TTL_S,
  type RegisteredClient,
} from "./state.js";
import {
  expandRedirectUris,
  isRegistrableRedirectUri,
  redirectUriMatches,
} from "./redirectUri.js";
import {
  buildAuthorizationRedirectUrl,
  renderAuthorizeForm,
  renderAuthorizeSuccess,
} from "./views.js";

export type OAuthConfig = {
  publicUrl?: string;
  iconUrl?: string;
};

// ─── CORS headers (required for browser-based OAuth discovery) ────────────────

export const OAUTH_CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
} as const;

function oauthError(error: string, status = 400): Response {
  return Response.json({ error }, { status, headers: OAUTH_CORS_HEADERS });
}

// ─── URL helpers ──────────────────────────────────────────────────────────────

function baseUrl(config: OAuthConfig, req: Request): string {
  return config.publicUrl ? config.publicUrl.replace(/\/$/, "") : new URL(req.url).origin;
}

export function mcpUrl(config: OAuthConfig, req: Request): string {
  return `${baseUrl(config, req)}/mcp`;
}

// ─── Discovery metadata ───────────────────────────────────────────────────────

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

// ─── RFC 7591 – dynamic client registration ───────────────────────────────────

export async function registerClient(req: Request): Promise<Response> {
  let body: Record<string, unknown> = {};
  try { body = await req.json() as Record<string, unknown>; } catch { /* empty body */ }

  const redirectUris = expandRedirectUris(
    Array.isArray(body.redirect_uris)
      ? (body.redirect_uris as unknown[]).filter((u): u is string => typeof u === "string" && isRegistrableRedirectUri(u))
      : [],
  );

  if (redirectUris.length === 0) {
    return oauthError("invalid_redirect_uris");
  }

  const clientId = `vmhq_${randomBytes(18).toString("base64url")}`;
  const clientIdIssuedAt = Math.floor(Date.now() / 1000);
  const client: RegisteredClient = {
    clientId,
    clientIdIssuedAt,
    redirectUris,
    clientName: typeof body.client_name === "string" ? body.client_name.slice(0, 256) : undefined,
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

// ─── GET /oauth/authorize ─────────────────────────────────────────────────────

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
    return oauthError("unsupported_grant_type");
  }

  const ac = codes.get(code);
  // Single-use: delete immediately (even on failure)
  if (codes.delete(code)) saveState();

  if (!ac) {
    return oauthError("invalid_grant");
  }
  if (ac.expiresAt < Date.now()) {
    return oauthError("invalid_grant");
  }
  if (ac.clientId !== clientId) {
    return oauthError("invalid_grant");
  }
  // RFC 8252 §7.3: match redirect URI port-agnostic for loopback
  if (!redirectUriMatches(redirectUri, ac.redirectUri)) {
    return oauthError("invalid_grant");
  }
  // PKCE S256 verification
  if (sha256(codeVerifier) !== ac.codeChallenge) {
    return oauthError("invalid_grant");
  }
  // RFC 8707: if resource was bound at authorize time it must match token request
  if (ac.resource && resource && ac.resource !== resource) {
    return oauthError("invalid_target");
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
  if (!token) return oauthError("invalid_request");

  const existed = accessTokens.delete(sha256(token));
  if (existed) saveState();

  return Response.json({}, { headers: OAUTH_CORS_HEADERS });
}

// ─── Token verification ───────────────────────────────────────────────────────

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

/** Returns true if the token is a valid, non-expired OAuth access token. */
export function isOAuthAccessToken(token: string): boolean {
  return verifyAccessToken(token) !== undefined;
}
