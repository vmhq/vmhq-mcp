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
  pendingAuth,
  PENDING_TTL_MS,
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
  renderAuthorizeConsent,
  renderAuthorizeError,
  renderAuthorizeSuccess,
} from "./views.js";
import {
  buildPocketIdAuthUrl,
  exchangePocketIdCode,
  type PocketIdConfig,
} from "./pocketid.js";
import { readBodyTextCapped, RequestBodyTooLargeError } from "../httpGuards.js";

export type OAuthConfig = {
  publicUrl?: string;
  iconUrl?: string;
  /** PocketID identity provider. When unset, interactive authorization is disabled. */
  pocketId?: PocketIdConfig;
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

/** Redirect URI registered with PocketID for this server (the OIDC callback). */
function callbackUri(config: OAuthConfig, req: Request): string {
  return `${baseUrl(config, req)}/oauth/callback`;
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
  try {
    const text = await readBodyTextCapped(req);
    if (text) body = JSON.parse(text) as Record<string, unknown>;
  } catch (err) {
    if (err instanceof RequestBodyTooLargeError) return oauthError("invalid_request", 413);
    /* malformed/empty body → treat as empty */
  }

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

/**
 * Parse an OAuth request body (JSON or application/x-www-form-urlencoded) with
 * the size cap enforced during the read. Throws RequestBodyTooLargeError when
 * the body is oversized; callers translate that to a 413 response.
 */
async function parseFormOrJson(req: Request): Promise<Record<string, string>> {
  const ct = req.headers.get("content-type") ?? "";
  const text = await readBodyTextCapped(req);
  if (ct.includes("application/json")) {
    let body: Record<string, unknown> = {};
    try { if (text) body = JSON.parse(text) as Record<string, unknown>; } catch { /* malformed → empty */ }
    return Object.fromEntries(Object.entries(body).map(([k, v]) => [k, String(v ?? "")]));
  }
  const form = new URLSearchParams(text);
  return Object.fromEntries([...form.entries()].map(([k, v]) => [k, String(v)]));
}

// ─── GET /oauth/authorize ─────────────────────────────────────────────────────

/**
 * Entry point for the MCP client's authorization request. Validates the client,
 * redirect URI, and PKCE, stores a pending transaction, then redirects the
 * browser to PocketID for the actual user authentication. PocketID returns to
 * GET /oauth/callback once the user signs in.
 */
export async function beginAuthorize(req: Request, config: OAuthConfig): Promise<Response> {
  if (!config.pocketId) {
    log("error", "oauth_pocketid_not_configured", {});
    return renderAuthorizeError(
      "Identity provider is not configured. Set POCKETID_ISSUER, POCKETID_CLIENT_ID and POCKETID_CLIENT_SECRET.",
    );
  }

  const url = new URL(req.url);
  const get = (k: string) => url.searchParams.get(k) ?? "";
  const clientId = get("client_id");
  const redirectUri = get("redirect_uri");
  const codeChallenge = get("code_challenge");
  const codeChallengeMethod = get("code_challenge_method");
  const state = get("state");
  const scope = get("scope") || "mcp";
  const resource = get("resource");

  // RFC 8707 §2.1: the resource parameter must be an absolute URI. Validate it
  // here so no garbage reaches the persisted state or verifyAccessToken.
  if (resource) {
    try {
      new URL(resource);
    } catch {
      return renderAuthorizeError("The resource indicator must be a valid absolute URL.");
    }
  }

  // 1. Client must exist and redirect URI must be registered (port-agnostic for loopback)
  const client = clients.get(clientId);
  if (!client) {
    log("error", "oauth_authorize_client_not_found", { clientId });
    return renderAuthorizeError(
      "This client is no longer registered. Please remove this MCP server from your client and re-add it to trigger fresh registration.",
    );
  }
  const matchedUri = client.redirectUris.find((r) => redirectUriMatches(redirectUri, r));
  if (!matchedUri || !isRegistrableRedirectUri(redirectUri)) {
    log("error", "oauth_authorize_invalid_redirect_uri", { clientId, redirectUri });
    return renderAuthorizeError("The redirect URI is not registered for this client.");
  }

  // 2. PKCE: must be S256
  if (!codeChallenge || codeChallengeMethod !== "S256") {
    log("error", "oauth_authorize_invalid_pkce", { clientId });
    return renderAuthorizeError("PKCE validation failed. The client must use the S256 code challenge method.");
  }

  // 3. Stash the pending request and redirect the user to PocketID
  pruneExpiredOAuthState();

  const txn = randomBytes(24).toString("base64url");
  const pkceVerifier = randomBytes(32).toString("base64url");
  pendingAuth.set(txn, {
    clientId,
    redirectUri,
    codeChallenge,
    state,
    scopes: scope.split(/\s+/).filter(Boolean),
    resource: resource || undefined,
    pkceVerifier,
    expiresAt: Date.now() + PENDING_TTL_MS,
  });
  saveState();

  let authUrl: string;
  try {
    authUrl = await buildPocketIdAuthUrl(config.pocketId, callbackUri(config, req), {
      state: txn,
      codeChallenge: sha256(pkceVerifier),
    });
  } catch (err) {
    pendingAuth.delete(txn);
    saveState();
    log("error", "oauth_pocketid_discovery_failed", {
      error: err instanceof Error ? err.message : String(err),
    });
    return renderAuthorizeError("Could not reach the identity provider. Please try again later.");
  }

  log("info", "oauth_authorize_consent_shown", { clientId });
  return renderAuthorizeConsent(authUrl, { clientName: client.clientName });
}

// ─── GET /oauth/callback ──────────────────────────────────────────────────────

/**
 * PocketID redirects here after the user authenticates. Exchanges the PocketID
 * code, then issues our own authorization code bound to the original MCP client
 * request and redirects the browser back to the MCP client's redirect URI.
 */
export async function oauthCallback(req: Request, config: OAuthConfig): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code") ?? "";
  const txn = url.searchParams.get("state") ?? "";
  const providerError = url.searchParams.get("error");

  if (providerError) {
    log("error", "oauth_pocketid_returned_error", { error: providerError });
    return renderAuthorizeError("The identity provider denied the sign-in request.");
  }

  // Single-use: consume the pending transaction immediately
  const pending = pendingAuth.get(txn);
  if (pending) { pendingAuth.delete(txn); saveState(); }

  if (!pending || pending.expiresAt < Date.now()) {
    log("error", "oauth_callback_unknown_transaction", {});
    return renderAuthorizeError("Your sign-in session expired or is invalid. Please try connecting again.");
  }
  if (!code) {
    return renderAuthorizeError("Missing authorization code from the identity provider.");
  }
  if (!config.pocketId) {
    return renderAuthorizeError("Identity provider is not configured.");
  }

  const result = await exchangePocketIdCode(
    config.pocketId,
    callbackUri(config, req),
    code,
    pending.pkceVerifier,
  );
  if (!result.ok) {
    log("error", "oauth_pocketid_exchange_failed", { error: result.error });
    return renderAuthorizeError("Sign-in with the identity provider failed. Please try again.");
  }

  // Issue our own authorization code bound to the original MCP client request
  const mcpCode = randomBytes(24).toString("base64url");
  codes.set(mcpCode, {
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    codeChallenge: pending.codeChallenge,
    scopes: pending.scopes.length ? pending.scopes : ["mcp"],
    resource: pending.resource,
    expiresAt: Date.now() + CODE_TTL_MS,
  });
  saveState();

  const redirectUrl = buildAuthorizationRedirectUrl(pending.redirectUri, mcpCode, pending.state);

  log("info", "oauth_authorization_code_issued", {
    clientId: pending.clientId,
    redirectHost: new URL(redirectUrl).host,
  });
  return renderAuthorizeSuccess(redirectUrl);
}

// ─── POST /oauth/token ────────────────────────────────────────────────────────

export async function exchangeToken(req: Request): Promise<Response> {
  let params: Record<string, string>;
  try {
    params = await parseFormOrJson(req);
  } catch (err) {
    if (err instanceof RequestBodyTooLargeError) return oauthError("invalid_request", 413);
    throw err;
  }
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
  let params: Record<string, string>;
  try {
    params = await parseFormOrJson(req);
  } catch (err) {
    if (err instanceof RequestBodyTooLargeError) return oauthError("invalid_request", 413);
    throw err;
  }
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
    // Drop it from memory, but don't block this request on a synchronous disk write:
    // the timestamp check above already rejects it on every future lookup regardless
    // of map presence, and the periodic prune persists the cleanup eventually.
    accessTokens.delete(hash);
    return undefined;
  }
  // Legacy persisted state may hold an invalid resource; never throw here.
  let resourceUrl: URL | undefined;
  if (stored.resource) {
    try {
      resourceUrl = new URL(stored.resource);
    } catch {
      resourceUrl = undefined;
    }
  }
  return {
    token,
    clientId: stored.clientId,
    scopes: stored.scopes,
    expiresAt: Math.floor(stored.expiresAt / 1000),
    ...(resourceUrl ? { resource: resourceUrl } : {}),
  };
}

/** Returns true if the token is a valid, non-expired OAuth access token. */
export function isOAuthAccessToken(token: string): boolean {
  return verifyAccessToken(token) !== undefined;
}
