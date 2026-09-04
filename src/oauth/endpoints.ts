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
  actorFor,
  clients,
  codes,
  CODE_TTL_MS,
  pendingAuth,
  PENDING_TTL_MS,
  pruneExpiredOAuthState,
  consumedRefreshTokens,
  refreshTokens,
  REFRESH_TOKEN_TTL_S,
  reserveClientSlot,
  revokeFamily,
  saveState,
  SESSION_MAX_S,
  sha256,
  TOKEN_TTL_S,
  type Identity,
  type RegisteredClient,
} from "./state.js";
import {
  expandRedirectUris,
  isAllowedRedirectTarget,
  isRegistrableRedirectUri,
  redirectTargetLabel,
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
  /**
   * Plain-language list of what an issued token can reach, shown on the consent
   * page so the user is told what they are handing over before they hand it over.
   */
  grantSummary?: string[];
};

// ─── CORS headers (required for browser-based OAuth discovery) ────────────────

export const OAUTH_CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
} as const;

/**
 * Optional allowlist of who may sign in, from MCP_ALLOWED_SUBJECTS (comma
 * separated OIDC `sub` values or emails). Unset means PocketID's own per-client
 * group restriction remains the only gate, which is the pre-existing behaviour.
 */
function allowedSubjects(): string[] {
  return (process.env.MCP_ALLOWED_SUBJECTS ?? "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

export function isAllowedSubject(identity: Identity, allowed = allowedSubjects()): boolean {
  if (allowed.length === 0) return true;
  const candidates = [identity.subject, identity.email].filter(Boolean).map((v) => v!.toLowerCase());
  return candidates.some((value) => allowed.includes(value));
}

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

/**
 * 401 response with RFC 9728 WWW-Authenticate header.
 *
 * `resourcePath` is the MCP endpoint being protected, so a server exposing more
 * than one (e.g. /mcp and /mcp/read) points each at its own metadata document
 * instead of at a single one describing a resource the client never asked for.
 */
export function unauthorized(config: OAuthConfig, req: Request, resourcePath = "/mcp"): Response {
  const root = baseUrl(config, req);
  const metadataUrl = `${root}/.well-known/oauth-protected-resource${resourcePath === "/mcp" ? "" : resourcePath}`;
  return Response.json(
    { error: "unauthorized" },
    {
      status: 401,
      headers: {
        "WWW-Authenticate": `Bearer realm="${root}", resource_metadata="${metadataUrl}"`,
        ...OAUTH_CORS_HEADERS,
      },
    },
  );
}

/** RFC 9728 – /.well-known/oauth-protected-resource[/path] */
export function protectedResourceMetadata(config: OAuthConfig, req: Request, resourcePath = "/mcp"): Response {
  const root = baseUrl(config, req);
  return Response.json(
    {
      resource: `${root}${resourcePath}`,
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
    grant_types_supported: ["authorization_code", "refresh_token"],
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

  const requested = Array.isArray(body.redirect_uris)
    ? (body.redirect_uris as unknown[]).filter((u): u is string => typeof u === "string" && isRegistrableRedirectUri(u))
    : [];

  // Registration is public, so an unrestricted destination is an open invitation
  // to phish an authorization code. Reject here rather than at authorize time,
  // so a client that cannot work finds out immediately.
  const rejected = requested.filter((uri) => !isAllowedRedirectTarget(uri));
  if (rejected.length > 0) {
    log("error", "oauth_register_redirect_host_not_allowed", {
      hosts: rejected.map((uri) => redirectTargetLabel(uri)),
    });
    return oauthError("invalid_redirect_uris");
  }

  const redirectUris = expandRedirectUris(requested);

  if (redirectUris.length === 0) {
    return oauthError("invalid_redirect_uris");
  }

  // Registration is public; the table it fills must not be.
  if (!reserveClientSlot()) {
    log("error", "oauth_register_client_table_full", { clients: clients.size });
    return oauthError("temporarily_unavailable", 503);
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
  // Re-checked here so a client persisted before the allowlist existed, or from
  // a state file restored by hand, cannot bypass it.
  if (!isAllowedRedirectTarget(redirectUri)) {
    log("error", "oauth_authorize_redirect_host_not_allowed", { clientId, host: redirectTargetLabel(redirectUri) });
    return renderAuthorizeError(
      `Authorization codes may not be sent to ${redirectTargetLabel(redirectUri)}. Add it to MCP_ALLOWED_REDIRECT_HOSTS if this client is yours.`,
    );
  }

  // 2. PKCE: must be S256
  if (!codeChallenge || codeChallengeMethod !== "S256") {
    log("error", "oauth_authorize_invalid_pkce", { clientId });
    return renderAuthorizeError("PKCE validation failed. The client must use the S256 code challenge method.");
  }

  // 3. Stash the pending request and redirect the user to PocketID
  pruneExpiredOAuthState();

  const txn = randomBytes(24).toString("base64url");
  const browserSecret = randomBytes(32).toString("base64url");
  const pkceVerifier = randomBytes(32).toString("base64url");
  pendingAuth.set(txn, {
    browserHash: sha256(browserSecret),
    approved: false,
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

  const response = renderAuthorizeConsent(txn, {
    redirectUri,
    clientName: client.clientName,
    grants: resource === `${baseUrl(config, req)}/mcp/read`
      ? ["Read access to configured services; no shell execution."]
      : config.grantSummary ?? ["Administrative access to configured services and tools."],
  });
  response.headers.set("Set-Cookie", `${consentCookieName(txn)}=${browserSecret}; Path=/oauth; HttpOnly; SameSite=Lax; Max-Age=600${new URL(callbackUri(config, req)).protocol === "https:" ? "; Secure" : ""}`);
  response.headers.set("Cache-Control", "no-store");
  log("info", "oauth_authorize_consent_shown", { clientId, redirectHost: redirectTargetLabel(redirectUri) });
  return response;
}

function consentCookieName(txn: string): string { return `vmhq_consent_${txn}`; }

function browserMatches(req: Request, txn: string, hash: string | undefined): boolean {
  if (!hash || !/^[A-Za-z0-9_-]{32}$/.test(txn)) return false;
  const cookies = (req.headers.get("cookie") ?? "").split(";").map((v) => v.trim());
  const value = cookies.find((v) => v.startsWith(`${consentCookieName(txn)}=`))?.split("=")[1];
  return !!value && sha256(value) === hash;
}

/** A same-origin POST and a per-transaction browser cookie are both required. */
export async function approveAuthorize(req: Request, config: OAuthConfig): Promise<Response> {
  if (req.method !== "POST" || req.headers.get("origin") !== new URL(baseUrl(config, req)).origin) {
    return renderAuthorizeError("Invalid consent origin.");
  }
  let params: Record<string, string>;
  try { params = await parseFormOrJson(req); } catch { return renderAuthorizeError("Invalid consent request."); }
  const txn = params.transaction ?? "";
  const pending = pendingAuth.get(txn);
  if (!pending || pending.expiresAt <= Date.now() || pending.approved || !browserMatches(req, txn, pending.browserHash) || !config.pocketId) {
    return renderAuthorizeError("Invalid or expired consent transaction.");
  }
  pending.approved = true;
  saveState();
  let authUrl: string;
  try {
    authUrl = await buildPocketIdAuthUrl(config.pocketId, callbackUri(config, req), {
      state: txn,
      codeChallenge: sha256(pending.pkceVerifier),
    });
  } catch (err) {
    pendingAuth.delete(txn);
    saveState();
    log("error", "oauth_pocketid_discovery_failed", {
      error: err instanceof Error ? err.message : String(err),
    });
    return renderAuthorizeError("Could not reach the identity provider. Please try again later.");
  }

  log("info", "oauth_authorize_consent_approved", { clientId: pending.clientId, redirectHost: redirectTargetLabel(pending.redirectUri) });
  return new Response(null, { status: 303, headers: { Location: authUrl, "Cache-Control": "no-store" } });
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
  if (!pending?.approved || !browserMatches(req, txn, pending.browserHash)) {
    return renderAuthorizeError("Consent is missing, expired or belongs to a different browser.");
  }
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
    if (result.error === "pocketid_id_token_missing") {
      return renderAuthorizeError(
        "The identity provider did not return an id_token, so the sign-in cannot be attributed to anyone. Make sure POCKETID_SCOPES includes openid.",
      );
    }
    return renderAuthorizeError("Sign-in with the identity provider failed. Please try again.");
  }

  const identity: Identity = {
    subject: result.identity.subject,
    ...(result.identity.email ? { email: result.identity.email } : {}),
  };

  // Checked before any credential is minted, so a rejected person never holds
  // even a short-lived authorization code.
  if (!isAllowedSubject(identity)) {
    log("error", "oauth_subject_not_allowed", { actor: actorFor(identity) });
    return renderAuthorizeError("This account is not allowed to access this server.");
  }

  // Issue our own authorization code bound to the original MCP client request
  const mcpCode = randomBytes(24).toString("base64url");
  codes.set(mcpCode, {
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    codeChallenge: pending.codeChallenge,
    scopes: pending.scopes.length ? pending.scopes : ["mcp"],
    resource: pending.resource,
    identity,
    expiresAt: Date.now() + CODE_TTL_MS,
  });
  saveState();

  const redirectUrl = buildAuthorizationRedirectUrl(pending.redirectUri, mcpCode, pending.state);

  log("info", "oauth_authorization_code_issued", {
    clientId: pending.clientId,
    actor: actorFor(identity),
    redirectHost: new URL(redirectUrl).host,
  });
  return renderAuthorizeSuccess(redirectUrl);
}

// ─── POST /oauth/token ────────────────────────────────────────────────────────

/**
 * Mints an access token, plus the refresh token that will replace it, and
 * returns the RFC 6749 token response. `familyId` ties the pair together so a
 * later rotation — or a revocation — can reach every credential descended from
 * one authorization.
 */
function issueTokens(params: {
  clientId: string;
  scopes: string[];
  resource?: string;
  identity?: Identity;
  familyId: string;
  /** Hard end of the session; neither token outlives it. */
  familyExpiresAt: number;
}): Response {
  const { clientId, scopes, resource, identity, familyId, familyExpiresAt } = params;
  const accessToken = `vmhq_mcp_${randomBytes(32).toString("base64url")}`;
  const refreshToken = `vmhq_rt_${randomBytes(32).toString("base64url")}`;
  const now = Date.now();
  const accessExpiresAt = Math.min(now + TOKEN_TTL_S * 1000, familyExpiresAt);
  const refreshExpiresAt = Math.min(now + REFRESH_TOKEN_TTL_S * 1000, familyExpiresAt);

  accessTokens.set(sha256(accessToken), {
    clientId,
    scopes,
    resource,
    identity,
    familyId,
    familyExpiresAt,
    expiresAt: accessExpiresAt,
  });
  refreshTokens.set(sha256(refreshToken), {
    clientId,
    scopes,
    resource,
    identity,
    familyId,
    familyExpiresAt,
    expiresAt: refreshExpiresAt,
  });
  saveState();

  return Response.json(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.max(1, Math.floor((accessExpiresAt - now) / 1000)),
      refresh_token: refreshToken,
      scope: scopes.join(" "),
    },
    {
      headers: {
        ...OAUTH_CORS_HEADERS,
        // RFC 6749 §5.1: a response carrying credentials must not be cached.
        "Cache-Control": "no-store",
        Pragma: "no-cache",
      },
    },
  );
}

export async function exchangeToken(req: Request): Promise<Response> {
  let params: Record<string, string>;
  try {
    params = await parseFormOrJson(req);
  } catch (err) {
    if (err instanceof RequestBodyTooLargeError) return oauthError("invalid_request", 413);
    throw err;
  }
  const { grant_type: grantType = "" } = params;

  if (grantType === "refresh_token") {
    return exchangeRefreshToken(params);
  }
  if (grantType !== "authorization_code") {
    return oauthError("unsupported_grant_type");
  }

  const {
    code = "",
    redirect_uri: redirectUri = "",
    client_id: clientId = "",
    code_verifier: codeVerifier = "",
    resource = "",
  } = params;

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
  // A client pruned between authorizing and redeeming no longer exists as far
  // as this server is concerned, so its code should not still buy a token.
  if (!clients.has(clientId)) {
    log("error", "oauth_token_client_unknown", { clientId });
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

  log("info", "oauth_access_token_issued", {
    clientId,
    actor: actorFor(ac.identity),
    expiresIn: TOKEN_TTL_S,
  });

  return issueTokens({
    clientId,
    scopes: ac.scopes,
    resource: ac.resource,
    identity: ac.identity,
    familyId: randomBytes(12).toString("hex"),
    familyExpiresAt: Date.now() + SESSION_MAX_S * 1000,
  });
}

/**
 * Refresh grant with rotation (OAuth 2.1 §4.3.1 for public clients).
 *
 * The presented token is consumed and replaced. A token presented after it was
 * already rotated away cannot be a mistake by a well-behaved client — either
 * the client's copy or the server's was stolen — so the entire family is
 * revoked rather than the request merely refused.
 */
function exchangeRefreshToken(params: Record<string, string>): Response {
  const { refresh_token: presented = "", client_id: clientId = "" } = params;
  if (!presented) return oauthError("invalid_request");
  // OAuth 2.1 §4.3.1: a public client identifies itself on every token
  // request. Without it the check below would be skipped rather than failed.
  if (!clientId) return oauthError("invalid_request");

  const hash = sha256(presented);
  const stored = refreshTokens.get(hash);

  if (!stored) {
    const consumed = consumedRefreshTokens.get(hash);
    if (consumed) {
      // A token that was already rotated away is being presented again. A
      // correct client never does this, so treat it as a leak and take down
      // everything descended from that authorization, not just this request.
      const revoked = revokeFamily(consumed.familyId);
      saveState();
      log("error", "oauth_refresh_reuse_detected", {
        clientId,
        familyId: consumed.familyId,
        revokedCredentials: revoked,
      });
    }
    return oauthError("invalid_grant");
  }

  refreshTokens.delete(hash);
  consumedRefreshTokens.set(hash, { familyId: stored.familyId, expiresAt: stored.expiresAt });

  if (stored.expiresAt < Date.now()) {
    saveState();
    return oauthError("invalid_grant");
  }
  if (stored.clientId !== clientId) {
    saveState();
    return oauthError("invalid_grant");
  }
  // The session's hard end is inherited, never extended, by a refresh.
  const familyExpiresAt = stored.familyExpiresAt ?? Date.now() + SESSION_MAX_S * 1000;
  if (familyExpiresAt <= Date.now()) {
    saveState();
    log("info", "oauth_session_max_lifetime_reached", { clientId, familyId: stored.familyId });
    return oauthError("invalid_grant");
  }
  // The allowlist is re-read here so that removing someone from
  // MCP_ALLOWED_SUBJECTS ends their session at the next refresh rather than
  // leaving it renewable until someone notices.
  if (!stored.identity || !isAllowedSubject(stored.identity)) {
    saveState();
    log("error", "oauth_refresh_subject_not_allowed", { clientId, actor: actorFor(stored.identity) });
    return oauthError("invalid_grant");
  }

  log("info", "oauth_access_token_refreshed", {
    clientId: stored.clientId,
    actor: actorFor(stored.identity),
    familyId: stored.familyId,
  });

  return issueTokens({
    clientId: stored.clientId,
    scopes: stored.scopes,
    resource: stored.resource,
    identity: stored.identity,
    familyId: stored.familyId,
    familyExpiresAt,
  });
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

  // RFC 7009: the caller may present either token type, and the endpoint always
  // answers 200. Revoking either one takes down the whole family, so a user who
  // revokes "the token" they have does not leave its sibling alive.
  const hash = sha256(token);
  const familyId = accessTokens.get(hash)?.familyId ?? refreshTokens.get(hash)?.familyId;

  let revoked = 0;
  if (familyId) {
    revoked = revokeFamily(familyId);
  } else {
    if (accessTokens.delete(hash)) revoked++;
    if (refreshTokens.delete(hash)) revoked++;
  }

  if (revoked > 0) {
    saveState();
    log("info", "oauth_token_revoked", { revokedCredentials: revoked, ...(familyId ? { familyId } : {}) });
  }

  return Response.json({}, { headers: OAUTH_CORS_HEADERS });
}

// ─── Token verification ───────────────────────────────────────────────────────

/**
 * RFC 8707 §2: a token bound to a resource is only valid at that resource.
 * Compared on origin + path with the fragment and any trailing slash ignored,
 * so `https://host/mcp` and `https://host/mcp/` are the same audience.
 */
function resourceMatches(tokenResource: string, expected: string): boolean {
  try {
    const a = new URL(tokenResource);
    const b = new URL(expected);
    const path = (url: URL) => url.pathname.replace(/\/+$/u, "");
    return a.origin === b.origin && path(a) === path(b);
  } catch {
    return false;
  }
}

/**
 * Verifies an OAuth access token and returns structured AuthInfo.
 * Returns undefined if the token is invalid or expired.
 *
 * `expectedResources` are the resource identifiers this server answers for. A
 * token carrying a `resource` must name one of them: without the check, a token
 * this server issued for a different audience would still open /mcp. Tokens
 * with no `resource` — everything issued before RFC 8707 was honoured, and any
 * client that does not send the parameter — are unaffected.
 *
 * A token with no identity is refused: everything reachable through it is
 * logged by actor, and "legacy" is not an actor. Such tokens predate identity
 * recording by long enough that any still on disk are stale, not in use.
 * The subject allowlist is re-checked on every call for the same reason it is
 * re-checked on refresh: a person removed from it should lose access now, not
 * when their token happens to expire.
 */
export function verifyAccessToken(token: string, expectedResources?: string[]): AuthInfo | undefined {
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
  if (!stored.identity) {
    log("error", "oauth_token_without_identity_rejected", { clientId: stored.clientId });
    accessTokens.delete(hash);
    return undefined;
  }
  if (!isAllowedSubject(stored.identity)) {
    log("error", "oauth_token_subject_not_allowed", { clientId: stored.clientId, actor: actorFor(stored.identity) });
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

  if (stored.resource && expectedResources && expectedResources.length > 0) {
    if (!expectedResources.some((expected) => resourceMatches(stored.resource!, expected))) {
      log("error", "oauth_token_resource_mismatch", {
        clientId: stored.clientId,
        actor: actorFor(stored.identity),
        tokenResource: stored.resource,
      });
      return undefined;
    }
  }
  return {
    token,
    clientId: stored.clientId,
    scopes: stored.scopes,
    expiresAt: Math.floor(stored.expiresAt / 1000),
    ...(resourceUrl ? { resource: resourceUrl } : {}),
    // Identity is absent on tokens issued before it was recorded; actorFor()
    // renders those as "legacy" rather than dropping them.
    extra: {
      actor: actorFor(stored.identity),
      ...(stored.identity ? { identity: stored.identity } : {}),
      ...(stored.familyId ? { familyId: stored.familyId } : {}),
    },
  };
}

/** Returns true if the token is a valid, non-expired OAuth access token. */
export function isOAuthAccessToken(token: string): boolean {
  return verifyAccessToken(token) !== undefined;
}

// ─── Session inventory (for the admin-tier vmhq_sessions tool) ────────────────

export type SessionSummary = {
  clientId: string;
  clientName?: string;
  actor: string;
  scopes: string[];
  expiresAt: string;
  /** Whether the session can renew itself past the access token's expiry. */
  renewable: boolean;
  familyId?: string;
};

/**
 * Active sessions, one per access token. Deliberately returns no token value
 * and no hash: this is an inventory for deciding what to revoke, and a listing
 * that leaked credentials would be worse than no listing at all.
 */
export function listSessions(now = Date.now()): SessionSummary[] {
  const renewableFamilies = new Set<string>();
  for (const token of refreshTokens.values()) {
    if (token.expiresAt > now) renewableFamilies.add(token.familyId);
  }

  const sessions: SessionSummary[] = [];
  for (const token of accessTokens.values()) {
    if (token.expiresAt <= now) continue;
    sessions.push({
      clientId: token.clientId,
      ...(clients.get(token.clientId)?.clientName ? { clientName: clients.get(token.clientId)!.clientName } : {}),
      actor: actorFor(token.identity),
      scopes: token.scopes,
      expiresAt: new Date(token.expiresAt).toISOString(),
      renewable: token.familyId ? renewableFamilies.has(token.familyId) : false,
      ...(token.familyId ? { familyId: token.familyId } : {}),
    });
  }

  return sessions.sort((a, b) => a.expiresAt.localeCompare(b.expiresAt));
}

/**
 * Revokes sessions by person, by client, or all of them, removing the access
 * and refresh tokens together so a cut session cannot renew itself. Returns how
 * many credentials were dropped.
 */
export function revokeSessions(filter: { actor?: string; clientId?: string; all?: boolean }): number {
  const actor = filter.actor?.trim().toLowerCase();
  const matches = (token: { clientId: string; identity?: Identity }): boolean => {
    if (filter.all) return true;
    if (filter.clientId && token.clientId === filter.clientId) return true;
    if (actor) {
      const candidates = [token.identity?.subject, token.identity?.email, actorFor(token.identity)];
      return candidates.some((value) => value?.toLowerCase() === actor);
    }
    return false;
  };

  let revoked = 0;
  for (const [hash, token] of accessTokens) {
    if (matches(token)) { accessTokens.delete(hash); revoked++; }
  }
  for (const [hash, token] of refreshTokens) {
    if (matches(token)) { refreshTokens.delete(hash); revoked++; }
  }

  if (revoked > 0) {
    saveState();
    log("info", "oauth_sessions_revoked", { revokedCredentials: revoked, ...filter });
  }

  return revoked;
}
