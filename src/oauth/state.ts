/**
 * OAuth in-memory state and disk persistence.
 *
 * Owns the registered clients, single-use authorization codes, and access-token
 * hash maps, plus their atomic JSON persistence. Side effects (initial load and
 * the hourly prune interval) run at module load.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { log } from "../logger.js";

export type RegisteredClient = {
  clientId: string;
  clientIdIssuedAt: number;
  redirectUris: string[];
  clientName?: string;
};

/** Who authenticated, carried from PocketID through to the issued token. */
export type Identity = {
  subject: string;
  email?: string;
};

/** Log-friendly name for an identity: the email if there is one, else the sub. */
export function actorFor(identity: Identity | undefined): string {
  if (!identity) return "legacy";
  return identity.email || identity.subject;
}

export type AuthorizationCode = {
  clientId: string;
  /** Exact redirect URI used in the authorize request (stored for validation) */
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  /** RFC 8707 resource indicator (optional) */
  resource?: string;
  /** Undefined only for codes persisted before identities were recorded. */
  identity?: Identity;
  expiresAt: number;
};

export type StoredToken = {
  clientId: string;
  scopes: string[];
  resource?: string;
  /** Undefined for tokens issued before identities were recorded ("legacy"). */
  identity?: Identity;
  /** Links the token to its refresh-token family, so revoking one kills both. */
  familyId?: string;
  /**
   * Hard end of the whole family, fixed when the authorization code was
   * redeemed. Refresh rotation cannot move it. Absent on tokens issued before
   * it existed, which then live by their own expiresAt alone.
   */
  familyExpiresAt?: number;
  expiresAt: number;
};

/**
 * A refresh token. Rotated on every use (OAuth 2.1 requires it for public
 * clients): each use consumes this one and issues a successor in the same
 * family. Presenting a token that was already rotated away means it leaked, so
 * the whole family is revoked rather than just refused.
 */
export type StoredRefreshToken = {
  clientId: string;
  scopes: string[];
  resource?: string;
  identity?: Identity;
  familyId: string;
  /** See StoredToken.familyExpiresAt. */
  familyExpiresAt?: number;
  expiresAt: number;
};

/**
 * A pending authorization while the user is being redirected through PocketID.
 * Created at GET /oauth/authorize, consumed at GET /oauth/callback. Keyed by an
 * opaque transaction id that is passed to PocketID as its `state` parameter.
 */
export type PendingAuth = {
  /** The MCP client (Claude.ai, Cursor, …) that initiated the authorization. */
  clientId: string;
  /** Redirect URI the MCP client expects the final code on. */
  redirectUri: string;
  /** The MCP client's PKCE S256 challenge (verified at token exchange). */
  codeChallenge: string;
  /** The MCP client's opaque `state`, echoed back on the final redirect. */
  state: string;
  scopes: string[];
  /** RFC 8707 resource indicator (optional) */
  resource?: string;
  /** PKCE verifier for the PocketID leg of the flow. */
  pkceVerifier: string;
  expiresAt: number;
};

// ─── In-memory state ──────────────────────────────────────────────────────────

export const clients = new Map<string, RegisteredClient>();
export const codes = new Map<string, AuthorizationCode>();
/** transaction id → PendingAuth (PocketID round-trip) */
export const pendingAuth = new Map<string, PendingAuth>();
/** token SHA-256 hash → StoredToken */
export const accessTokens = new Map<string, StoredToken>();
/** refresh token SHA-256 hash → StoredRefreshToken */
export const refreshTokens = new Map<string, StoredRefreshToken>();
/**
 * Refresh tokens that have already been rotated away, kept until they would
 * have expired anyway. This is what makes reuse detectable: without it a
 * replayed token is indistinguishable from a random string, and the theft it
 * signals goes unnoticed. hash → { familyId, expiresAt }.
 */
export const consumedRefreshTokens = new Map<string, { familyId: string; expiresAt: number }>();

// ─── Persistence ──────────────────────────────────────────────────────────────

const STATE_PATH = process.env.MCP_OAUTH_STATE_PATH ?? "./data/oauth-state.json";
export const CODE_TTL_MS = 5 * 60 * 1000;          // 5 min
export const PENDING_TTL_MS = 10 * 60 * 1000;      // 10 min (PocketID round-trip)
/** Access token lifetime, configurable via MCP_OAUTH_TOKEN_TTL_S (seconds). */
export const TOKEN_TTL_S = (() => {
  const raw = process.env.MCP_OAUTH_TOKEN_TTL_S;
  if (!raw) return 60 * 60 * 24; // 24 hours — refresh tokens carry the long tail
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("MCP_OAUTH_TOKEN_TTL_S must be a positive number of seconds.");
  }
  return value;
})();
/** Refresh token lifetime, configurable via MCP_OAUTH_REFRESH_TTL_S (seconds). */
export const REFRESH_TOKEN_TTL_S = (() => {
  const raw = process.env.MCP_OAUTH_REFRESH_TTL_S;
  if (!raw) return 60 * 60 * 24 * 30; // 30 days
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("MCP_OAUTH_REFRESH_TTL_S must be a positive number of seconds.");
  }
  return value;
})();

/**
 * Longest a session may live from the moment the code is redeemed, whatever
 * the refresh cadence. Rotation renews the refresh token's own lifetime, so
 * without this a session that keeps refreshing never ends, and neither does a
 * stolen refresh chain that is used at least once a month. Configurable via
 * MCP_OAUTH_SESSION_MAX_S; the default is 90 days.
 */
export const SESSION_MAX_S = (() => {
  const raw = process.env.MCP_OAUTH_SESSION_MAX_S;
  if (!raw) return 60 * 60 * 24 * 90;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("MCP_OAUTH_SESSION_MAX_S must be a positive number of seconds.");
  }
  return value;
})();

/**
 * Cap on registered clients. Registration is public and every registration
 * rewrites the whole state file synchronously, so an unbounded table is a way
 * to grow that file and stall the event loop from the outside. Clients with no
 * live credential are evicted oldest first to make room; clients that still
 * hold a token are never evicted, and registration fails instead.
 */
export const MAX_REGISTERED_CLIENTS = 200;

/**
 * Clients outlive their tokens: prune 30 days after the longest-lived
 * credential they can hold. Measured against the refresh TTL, not the access
 * TTL, so a short access token cannot cause a client to be pruned while its own
 * refresh token is still valid.
 */
export const CLIENT_TTL_MS = (Math.max(TOKEN_TTL_S, REFRESH_TOKEN_TTL_S) + 30 * 24 * 60 * 60) * 1000;

export function sha256(value: string): string {
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
      pendingAuth?: Array<[string, PendingAuth]>;
      accessTokens?: Array<[string, StoredToken | number]>;
      refreshTokens?: Array<[string, StoredRefreshToken]>;
      consumedRefreshTokens?: Array<[string, { familyId: string; expiresAt: number }]>;
    };

    const now = Date.now();
    if (Array.isArray(saved.clients)) {
      for (const [id, c] of saved.clients) {
        // Legacy persisted clients predate clientIdIssuedAt; backfill it so
        // pruneExpiredOAuthState() can age them out (NaN would never expire).
        if (typeof c.clientIdIssuedAt !== "number" || !Number.isFinite(c.clientIdIssuedAt)) {
          c.clientIdIssuedAt = Math.floor(now / 1000);
        }
        clients.set(id, c);
      }
    }

    if (Array.isArray(saved.authorizationCodes)) {
      for (const [code, ac] of saved.authorizationCodes) {
        if (ac.expiresAt > now) codes.set(code, ac);
      }
    }

    if (Array.isArray(saved.pendingAuth)) {
      for (const [txn, p] of saved.pendingAuth) {
        if (p.expiresAt > now) pendingAuth.set(txn, p);
      }
    }

    if (Array.isArray(saved.accessTokens)) {
      for (const [hash, data] of saved.accessTokens) {
        // The oldest format stored just a number (expiresAt) with no identity.
        // Such a token names nobody, so it is dropped rather than honoured;
        // verifyAccessToken() refuses identity-less tokens for the same reason.
        if (typeof data === "object" && data !== null && data.expiresAt > now) {
          accessTokens.set(hash, data);
        }
      }
    }

    // Both are absent from state files written before refresh tokens existed.
    if (Array.isArray(saved.refreshTokens)) {
      for (const [hash, token] of saved.refreshTokens) {
        if (token.expiresAt > now) refreshTokens.set(hash, token);
      }
    }

    if (Array.isArray(saved.consumedRefreshTokens)) {
      for (const [hash, entry] of saved.consumedRefreshTokens) {
        if (entry.expiresAt > now) consumedRefreshTokens.set(hash, entry);
      }
    }
  } catch {
    // Fresh start — no persisted state yet
  }
}

export function saveState(): void {
  try {
    mkdirSync(dirname(STATE_PATH), { recursive: true });
    const payload = {
      clients: [...clients.entries()],
      authorizationCodes: [...codes.entries()],
      pendingAuth: [...pendingAuth.entries()],
      accessTokens: [...accessTokens.entries()],
      refreshTokens: [...refreshTokens.entries()],
      consumedRefreshTokens: [...consumedRefreshTokens.entries()],
    };
    const tmp = `${STATE_PATH}.tmp`;
    writeFileSync(tmp, JSON.stringify(payload), { encoding: "utf-8", mode: 0o600 });
    chmodSync(tmp, 0o600); // covers the case where a loose tmp file already existed
    renameSync(tmp, STATE_PATH);
  } catch (err) {
    log("error", "oauth_state_persist_failed", { error: err instanceof Error ? err.message : String(err) });
  }
}

export function pruneExpiredOAuthState(now = Date.now()): void {
  let dirty = false;

  for (const [code, ac] of codes) {
    if (ac.expiresAt <= now) { codes.delete(code); dirty = true; }
  }
  for (const [txn, p] of pendingAuth) {
    if (p.expiresAt <= now) { pendingAuth.delete(txn); dirty = true; }
  }
  for (const [hash, tok] of accessTokens) {
    if (tok.expiresAt <= now) { accessTokens.delete(hash); dirty = true; }
  }
  for (const [hash, tok] of refreshTokens) {
    if (tok.expiresAt <= now) { refreshTokens.delete(hash); dirty = true; }
  }
  // A consumed token only needs remembering while it could still be replayed,
  // which is bounded by the lifetime it would have had.
  for (const [hash, entry] of consumedRefreshTokens) {
    if (entry.expiresAt <= now) { consumedRefreshTokens.delete(hash); dirty = true; }
  }
  for (const [id, client] of clients) {
    // Guard against a non-finite timestamp so the comparison can't silently
    // evaluate to false and keep a client alive forever.
    const issuedAtMs = Number.isFinite(client.clientIdIssuedAt) ? client.clientIdIssuedAt * 1000 : 0;
    if (issuedAtMs + CLIENT_TTL_MS <= now) { clients.delete(id); dirty = true; }
  }

  if (dirty) saveState();
}

/** Client ids that still hold an access token, a refresh token, or a pending code. */
function clientsWithCredentials(): Set<string> {
  const live = new Set<string>();
  for (const token of accessTokens.values()) live.add(token.clientId);
  for (const token of refreshTokens.values()) live.add(token.clientId);
  for (const code of codes.values()) live.add(code.clientId);
  for (const pending of pendingAuth.values()) live.add(pending.clientId);
  return live;
}

/**
 * Makes room for one more registration under MAX_REGISTERED_CLIENTS by
 * evicting idle clients, oldest first. Returns false when the table is full of
 * clients that still hold credentials, in which case the caller must refuse.
 */
export function reserveClientSlot(max = MAX_REGISTERED_CLIENTS): boolean {
  if (clients.size < max) return true;

  const live = clientsWithCredentials();
  const idle = [...clients.values()]
    .filter((client) => !live.has(client.clientId))
    .sort((a, b) => a.clientIdIssuedAt - b.clientIdIssuedAt);

  for (const client of idle) {
    if (clients.size < max) break;
    clients.delete(client.clientId);
  }

  return clients.size < max;
}

/** Reload clients, authorization codes, and tokens from disk (for tests and hot recovery). */
export function reloadPersistedOAuthState(): void {
  clients.clear();
  codes.clear();
  pendingAuth.clear();
  accessTokens.clear();
  refreshTokens.clear();
  consumedRefreshTokens.clear();
  loadState();
}

/**
 * Drops every credential descended from one authorization. Used both for
 * deliberate revocation and as the response to a replayed refresh token, where
 * refusing the request alone would leave the thief's other tokens working.
 */
export function revokeFamily(familyId: string): number {
  let revoked = 0;
  for (const [hash, tok] of accessTokens) {
    if (tok.familyId === familyId) { accessTokens.delete(hash); revoked++; }
  }
  for (const [hash, tok] of refreshTokens) {
    if (tok.familyId === familyId) { refreshTokens.delete(hash); revoked++; }
  }
  return revoked;
}

loadState();
setInterval(() => pruneExpiredOAuthState(), 60 * 60 * 1000).unref?.();
