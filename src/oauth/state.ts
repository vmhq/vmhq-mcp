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

export type AuthorizationCode = {
  clientId: string;
  /** Exact redirect URI used in the authorize request (stored for validation) */
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  /** RFC 8707 resource indicator (optional) */
  resource?: string;
  expiresAt: number;
};

export type StoredToken = {
  clientId: string;
  scopes: string[];
  resource?: string;
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

// ─── Persistence ──────────────────────────────────────────────────────────────

const STATE_PATH = process.env.MCP_OAUTH_STATE_PATH ?? "./data/oauth-state.json";
export const CODE_TTL_MS = 5 * 60 * 1000;          // 5 min
export const PENDING_TTL_MS = 10 * 60 * 1000;      // 10 min (PocketID round-trip)
export const TOKEN_TTL_S = 60 * 60 * 24 * 90;      // 90 days

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

    if (Array.isArray(saved.pendingAuth)) {
      for (const [txn, p] of saved.pendingAuth) {
        if (p.expiresAt > now) pendingAuth.set(txn, p);
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

export function saveState(): void {
  try {
    mkdirSync(dirname(STATE_PATH), { recursive: true });
    const payload = {
      clients: [...clients.entries()],
      authorizationCodes: [...codes.entries()],
      pendingAuth: [...pendingAuth.entries()],
      accessTokens: [...accessTokens.entries()],
    };
    const tmp = `${STATE_PATH}.tmp`;
    writeFileSync(tmp, JSON.stringify(payload), "utf-8");
    chmodSync(tmp, 0o600);
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

  if (dirty) saveState();
}

/** Reload clients, authorization codes, and tokens from disk (for tests and hot recovery). */
export function reloadPersistedOAuthState(): void {
  clients.clear();
  codes.clear();
  pendingAuth.clear();
  accessTokens.clear();
  loadState();
}

loadState();
setInterval(() => pruneExpiredOAuthState(), 60 * 60 * 1000).unref?.();
