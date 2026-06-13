/**
 * PocketID (OIDC) client used as the upstream identity provider.
 *
 * The MCP server acts as an OAuth bridge: it remains the authorization server
 * toward MCP clients (DCR + PKCE + token issuance) but delegates the actual
 * user authentication step to a PocketID instance via the standard OIDC
 * authorization-code + PKCE flow.
 *
 * PocketID is a standard OIDC provider:
 *   - Discovery:  {issuer}/.well-known/openid-configuration
 *   - PKCE (S256) supported on the authorization endpoint
 *   - Token endpoint auth: client_secret_post (credentials in the form body)
 */
import { log } from "../logger.js";

export type PocketIdConfig = {
  /** Base issuer URL with no trailing slash, e.g. https://id.example.com */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** OIDC scopes requested at the PocketID authorization endpoint. */
  scopes: string[];
};

type Discovery = {
  authorization_endpoint: string;
  token_endpoint: string;
};

const DISCOVERY_TTL_MS = 60 * 60 * 1000; // 1 hour
let discoveryCache: { issuer: string; data: Discovery; expiresAt: number } | undefined;

/** Fetch (and cache) the OIDC discovery document for the configured issuer. */
async function discover(cfg: PocketIdConfig): Promise<Discovery> {
  if (
    discoveryCache &&
    discoveryCache.issuer === cfg.issuer &&
    discoveryCache.expiresAt > Date.now()
  ) {
    return discoveryCache.data;
  }

  const url = `${cfg.issuer}/.well-known/openid-configuration`;
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`pocketid_discovery_http_${res.status}`);
  }

  const json = (await res.json()) as Partial<Discovery>;
  if (!json.authorization_endpoint || !json.token_endpoint) {
    throw new Error("pocketid_discovery_incomplete");
  }

  const data: Discovery = {
    authorization_endpoint: json.authorization_endpoint,
    token_endpoint: json.token_endpoint,
  };
  discoveryCache = { issuer: cfg.issuer, data, expiresAt: Date.now() + DISCOVERY_TTL_MS };
  return data;
}

/** Clear the cached discovery document (used by tests). */
export function resetPocketIdDiscoveryCache(): void {
  discoveryCache = undefined;
}

/**
 * Build the PocketID authorization URL the browser is redirected to.
 * `state` carries our pending-transaction id; `codeChallenge` is the S256
 * challenge for the PocketID leg of the flow.
 */
export async function buildPocketIdAuthUrl(
  cfg: PocketIdConfig,
  callbackUri: string,
  params: { state: string; codeChallenge: string },
): Promise<string> {
  const { authorization_endpoint } = await discover(cfg);
  const u = new URL(authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", cfg.clientId);
  u.searchParams.set("redirect_uri", callbackUri);
  u.searchParams.set("scope", cfg.scopes.join(" "));
  u.searchParams.set("state", params.state);
  u.searchParams.set("code_challenge", params.codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

/**
 * Exchange the PocketID authorization code for tokens (client_secret_post).
 * Returns ok=true when PocketID confirms a successful authentication. We trust
 * PocketID's client-level group restriction, so the tokens themselves are not
 * propagated downstream — only the success signal matters.
 */
export async function exchangePocketIdCode(
  cfg: PocketIdConfig,
  callbackUri: string,
  code: string,
  codeVerifier: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  let tokenEndpoint: string;
  try {
    ({ token_endpoint: tokenEndpoint } = await discover(cfg));
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: callbackUri,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    code_verifier: codeVerifier,
  });

  let res: Response;
  try {
    res = await fetch(tokenEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body,
    });
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }

  if (!res.ok) {
    let detail = "";
    try { detail = (await res.text()).slice(0, 200); } catch { /* ignore */ }
    log("error", "pocketid_token_exchange_http_error", { status: res.status, detail });
    return { ok: false, error: `pocketid_token_http_${res.status}` };
  }

  const tokens = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (typeof tokens.access_token !== "string" && typeof tokens.id_token !== "string") {
    return { ok: false, error: "pocketid_token_missing" };
  }

  return { ok: true };
}
