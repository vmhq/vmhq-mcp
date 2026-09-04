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
import { createRemoteJWKSet, jwtVerify } from "jose";
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
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
};

/** The authenticated person, as asserted by PocketID's signed id_token. */
export type PocketIdIdentity = {
  /** OIDC `sub`: stable per user, the thing worth storing and revoking by. */
  subject: string;
  email?: string;
  name?: string;
};

const DISCOVERY_TTL_MS = 60 * 60 * 1000; // 1 hour
/**
 * Ceiling on every call to the provider. Both calls sit inside a browser
 * request handler, so an identity provider that stops answering would
 * otherwise hold those handlers open for as long as it liked.
 */
export const PROVIDER_TIMEOUT_MS = 10_000;
let discoveryCache: { issuer: string; data: Discovery; expiresAt: number } | undefined;
/**
 * Remote JWKS for the current issuer. createRemoteJWKSet() caches the keys and
 * refetches on an unknown `kid`, so key rotation at PocketID is handled without
 * restarting this server. Cached alongside the discovery document and
 * invalidated with it.
 */
let jwksCache: { issuer: string; jwks: ReturnType<typeof createRemoteJWKSet> } | undefined;

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
  const res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS) });
  if (!res.ok) {
    throw new Error(`pocketid_discovery_http_${res.status}`);
  }

  const json = (await res.json()) as Partial<Discovery>;
  // jwks_uri and issuer are required now that the id_token is verified rather
  // than trusted: without them there is nothing to check the signature against.
  if (!json.authorization_endpoint || !json.token_endpoint || !json.jwks_uri || !json.issuer) {
    throw new Error("pocketid_discovery_incomplete");
  }

  const data: Discovery = {
    issuer: json.issuer,
    authorization_endpoint: json.authorization_endpoint,
    token_endpoint: json.token_endpoint,
    jwks_uri: json.jwks_uri,
  };
  if (data.issuer !== cfg.issuer) throw new Error("pocketid_discovery_issuer_mismatch");
  for (const endpoint of [data.authorization_endpoint, data.token_endpoint, data.jwks_uri]) {
    const parsed = new URL(endpoint);
    if (parsed.username || parsed.password || (parsed.protocol !== "https:" && !(new URL(cfg.issuer).protocol === "http:" && parsed.origin === new URL(cfg.issuer).origin))) {
      throw new Error("pocketid_discovery_insecure_endpoint");
    }
  }
  discoveryCache = { issuer: cfg.issuer, data, expiresAt: Date.now() + DISCOVERY_TTL_MS };
  return data;
}

/** Clear the cached discovery document (used by tests). */
export function resetPocketIdDiscoveryCache(): void {
  discoveryCache = undefined;
  jwksCache = undefined;
}

function jwksFor(discovery: Discovery): ReturnType<typeof createRemoteJWKSet> {
  if (jwksCache && jwksCache.issuer === discovery.issuer) {
    return jwksCache.jwks;
  }
  const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
  jwksCache = { issuer: discovery.issuer, jwks };
  return jwks;
}

/**
 * Verifies the id_token and returns who signed in.
 *
 * The signature, issuer, audience and expiry are all checked. OIDC Core allows
 * skipping signature validation for a token fetched directly from the token
 * endpoint over TLS, but this server hands out a root shell on the strength of
 * this assertion, so it is verified properly rather than trusted because the
 * transport looked right.
 */
async function verifyIdToken(cfg: PocketIdConfig, discovery: Discovery, idToken: string): Promise<PocketIdIdentity> {
  const { payload } = await jwtVerify(idToken, jwksFor(discovery), {
    issuer: discovery.issuer,
    audience: cfg.clientId,
  });

  const subject = typeof payload.sub === "string" ? payload.sub : "";
  if (!subject) {
    throw new Error("pocketid_id_token_without_subject");
  }

  return {
    subject,
    ...(typeof payload.email === "string" ? { email: payload.email } : {}),
    ...(typeof payload.name === "string" ? { name: payload.name } : {}),
  };
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
 * Exchange the PocketID authorization code for tokens (client_secret_post) and
 * return who signed in.
 *
 * PocketID's client-level group restriction still decides who may authenticate,
 * but the identity is carried downstream now: it is bound to the access token
 * and named in every log line, so a command run against the hypervisor can be
 * traced back to a person rather than to a client id.
 */
export async function exchangePocketIdCode(
  cfg: PocketIdConfig,
  callbackUri: string,
  code: string,
  codeVerifier: string,
): Promise<{ ok: true; identity: PocketIdIdentity } | { ok: false; error: string }> {
  let discovery: Discovery;
  try {
    discovery = await discover(cfg);
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
  const tokenEndpoint = discovery.token_endpoint;

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
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      redirect: "error",
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
  if (typeof tokens.id_token !== "string" || !tokens.id_token) {
    // Without an id_token there is no identity to attribute anything to, and a
    // silent fallback would put unattributable sessions back on the hypervisor.
    log("error", "pocketid_id_token_missing", { hint: "POCKETID_SCOPES must include openid." });
    return { ok: false, error: "pocketid_id_token_missing" };
  }

  try {
    const identity = await verifyIdToken(cfg, discovery, tokens.id_token);
    return { ok: true, identity };
  } catch (err) {
    log("error", "pocketid_id_token_invalid", { error: err instanceof Error ? err.message : String(err) });
    return { ok: false, error: "pocketid_id_token_invalid" };
  }
}
