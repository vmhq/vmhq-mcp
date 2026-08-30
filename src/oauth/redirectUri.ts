/**
 * Redirect URI validation and matching.
 *
 *   RFC 8252 §7.1 – private-use URI schemes (native apps)
 *   RFC 8252 §7.3 – loopback port-agnostic matching
 *   RFC 8252 §8.3 – loopback must use http
 */

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Schemes that must never be accepted as OAuth redirect URIs: they execute
 * script in the browser context (javascript:, vbscript:), embed attacker-
 * controlled documents (data:, blob:), or reference local/browser-internal
 * resources. Native-app schemes (claude://, cursor://, …) remain allowed
 * per RFC 8252 §7.1.
 */
const BLOCKED_SCHEMES = new Set([
  "javascript:",
  "data:",
  "vbscript:",
  "file:",
  "filesystem:",
  "about:",
  "blob:",
  "view-source:",
  "chrome:",
  "chrome-extension:",
  "moz-extension:",
  "ms-browser-extension:",
  "resource:",
  "jar:",
  "ws:",
  "wss:",
]);

/** Claude.ai web connector callback (https://claude.com/docs/connectors/building/authentication). */
export const CLAUDE_WEB_AUTH_CALLBACK = "https://claude.ai/api/mcp/auth_callback";

/** Legacy/wrong URIs some clients register; map to the canonical Claude web callback. */
const REDIRECT_URI_ALIASES: Record<string, string> = {
  "https://claude.ai/callback": CLAUDE_WEB_AUTH_CALLBACK,
};

export function canonicalRedirectUri(uri: string): string {
  return REDIRECT_URI_ALIASES[uri] ?? uri;
}

export function expandRedirectUris(uris: string[]): string[] {
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
export function isRegistrableRedirectUri(uri: string): boolean {
  try {
    const p = new URL(uri);
    if (p.username || p.password || p.hash) return false;

    // RFC 8252 §8.3 – loopback: must use http (not https)
    if (LOOPBACK.has(p.hostname)) return p.protocol === "http:";

    // RFC 8252 §7.1 – private-use URI schemes (e.g. claude://, cursor://),
    // minus browser-executable / local-resource schemes.
    if (p.protocol !== "https:" && p.protocol !== "http:") {
      return !BLOCKED_SCHEMES.has(p.protocol);
    }

    // Standard HTTPS
    return p.protocol === "https:" && p.hostname !== "0.0.0.0" && !p.hostname.includes("*");
  } catch {
    return false;
  }
}

/**
 * Optional hard allowlist of redirect destinations, from
 * MCP_ALLOWED_REDIRECT_HOSTS (comma-separated hostnames).
 *
 * Dynamic client registration is public by design, and isRegistrableRedirectUri()
 * accepts any HTTPS host, so without an allowlist anyone can register a client
 * pointing at a host they control and phish an authorization code out of the
 * one person who can sign in. Loopback and private-use schemes stay allowed
 * regardless: they deliver the code to an app on the user's own machine.
 *
 * When the variable is unset every host is accepted (the pre-existing
 * behaviour); loadConfig() warns about that at startup.
 */
export function allowedRedirectHosts(): string[] {
  return (process.env.MCP_ALLOWED_REDIRECT_HOSTS ?? "")
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
}

/** True when a host matches an allowlist entry exactly or as a subdomain of it. */
function hostMatches(hostname: string, allowed: string): boolean {
  return hostname === allowed || hostname.endsWith(`.${allowed}`);
}

export function isAllowedRedirectTarget(uri: string, allowed = allowedRedirectHosts()): boolean {
  if (allowed.length === 0) return true;

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  // Loopback and private-use schemes (claude://, cursor://) hand the code to a
  // local app, not to a remote host, so an allowlist of hosts cannot judge them.
  if (LOOPBACK.has(parsed.hostname)) return true;
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return true;

  const hostname = parsed.hostname.toLowerCase();
  return allowed.some((entry) => hostMatches(hostname, entry));
}

/** Human-readable destination shown on the consent page. */
export function redirectTargetLabel(uri: string): string {
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return `${parsed.protocol}//${parsed.hostname || parsed.pathname}`.replace(/\/+$/u, "");
    }
    return parsed.host;
  } catch {
    return uri;
  }
}

/**
 * RFC 8252 §7.3 – when matching redirect URIs at authorize time, loopback
 * addresses must accept any port (native clients bind an ephemeral port).
 * All other URIs require an exact match.
 */
export function redirectUriMatches(requested: string, registered: string): boolean {
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
