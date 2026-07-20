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
