const windows = new Map<string, Map<string, { count: number; resetAt: number }>>();

const UNKNOWN_CLIENT_KEY = "__no_client_ip__";

/**
 * Whether to trust reverse-proxy IP headers (CF-Connecting-IP, X-Real-IP,
 * X-Forwarded-For). Defaults to true (this server expects Cloudflare/nginx in
 * front of it). Set MCP_TRUST_PROXY=false if the server is ever reachable
 * directly, since those headers are trivially spoofable by any client and
 * would otherwise let a caller dodge per-IP rate limits by rotating them.
 * When proxy headers are not trusted (or absent), the real socket IP from
 * the HTTP server (Bun: server.requestIP(req)) is used as the rate-limit key,
 * so there is no shared global bucket that one client could exhaust for all.
 */
function trustProxyHeaders(): boolean {
  return (process.env.MCP_TRUST_PROXY ?? "true").toLowerCase() !== "false";
}

/** Headers consulted, in order, when no single header has been pinned. */
const LEGACY_PROXY_HEADERS = ["cf-connecting-ip", "x-real-ip", "x-forwarded-for"] as const;

/**
 * The one header the reverse proxy in front of this server sets, from
 * MCP_TRUSTED_IP_HEADER. Consulting several at once is a bypass waiting to
 * happen: a proxy that sets X-Real-IP does not strip CF-Connecting-IP, so a
 * client behind it can supply that one itself and win. Unset keeps the older
 * behaviour of trying all three; loadConfig() says so at startup.
 */
export function trustedIpHeader(): string | undefined {
  const raw = process.env.MCP_TRUSTED_IP_HEADER?.trim().toLowerCase();
  return raw || undefined;
}

export type ClientIpOptions = {
  trustProxy?: boolean;
  /** Real socket IP from the HTTP server (Bun: server.requestIP(req)). */
  socketIp?: string;
  /** Only this header is read when set. Defaults to MCP_TRUSTED_IP_HEADER. */
  trustedHeader?: string;
};

function ipFromHeader(req: Request, header: string): string | undefined {
  const value = req.headers.get(header)?.trim();
  if (!value) return undefined;
  // X-Forwarded-For is a chain; the first hop is the client as the proxy saw it.
  return header === "x-forwarded-for" ? value.split(",")[0]?.trim() || undefined : value;
}

/**
 * Client IP from reverse-proxy headers (Cloudflare, nginx, etc.) when trusted,
 * falling back to the real socket IP. Returns undefined only when neither a
 * trusted header nor a socket IP is available.
 */
export function clientIp(req: Request, options: ClientIpOptions = {}): string | undefined {
  const trustProxy = options.trustProxy ?? trustProxyHeaders();
  if (trustProxy) {
    const pinned = options.trustedHeader?.trim().toLowerCase() || trustedIpHeader();
    const headers = pinned ? [pinned] : LEGACY_PROXY_HEADERS;
    for (const header of headers) {
      const value = ipFromHeader(req, header);
      if (value) return value;
    }
  }
  return options.socketIp;
}

function rateLimitKey(req: Request, options: ClientIpOptions): string {
  return clientIp(req, options) ?? UNKNOWN_CLIENT_KEY;
}

export type RateLimitConfig = {
  maxRequests: number;
  windowMs: number;
};

const defaultConfigs: Record<string, RateLimitConfig> = {
  oauth_authorize: { maxRequests: 30, windowMs: 60_000 },
  oauth_register: { maxRequests: 30, windowMs: 60_000 },
  oauth_token: { maxRequests: 60, windowMs: 60_000 },
  oauth_revoke: { maxRequests: 20, windowMs: 60_000 },
  mcp: { maxRequests: 120, windowMs: 60_000 },
  // Only consumed when authentication fails, so a legitimate client never
  // touches it. Not persisted across restarts: that would mean writing to disk
  // on the hot path to close a window that only opens on a deploy, against a
  // token long enough that brute force was never the threat.
  mcp_auth_failure: { maxRequests: 10, windowMs: 60_000 },
};

/** Shared bucket for requests with no IP at all (no socket IP available; acts as a global fallback cap). */
const unknownClientConfigs: Partial<Record<string, RateLimitConfig>> = {
  oauth_register: { maxRequests: 60, windowMs: 60_000 },
  oauth_authorize: { maxRequests: 30, windowMs: 60_000 },
  oauth_token: { maxRequests: 60, windowMs: 60_000 },
};

export function checkRateLimit(req: Request, bucket: string, options: ClientIpOptions = {}): boolean {
  const key = rateLimitKey(req, options);
  const config =
    key === UNKNOWN_CLIENT_KEY
      ? (unknownClientConfigs[bucket] ?? defaultConfigs[bucket])
      : defaultConfigs[bucket];
  if (!config) return true;

  let bucketMap = windows.get(bucket);
  if (!bucketMap) {
    bucketMap = new Map();
    windows.set(bucket, bucketMap);
  }

  const now = Date.now();
  const entry = bucketMap.get(key);

  if (!entry || entry.resetAt <= now) {
    bucketMap.set(key, { count: 1, resetAt: now + config.windowMs });
    return true;
  }

  if (entry.count >= config.maxRequests) {
    return false;
  }

  entry.count++;
  return true;
}

/** Seconds until the current rate-limit window resets (for Retry-After). */
export function rateLimitRetryAfterSec(req: Request, bucket: string, options: ClientIpOptions = {}): number {
  const key = rateLimitKey(req, options);
  const entry = windows.get(bucket)?.get(key);
  if (!entry) return 60;
  return Math.max(1, Math.ceil((entry.resetAt - Date.now()) / 1000));
}

const CLEANUP_INTERVAL_MS = 5 * 60_000;
setInterval(() => {
  const now = Date.now();
  for (const [bucket, bucketMap] of windows.entries()) {
    for (const [ip, entry] of bucketMap) {
      if (entry.resetAt <= now) {
        bucketMap.delete(ip);
      }
    }
    if (bucketMap.size === 0) {
      windows.delete(bucket);
    }
  }
}, CLEANUP_INTERVAL_MS).unref?.();
