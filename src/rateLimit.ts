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

export type ClientIpOptions = {
  trustProxy?: boolean;
  /** Real socket IP from the HTTP server (Bun: server.requestIP(req)). */
  socketIp?: string;
};

/**
 * Client IP from reverse-proxy headers (Cloudflare, nginx, etc.) when trusted,
 * falling back to the real socket IP. Returns undefined only when neither a
 * trusted header nor a socket IP is available.
 */
export function clientIp(req: Request, options: ClientIpOptions = {}): string | undefined {
  const trustProxy = options.trustProxy ?? trustProxyHeaders();
  if (trustProxy) {
    for (const header of ["cf-connecting-ip", "x-real-ip"]) {
      const value = req.headers.get(header)?.trim();
      if (value) return value;
    }
    const forwarded = req.headers.get("x-forwarded-for");
    if (forwarded) {
      return forwarded.split(",")[0]?.trim() || options.socketIp;
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
