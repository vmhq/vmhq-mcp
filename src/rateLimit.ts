const windows = new Map<string, Map<string, { count: number; resetAt: number }>>();

const UNKNOWN_CLIENT_KEY = "__no_client_ip__";

/** Client IP from reverse-proxy headers (Cloudflare, nginx, etc.). */
export function clientIp(req: Request): string | undefined {
  for (const header of ["cf-connecting-ip", "x-real-ip"]) {
    const value = req.headers.get(header)?.trim();
    if (value) return value;
  }

  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0]?.trim() || undefined;
  }

  return undefined;
}

function rateLimitKey(req: Request): string {
  return clientIp(req) ?? UNKNOWN_CLIENT_KEY;
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

/** Stricter cap when the client IP cannot be determined (avoids one shared 0.0.0.0 bucket). */
const unknownClientConfigs: Partial<Record<string, RateLimitConfig>> = {
  oauth_register: { maxRequests: 60, windowMs: 60_000 },
  oauth_authorize: { maxRequests: 30, windowMs: 60_000 },
  oauth_token: { maxRequests: 60, windowMs: 60_000 },
};

export function checkRateLimit(req: Request, bucket: string): boolean {
  const key = rateLimitKey(req);
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
export function rateLimitRetryAfterSec(req: Request, bucket: string): number {
  const key = rateLimitKey(req);
  const entry = windows.get(bucket)?.get(key);
  if (!entry) return 60;
  return Math.max(1, Math.ceil((entry.resetAt - Date.now()) / 1000));
}

const CLEANUP_INTERVAL_MS = 5 * 60_000;
setInterval(() => {
  const now = Date.now();
  for (const bucketMap of windows.values()) {
    for (const [ip, entry] of bucketMap) {
      if (entry.resetAt <= now) {
        bucketMap.delete(ip);
      }
    }
  }
}, CLEANUP_INTERVAL_MS).unref?.();
