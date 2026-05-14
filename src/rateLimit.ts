const windows = new Map<string, Map<string, { count: number; resetAt: number }>>();

function clientIp(req: Request): string {
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }
  return "0.0.0.0";
}

export type RateLimitConfig = {
  maxRequests: number;
  windowMs: number;
};

const defaultConfigs: Record<string, RateLimitConfig> = {
  "oauth_authorize": { maxRequests: 5, windowMs: 60_000 },
  "oauth_register": { maxRequests: 3, windowMs: 60_000 },
  "oauth_token": { maxRequests: 10, windowMs: 60_000 },
  "oauth_revoke": { maxRequests: 5, windowMs: 60_000 },
  "mcp": { maxRequests: 120, windowMs: 60_000 },
};

export function checkRateLimit(req: Request, bucket: string): boolean {
  const config = defaultConfigs[bucket];
  if (!config) return true;

  const ip = clientIp(req);
  let bucketMap = windows.get(bucket);
  if (!bucketMap) {
    bucketMap = new Map();
    windows.set(bucket, bucketMap);
  }

  const now = Date.now();
  const entry = bucketMap.get(ip);

  if (!entry || entry.resetAt <= now) {
    bucketMap.set(ip, { count: 1, resetAt: now + config.windowMs });
    return true;
  }

  if (entry.count >= config.maxRequests) {
    return false;
  }

  entry.count++;
  return true;
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
}, CLEANUP_INTERVAL_MS).unref();
