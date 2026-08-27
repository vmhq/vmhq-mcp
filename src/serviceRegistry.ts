import type { ServiceAuth, ServiceDefinition, ServiceId } from "./services.js";

export type ServiceRegistryEntry = {
  id: ServiceId;
  title: string;
  defaultPathPrefix: string;
  baseUrlEnv?: string;
  defaultBaseUrl?: string;
  enabledWhenEnv?: string;
  auth: ServiceAuth | ((readEnv: (name: string, fallback?: string) => string) => ServiceAuth);
  defaultPathParams?: (readEnv: (name: string, fallback?: string) => string) => Record<string, string> | undefined;
  timeoutMs?: number;
  pingPath?: string;
  /** Env var that, when truthy, disables TLS verification for this service alone. */
  insecureTlsEnv?: string;
};

/**
 * Hosts for which disabling TLS verification is acceptable: loopback, RFC1918
 * ranges, CGNAT, link-local and .local/.internal names. Everything else must
 * present a valid certificate, so a misconfigured flag cannot silently expose
 * traffic to a public host.
 */
export function isPrivateHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/gu, "").toLowerCase();

  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) {
    return true;
  }

  // IPv6 loopback and unique-local/link-local ranges.
  if (host === "::1" || /^f[cd][0-9a-f]{2}:/u.test(host) || host.startsWith("fe80:")) {
    return true;
  }

  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u);
  if (!ipv4) {
    return false;
  }

  const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
  if (a === 127 || a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;

  return false;
}

function readInsecureTls(entry: ServiceRegistryEntry, baseUrl: string, readEnv: (name: string, fallback?: string) => string): boolean {
  if (!entry.insecureTlsEnv) {
    return false;
  }

  const raw = readEnv(entry.insecureTlsEnv).toLowerCase();
  if (raw !== "true" && raw !== "1") {
    return false;
  }

  let hostname: string;
  try {
    hostname = new URL(baseUrl).hostname;
  } catch {
    throw new Error(`${entry.baseUrlEnv ?? entry.id} is not a valid URL.`);
  }

  if (!isPrivateHost(hostname)) {
    throw new Error(
      `${entry.insecureTlsEnv} may only be enabled for private-network hosts, but ${hostname} is public. ` +
        "Use a valid certificate (or NODE_EXTRA_CA_CERTS) for public upstreams.",
    );
  }

  return true;
}

function bearerAuth(tokenEnv: string): ServiceAuth {
  return { type: "bearer", tokenEnv };
}

function proxmoxAuth(readEnv: (name: string, fallback?: string) => string): ServiceAuth {
  const tokenId = readEnv("PROXMOX_TOKEN_ID");
  const tokenSecret = readEnv("PROXMOX_TOKEN_SECRET");

  if (!tokenId && !tokenSecret) {
    return { type: "none" };
  }

  if (!tokenId || !tokenSecret) {
    throw new Error("PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET must be configured together.");
  }

  return {
    type: "static",
    headerName: "Authorization",
    value: `PVEAPIToken=${tokenId}=${tokenSecret}`,
  };
}

function minifluxAuth(readEnv: (name: string, fallback?: string) => string): ServiceAuth {
  const authMode = readEnv("MINIFLUX_AUTH_MODE", "x-auth-token");
  return authMode === "bearer"
    ? bearerAuth("MINIFLUX_TOKEN")
    : { type: "header", tokenEnv: "MINIFLUX_TOKEN", headerName: "X-Auth-Token" };
}

function adguardAuth(readEnv: (name: string, fallback?: string) => string): ServiceAuth {
  const username = readEnv("ADGUARD_USERNAME");
  const password = readEnv("ADGUARD_PASSWORD");

  if (!username && !password) {
    return { type: "none" };
  }

  if (!username || !password) {
    throw new Error("ADGUARD_USERNAME and ADGUARD_PASSWORD must be configured together.");
  }

  return {
    type: "static",
    headerName: "Authorization",
    value: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
  };
}

export const SERVICE_REGISTRY: ServiceRegistryEntry[] = [
  {
    id: "home_assistant",
    title: "Home Assistant",
    baseUrlEnv: "HOME_ASSISTANT_BASE_URL",
    auth: bearerAuth("HOME_ASSISTANT_TOKEN"),
    defaultPathPrefix: "/api",
    pingPath: "/api/",
  },
  {
    id: "miniflux",
    title: "Miniflux",
    baseUrlEnv: "MINIFLUX_BASE_URL",
    auth: minifluxAuth,
    defaultPathPrefix: "/v1",
    pingPath: "/v1/me",
  },
  {
    id: "karakeep",
    title: "Karakeep",
    baseUrlEnv: "KARAKEEP_BASE_URL",
    auth: bearerAuth("KARAKEEP_TOKEN"),
    defaultPathPrefix: "/api/v1",
    pingPath: "/api/v1/lists",
  },
  {
    id: "searxng",
    title: "SearXNG",
    baseUrlEnv: "SEARXNG_BASE_URL",
    auth: { type: "none" },
    defaultPathPrefix: "/",
    pingPath: "/",
  },
  {
    id: "proxmox",
    title: "Proxmox",
    baseUrlEnv: "PROXMOX_BASE_URL",
    auth: proxmoxAuth,
    defaultPathPrefix: "/api2/json",
    timeoutMs: 120_000,
    pingPath: "/api2/json/version",
    insecureTlsEnv: "PROXMOX_INSECURE_TLS",
  },
  {
    id: "memos",
    title: "Memos",
    baseUrlEnv: "MEMOS_BASE_URL",
    auth: bearerAuth("MEMOS_TOKEN"),
    defaultPathPrefix: "/api/v1",
    pingPath: "/api/v1/instance/profile",
  },
  {
    id: "adguard",
    title: "AdGuard Home",
    baseUrlEnv: "ADGUARD_BASE_URL",
    auth: adguardAuth,
    defaultPathPrefix: "/control",
    pingPath: "/control/status",
  },
];

export function serviceFromRegistryEntry(
  entry: ServiceRegistryEntry,
  readEnv: (name: string, fallback?: string) => string,
): ServiceDefinition | undefined {
  if (entry.enabledWhenEnv && !readEnv(entry.enabledWhenEnv)) {
    return undefined;
  }

  const baseUrl = entry.baseUrlEnv ? readEnv(entry.baseUrlEnv, entry.defaultBaseUrl) : entry.defaultBaseUrl ?? "";
  if (!baseUrl) {
    return undefined;
  }

  const auth = typeof entry.auth === "function" ? entry.auth(readEnv) : entry.auth;

  return {
    id: entry.id,
    title: entry.title,
    baseUrl,
    auth,
    defaultPathPrefix: entry.defaultPathPrefix,
    defaultPathParams: entry.defaultPathParams?.(readEnv),
    timeoutMs: entry.timeoutMs,
    pingPath: entry.pingPath,
    insecureTls: readInsecureTls(entry, baseUrl, readEnv),
  };
}
