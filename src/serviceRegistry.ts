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
};

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

export const SERVICE_REGISTRY: ServiceRegistryEntry[] = [
  {
    id: "home_assistant",
    title: "Home Assistant",
    baseUrlEnv: "HOME_ASSISTANT_BASE_URL",
    auth: bearerAuth("HOME_ASSISTANT_TOKEN"),
    defaultPathPrefix: "/api",
  },
  {
    id: "miniflux",
    title: "Miniflux",
    baseUrlEnv: "MINIFLUX_BASE_URL",
    auth: minifluxAuth,
    defaultPathPrefix: "/v1",
  },
  {
    id: "karakeep",
    title: "Karakeep",
    baseUrlEnv: "KARAKEEP_BASE_URL",
    auth: bearerAuth("KARAKEEP_TOKEN"),
    defaultPathPrefix: "/api/v1",
  },
  {
    id: "searxng",
    title: "SearXNG",
    baseUrlEnv: "SEARXNG_BASE_URL",
    auth: { type: "none" },
    defaultPathPrefix: "/",
  },
  {
    id: "proxmox",
    title: "Proxmox",
    baseUrlEnv: "PROXMOX_BASE_URL",
    auth: proxmoxAuth,
    defaultPathPrefix: "/api2/json",
  },
  {
    id: "memos",
    title: "Memos",
    baseUrlEnv: "MEMOS_BASE_URL",
    auth: bearerAuth("MEMOS_TOKEN"),
    defaultPathPrefix: "/api/v1",
  },
  {
    id: "perplexity",
    title: "Perplexity via OpenRouter",
    enabledWhenEnv: "OPENROUTER_API_KEY",
    defaultBaseUrl: "https://openrouter.ai/api/v1",
    baseUrlEnv: "OPENROUTER_BASE_URL",
    auth: bearerAuth("OPENROUTER_API_KEY"),
    defaultPathPrefix: "/",
  },
  {
    id: "nextdns",
    title: "NextDNS",
    baseUrlEnv: "NEXTDNS_BASE_URL",
    auth: { type: "header", tokenEnv: "NEXTDNS_API_KEY", headerName: "X-Api-Key" },
    defaultPathPrefix: "/profiles/{profileId}",
    defaultPathParams: (readEnv) => {
      const profileId = readEnv("NEXTDNS_PROFILE_ID");
      return profileId ? { profileId } : undefined;
    },
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
  };
}
