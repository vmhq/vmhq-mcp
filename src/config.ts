import type { ServiceAuth, ServiceDefinition, ServiceId } from "./services.js";

function readEnv(name: string, fallback?: string): string {
  return process.env[name] ?? fallback ?? "";
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function bearerAuth(tokenEnv: string): ServiceAuth {
  return { type: "bearer", tokenEnv };
}

function optionalService(
  id: ServiceId,
  title: string,
  baseUrlEnv: string,
  auth: ServiceAuth,
  defaultPathPrefix: string,
  defaultPathParams?: Record<string, string>,
): ServiceDefinition | undefined {
  const baseUrl = readEnv(baseUrlEnv);

  if (!baseUrl) {
    return undefined;
  }

  return {
    id,
    title,
    baseUrl,
    auth,
    defaultPathPrefix,
    defaultPathParams,
  };
}

function proxmoxAuth(): ServiceAuth {
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

export type AppConfig = {
  port: number;
  publicUrl?: string;
  iconUrl: string;
  accessToken: string;
  corsOrigin?: string;
  services: ServiceDefinition[];
};

function perplexityService(): ServiceDefinition | undefined {
  const apiKey = readEnv("OPENROUTER_API_KEY");
  if (!apiKey) return undefined;

  return {
    id: "perplexity",
    title: "Perplexity via OpenRouter",
    baseUrl: readEnv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
    auth: bearerAuth("OPENROUTER_API_KEY"),
    defaultPathPrefix: "/",
  };
}

export function loadConfig(): AppConfig {
  const minifluxAuthMode = readEnv("MINIFLUX_AUTH_MODE", "x-auth-token");
  const services = [
    optionalService("home_assistant", "Home Assistant", "HOME_ASSISTANT_BASE_URL", bearerAuth("HOME_ASSISTANT_TOKEN"), "/api"),
    optionalService(
      "miniflux",
      "Miniflux",
      "MINIFLUX_BASE_URL",
      minifluxAuthMode === "bearer"
        ? bearerAuth("MINIFLUX_TOKEN")
        : { type: "header", tokenEnv: "MINIFLUX_TOKEN", headerName: "X-Auth-Token" },
      "/v1",
    ),
    optionalService("karakeep", "Karakeep", "KARAKEEP_BASE_URL", bearerAuth("KARAKEEP_TOKEN"), "/api/v1"),
    optionalService("searxng", "SearXNG", "SEARXNG_BASE_URL", { type: "none" }, "/"),
    optionalService("proxmox", "Proxmox", "PROXMOX_BASE_URL", proxmoxAuth(), "/api2/json"),
    optionalService("memos", "Memos", "MEMOS_BASE_URL", bearerAuth("MEMOS_TOKEN"), "/api/v1"),
    perplexityService(),
    optionalService(
      "nextdns",
      "NextDNS",
      "NEXTDNS_BASE_URL",
      { type: "header", tokenEnv: "NEXTDNS_API_KEY", headerName: "X-Api-Key" },
      `/profiles/${readEnv("NEXTDNS_PROFILE_ID", "39f768")}`,
      { profileId: readEnv("NEXTDNS_PROFILE_ID", "39f768") },
    ),
  ].filter((service): service is ServiceDefinition => service !== undefined);

  return {
    port: Number(readEnv("MCP_PORT", "3010")),
    publicUrl: readEnv("MCP_PUBLIC_URL") || undefined,
    iconUrl: readEnv("MCP_ICON_URL", "https://cdn.jsdelivr.net/gh/selfhst/icons/png/mcphub.png"),
    accessToken: requireEnv("MCP_ACCESS_TOKEN"),
    corsOrigin: readEnv("MCP_CORS_ORIGIN") || undefined,
    services,
  };
}
