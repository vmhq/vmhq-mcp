import type { ServiceAuth, ServiceDefinition } from "./services.js";

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

export type AppConfig = {
  port: number;
  accessToken: string;
  services: ServiceDefinition[];
};

export function loadConfig(): AppConfig {
  const minifluxAuthMode = readEnv("MINIFLUX_AUTH_MODE", "x-auth-token");
  const proxmoxPrefix = readEnv("PROXMOX_AUTH_PREFIX", "PVEAPIToken=");

  return {
    port: Number(readEnv("MCP_PORT", "3010")),
    accessToken: requireEnv("MCP_ACCESS_TOKEN"),
    services: [
      {
        id: "home_assistant",
        title: "Home Assistant",
        baseUrl: requireEnv("HOME_ASSISTANT_BASE_URL"),
        auth: bearerAuth("HOME_ASSISTANT_TOKEN"),
        defaultPathPrefix: "/api",
      },
      {
        id: "miniflux",
        title: "Miniflux",
        baseUrl: requireEnv("MINIFLUX_BASE_URL"),
        auth:
          minifluxAuthMode === "bearer"
            ? bearerAuth("MINIFLUX_TOKEN")
            : { type: "header", tokenEnv: "MINIFLUX_TOKEN", headerName: "X-Auth-Token" },
        defaultPathPrefix: "/v1",
      },
      {
        id: "karakeep",
        title: "Karakeep",
        baseUrl: requireEnv("KARAKEEP_BASE_URL"),
        auth: bearerAuth("KARAKEEP_TOKEN"),
        defaultPathPrefix: "/api/v1",
      },
      {
        id: "searxng",
        title: "SearXNG",
        baseUrl: requireEnv("SEARXNG_BASE_URL"),
        auth: readEnv("SEARXNG_TOKEN") ? bearerAuth("SEARXNG_TOKEN") : { type: "none" },
        defaultPathPrefix: "/",
      },
      {
        id: "proxmox",
        title: "Proxmox",
        baseUrl: requireEnv("PROXMOX_BASE_URL"),
        auth: { type: "prefixed", tokenEnv: "PROXMOX_TOKEN", prefix: proxmoxPrefix },
        defaultPathPrefix: "/api2/json",
      },
      {
        id: "memos",
        title: "Memos",
        baseUrl: requireEnv("MEMOS_BASE_URL"),
        auth: bearerAuth("MEMOS_TOKEN"),
        defaultPathPrefix: "/api/v1",
      },
    ],
  };
}
