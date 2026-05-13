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
        baseUrl: readEnv("HOME_ASSISTANT_BASE_URL", "https://iot.vmhq.cl"),
        auth: bearerAuth("HOME_ASSISTANT_TOKEN"),
        defaultPathPrefix: "/api",
      },
      {
        id: "miniflux",
        title: "Miniflux",
        baseUrl: readEnv("MINIFLUX_BASE_URL", "https://miniflux.vmhq.cl"),
        auth:
          minifluxAuthMode === "bearer"
            ? bearerAuth("MINIFLUX_TOKEN")
            : { type: "header", tokenEnv: "MINIFLUX_TOKEN", headerName: "X-Auth-Token" },
        defaultPathPrefix: "/v1",
      },
      {
        id: "karakeep",
        title: "Karakeep",
        baseUrl: readEnv("KARAKEEP_BASE_URL", "https://karakeep.vmhq.cl"),
        auth: bearerAuth("KARAKEEP_TOKEN"),
        defaultPathPrefix: "/api/v1",
      },
      {
        id: "searxng",
        title: "SearXNG",
        baseUrl: readEnv("SEARXNG_BASE_URL", "https://searx.vmhq.cl"),
        auth: readEnv("SEARXNG_TOKEN") ? bearerAuth("SEARXNG_TOKEN") : { type: "none" },
        defaultPathPrefix: "/",
      },
      {
        id: "proxmox",
        title: "Proxmox",
        baseUrl: readEnv("PROXMOX_BASE_URL", "https://pve.vmhq.cl"),
        auth: { type: "prefixed", tokenEnv: "PROXMOX_TOKEN", prefix: proxmoxPrefix },
        defaultPathPrefix: "/api2/json",
      },
      {
        id: "memos",
        title: "Memos",
        baseUrl: readEnv("MEMOS_BASE_URL", "https://memos.vmhq.cl"),
        auth: bearerAuth("MEMOS_TOKEN"),
        defaultPathPrefix: "/api/v1",
      },
    ],
  };
}
