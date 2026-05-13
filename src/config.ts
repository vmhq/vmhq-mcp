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
  accessToken: string;
  services: ServiceDefinition[];
};

export function loadConfig(): AppConfig {
  const minifluxAuthMode = readEnv("MINIFLUX_AUTH_MODE", "x-auth-token");

  return {
    port: Number(readEnv("MCP_PORT", "3010")),
    publicUrl: readEnv("MCP_PUBLIC_URL") || undefined,
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
        auth: { type: "none" },
        defaultPathPrefix: "/",
      },
      {
        id: "proxmox",
        title: "Proxmox",
        baseUrl: requireEnv("PROXMOX_BASE_URL"),
        auth: proxmoxAuth(),
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
