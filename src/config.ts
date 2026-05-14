import type { ServiceDefinition } from "./services.js";
import { serviceFromRegistryEntry, SERVICE_REGISTRY } from "./serviceRegistry.js";

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

function readNumberEnv(name: string, fallback: number): number {
  const raw = readEnv(name);
  if (!raw) return fallback;

  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive number.`);
  }

  return value;
}

export type AppConfig = {
  port: number;
  publicUrl?: string;
  iconUrl: string;
  accessToken: string;
  corsOrigin?: string;
  upstreamTimeoutMs: number;
  services: ServiceDefinition[];
};

export function loadConfig(): AppConfig {
  const services = SERVICE_REGISTRY.map((entry) => serviceFromRegistryEntry(entry, readEnv)).filter(
    (service): service is ServiceDefinition => service !== undefined,
  );

  return {
    port: readNumberEnv("MCP_PORT", 3010),
    publicUrl: readEnv("MCP_PUBLIC_URL") || undefined,
    iconUrl: readEnv("MCP_ICON_URL", "https://cdn.jsdelivr.net/gh/selfhst/icons/png/mcphub.png"),
    accessToken: requireEnv("MCP_ACCESS_TOKEN"),
    corsOrigin: readEnv("MCP_CORS_ORIGIN") || undefined,
    upstreamTimeoutMs: readNumberEnv("MCP_UPSTREAM_TIMEOUT_MS", 30_000),
    services,
  };
}
