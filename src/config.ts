import type { ServiceDefinition } from "./services.js";
import { serviceFromRegistryEntry, SERVICE_REGISTRY } from "./serviceRegistry.js";
import type { PocketIdConfig } from "./oauth.js";

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

export type PinnedHaEntity = { entityId: string; alias?: string };

export type AppConfig = {
  port: number;
  publicUrl?: string;
  iconUrl: string;
  accessToken: string;
  corsOrigin?: string;
  upstreamTimeoutMs: number;
  services: ServiceDefinition[];
  pinnedHaEntities: PinnedHaEntity[];
  /** PocketID identity provider for the interactive OAuth flow (optional). */
  pocketId?: PocketIdConfig;
};

function loadPocketIdConfig(): PocketIdConfig | undefined {
  const issuer = readEnv("POCKETID_ISSUER").replace(/\/$/, "");
  const clientId = readEnv("POCKETID_CLIENT_ID");
  const clientSecret = readEnv("POCKETID_CLIENT_SECRET");
  if (!issuer || !clientId || !clientSecret) return undefined;

  const scopes = readEnv("POCKETID_SCOPES", "openid profile email")
    .split(/\s+/)
    .filter(Boolean);

  return { issuer, clientId, clientSecret, scopes: scopes.length ? scopes : ["openid"] };
}

export function loadConfig(): AppConfig {
  const services = SERVICE_REGISTRY.map((entry) => serviceFromRegistryEntry(entry, readEnv)).filter(
    (service): service is ServiceDefinition => service !== undefined,
  );

  const rawPinnedEntities = readEnv("HOME_ASSISTANT_PINNED_ENTITIES");
  const pinnedHaEntities: PinnedHaEntity[] = rawPinnedEntities
    ? rawPinnedEntities.split(",").flatMap((s) => {
        const trimmed = s.trim();
        if (!trimmed) return [];
        const colonIdx = trimmed.indexOf(":");
        if (colonIdx === -1) return [{ entityId: trimmed }];
        const entityId = trimmed.slice(0, colonIdx).trim();
        const alias = trimmed.slice(colonIdx + 1).trim();
        return entityId ? [{ entityId, alias: alias || undefined }] : [];
      })
    : [];

  const publicUrl = readEnv("MCP_PUBLIC_URL") || undefined;
  const defaultIconUrl = publicUrl
    ? `${publicUrl.replace(/\/$/, "")}/icon.svg`
    : "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/lovable.svg";

  return {
    port: readNumberEnv("MCP_PORT", 3010),
    publicUrl,
    iconUrl: readEnv("MCP_ICON_URL", defaultIconUrl),
    accessToken: requireEnv("MCP_ACCESS_TOKEN"),
    corsOrigin: readEnv("MCP_CORS_ORIGIN") || undefined,
    upstreamTimeoutMs: readNumberEnv("MCP_UPSTREAM_TIMEOUT_MS", 30_000),
    services,
    pinnedHaEntities,
    pocketId: loadPocketIdConfig(),
  };
}
