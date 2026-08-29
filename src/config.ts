import type { ServiceDefinition } from "./services.js";
import { isPrivateHost, serviceFromRegistryEntry, SERVICE_REGISTRY } from "./serviceRegistry.js";
import type { ProxmoxSshConfig } from "./sshClient.js";
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

/** Minimum accepted length for the static MCP access token. */
const MIN_ACCESS_TOKEN_LENGTH = 32;

function requireAccessToken(): string {
  const token = requireEnv("MCP_ACCESS_TOKEN");
  if (token.length < MIN_ACCESS_TOKEN_LENGTH) {
    throw new Error(
      `MCP_ACCESS_TOKEN must be at least ${MIN_ACCESS_TOKEN_LENGTH} characters. Generate one with: openssl rand -base64 48`,
    );
  }
  return token;
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
  /** SSH access to the Proxmox node, enabling shell tools (optional). */
  proxmoxSsh?: ProxmoxSshConfig;
};

function parseVmidList(raw: string): number[] | undefined {
  const vmids = raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const vmid = Number(entry);
      if (!Number.isInteger(vmid) || vmid <= 0) {
        throw new Error(`PROXMOX_SSH_ALLOWED_VMIDS contains an invalid container ID: ${entry}`);
      }
      return vmid;
    });

  return vmids.length ? vmids : undefined;
}

/**
 * SSH tools are enabled by setting PROXMOX_SSH_HOST. They hand an agent a real
 * shell on the hypervisor, so the host key is pinned unless the node sits on a
 * private network, mirroring how PROXMOX_INSECURE_TLS is gated.
 */
export function loadProxmoxSshConfig(): ProxmoxSshConfig | undefined {
  const host = readEnv("PROXMOX_SSH_HOST").trim();
  if (!host) return undefined;

  const hostFingerprint = readEnv("PROXMOX_SSH_HOST_FINGERPRINT").trim() || undefined;
  // A single-label hostname (pve, proxmox) only resolves on the local network,
  // so treat it like the private addresses isPrivateHost() already accepts.
  const isLocalNode = isPrivateHost(host) || !host.includes(".");
  if (!hostFingerprint && !isLocalNode) {
    throw new Error(
      `PROXMOX_SSH_HOST_FINGERPRINT is required for the public host ${host}. ` +
        "Get it with: ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -",
    );
  }

  return {
    host,
    port: readNumberEnv("PROXMOX_SSH_PORT", 22),
    user: readEnv("PROXMOX_SSH_USER", "root"),
    hostFingerprint,
    timeoutMs: readNumberEnv("PROXMOX_SSH_TIMEOUT_MS", 120_000),
    maxOutputChars: readNumberEnv("PROXMOX_SSH_MAX_OUTPUT", 30_000),
    allowedVmids: parseVmidList(readEnv("PROXMOX_SSH_ALLOWED_VMIDS")),
    sudo: readEnv("PROXMOX_SSH_SUDO").toLowerCase() === "true",
    containerShell: readEnv("PROXMOX_SSH_CONTAINER_SHELL", "/bin/sh"),
  };
}

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
    accessToken: requireAccessToken(),
    corsOrigin: readEnv("MCP_CORS_ORIGIN") || undefined,
    upstreamTimeoutMs: readNumberEnv("MCP_UPSTREAM_TIMEOUT_MS", 30_000),
    services,
    pinnedHaEntities,
    pocketId: loadPocketIdConfig(),
    proxmoxSsh: loadProxmoxSshConfig(),
  };
}
