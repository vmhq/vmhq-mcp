import type { ServiceDefinition } from "./services.js";
import { allowedRedirectHosts } from "./oauth/redirectUri.js";
import { log } from "./logger.js";
import { isPrivateHost, serviceFromRegistryEntry, SERVICE_REGISTRY } from "./serviceRegistry.js";
import { isAllowedShell, type ProxmoxSshConfig } from "./sshClient.js";
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


export type AppConfig = {
  port: number;
  publicUrl?: string;
  iconUrl: string;
  accessToken: string;
  corsOrigin?: string;
  upstreamTimeoutMs: number;
  services: ServiceDefinition[];
  /** PocketID identity provider for the interactive OAuth flow (optional). */
  pocketId?: PocketIdConfig;
  /** SSH access to the Proxmox node, enabling shell tools (optional). */
  proxmoxSsh?: ProxmoxSshConfig;
  /** Plain-language capabilities of an issued token, shown on the consent page. */
  grantSummary: string[];
  /**
   * Host header values accepted on /mcp. When set, the MCP transport enables
   * DNS-rebinding protection. Empty means the protection stays off.
   */
  allowedHosts: string[];
};

/**
 * What a token issued through the OAuth flow can actually reach. The consent
 * page shows this, so someone deciding whether to continue is told that they
 * are handing over a root shell rather than "access to an MCP server".
 */
export function describeGrants(services: ServiceDefinition[], proxmoxSsh?: ProxmoxSshConfig): string[] {
  const grants: string[] = [];

  if (proxmoxSsh) {
    const scope = proxmoxSsh.allowedVmids
      ? `containers ${proxmoxSsh.allowedVmids.join(", ")}`
      : "the node and every container";
    grants.push(`A root shell on ${proxmoxSsh.host} (${scope}), as ${proxmoxSsh.user}`);
  }

  for (const service of services) {
    grants.push(`Full read and write access to ${service.title}`);
  }

  return grants;
}

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
  // A public node must be pinned up front. A private one falls back to
  // trust-on-first-use in sshKnownHosts.ts, which pins whatever key answers the
  // first connection rather than accepting any key forever.
  if (!hostFingerprint && !isLocalNode) {
    throw new Error(
      `PROXMOX_SSH_HOST_FINGERPRINT is required for the public host ${host}. ` +
        "Get it with: ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -",
    );
  }

  // The container shell is spliced into the node-level `pct exec` command, so
  // an operator typo with a space or a metacharacter must fail at startup
  // rather than at the first exec.
  // Trimmed before validating: a stray space pasted into a deployment UI is an
  // operator typo, not an injection attempt, and must not keep the server down.
  const containerShell = readEnv("PROXMOX_SSH_CONTAINER_SHELL", "/bin/sh").trim() || "/bin/sh";
  if (!isAllowedShell(containerShell)) {
    throw new Error(
      `PROXMOX_SSH_CONTAINER_SHELL must be an absolute path to an interpreter, for example /bin/sh. Got: ${containerShell}`,
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
    containerShell,
    jobDir: readEnv("PROXMOX_SSH_JOB_DIR", "/var/log/vmhq-mcp"),
    jobRetentionDays: readNumberEnv("PROXMOX_SSH_JOB_RETENTION_DAYS", 30),
  };
}

function loadPocketIdConfig(): PocketIdConfig | undefined {
  const issuer = readEnv("POCKETID_ISSUER").replace(/\/$/, "");
  const clientId = readEnv("POCKETID_CLIENT_ID");
  const clientSecret = readEnv("POCKETID_CLIENT_SECRET");
  if (!issuer || !clientId || !clientSecret) return undefined;

  // The client secret and the id_token both cross this connection, so a public
  // issuer over cleartext would hand them to the network. Private hosts are
  // exempt, the same carve-out isPrivateHost() already makes for
  // PROXMOX_INSECURE_TLS.
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    throw new Error(`POCKETID_ISSUER is not a valid URL: ${issuer}`);
  }
  if (issuerUrl.protocol !== "https:" && !isPrivateHost(issuerUrl.hostname)) {
    throw new Error(
      `POCKETID_ISSUER must use https for the public host ${issuerUrl.hostname}; the client secret and id_token travel over it.`,
    );
  }

  const scopes = readEnv("POCKETID_SCOPES", "openid profile email")
    .split(/\s+/)
    .filter(Boolean);

  return { issuer, clientId, clientSecret, scopes: scopes.length ? scopes : ["openid"] };
}

export function loadConfig(): AppConfig {
  const services = SERVICE_REGISTRY.map((entry) => serviceFromRegistryEntry(entry, readEnv)).filter(
    (service): service is ServiceDefinition => service !== undefined,
  );

  const proxmoxSsh = loadProxmoxSshConfig();

  // Registration is public and accepts any HTTPS destination, so running
  // without an allowlist means a stranger's client can ask the one person who
  // can sign in for a code. Say so once at startup instead of only on the
  // consent page, which is seen too late to change the configuration.
  if (allowedRedirectHosts().length === 0) {
    log("error", "oauth_redirect_allowlist_not_configured", {
      hint: "Set MCP_ALLOWED_REDIRECT_HOSTS (e.g. claude.ai) so authorization codes can only be delivered to clients you expect.",
    });
  }

  const allowedSubjects = readEnv("MCP_ALLOWED_SUBJECTS")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (allowedSubjects.length > 0) {
    log("info", "oauth_subject_allowlist_configured", { count: allowedSubjects.length });
  }

  // Opt-in on purpose: deriving the allowed host from MCP_PUBLIC_URL would make
  // /mcp start rejecting requests whenever a reverse proxy forwards a different
  // Host header, which trades a working server for a layer the bearer token
  // already covers. Same reasoning as MCP_ALLOWED_REDIRECT_HOSTS.
  const allowedHosts = readEnv("MCP_ALLOWED_HOSTS")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

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
    pocketId: loadPocketIdConfig(),
    proxmoxSsh,
    grantSummary: describeGrants(services, proxmoxSsh),
    allowedHosts,
  };
}
