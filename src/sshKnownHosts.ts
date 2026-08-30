/**
 * Trust-on-first-use pinning for the Proxmox node's SSH host key.
 *
 * `PROXMOX_SSH_HOST_FINGERPRINT` is only required when the node is public, so a
 * node on a private network was reached with no host verification at all: the
 * connection that carries a root shell would accept whatever key answered.
 * Requiring the fingerprint everywhere would mean the server refuses to start
 * until an operator runs ssh-keyscan, so instead the first connection records
 * the key it saw and every later one has to match it — the same bargain ssh
 * itself makes with known_hosts.
 *
 * An explicitly configured fingerprint always wins over what is recorded here.
 */
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { log } from "./logger.js";

type KnownHostEntry = { fingerprint: string; firstSeenAt: string };

function storePath(): string {
  return process.env.PROXMOX_SSH_KNOWN_HOSTS_PATH ?? "./data/proxmox-known-hosts.json";
}

export function hostKeyFor(host: string, port: number): string {
  return `${host}:${port}`;
}

function readStore(): Record<string, KnownHostEntry> {
  try {
    const parsed = JSON.parse(readFileSync(storePath(), "utf-8")) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, KnownHostEntry>;
    }
  } catch {
    // No store yet, or an unreadable one: treat the host as unseen.
  }
  return {};
}

/** The fingerprint recorded for this host, if it has been seen before. */
export function knownHostKey(host: string, port: number): string | undefined {
  return readStore()[hostKeyFor(host, port)]?.fingerprint;
}

/**
 * Records the fingerprint seen on a first connection. Written atomically at
 * 0600, mirroring how the OAuth state file is persisted.
 *
 * A store that cannot be written is logged and otherwise ignored: a read-only
 * volume should not take the node offline, it should only mean the key is not
 * pinned yet.
 */
export function rememberHostKey(host: string, port: number, fingerprint: string): void {
  const path = storePath();
  try {
    const store = readStore();
    store[hostKeyFor(host, port)] = { fingerprint, firstSeenAt: new Date().toISOString() };

    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.tmp`;
    writeFileSync(tmp, JSON.stringify(store, null, 2), { encoding: "utf-8", mode: 0o600 });
    chmodSync(tmp, 0o600); // covers a loose tmp file left by an earlier run
    renameSync(tmp, path);

    log("info", "ssh_host_key_pinned", { host, port, fingerprint, path });
  } catch (error) {
    log("error", "ssh_host_key_pin_failed", {
      host,
      port,
      path,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

/** Drops a recorded fingerprint, for when a host key legitimately changed. */
export function forgetHostKey(host: string, port: number): void {
  const path = storePath();
  try {
    const store = readStore();
    delete store[hostKeyFor(host, port)];
    const tmp = `${path}.tmp`;
    writeFileSync(tmp, JSON.stringify(store, null, 2), { encoding: "utf-8", mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, path);
  } catch (error) {
    log("error", "ssh_host_key_forget_failed", {
      host,
      port,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}
