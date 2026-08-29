import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { StringDecoder } from "node:string_decoder";
import { Client } from "ssh2";
import { log } from "./logger.js";

/**
 * SSH access to the Proxmox node. Unlike every other upstream in this server,
 * this is not an HTTP API: the Proxmox REST API has no exec endpoint for LXC
 * containers (only QEMU guests expose one, through the guest agent), so running
 * commands inside a container means SSHing into the node and calling `pct exec`.
 *
 * The tools built on top of this module hand the caller a real shell on the
 * hypervisor. Scope the SSH credential itself (dedicated user, restricted
 * sudoers, forced command) if you want narrower access than "root on the node".
 */
export type ProxmoxSshConfig = {
  host: string;
  port: number;
  user: string;
  /** Pinned host key fingerprint, OpenSSH style: `SHA256:<base64>`. */
  hostFingerprint?: string;
  timeoutMs: number;
  maxOutputChars: number;
  /** When set, only these container IDs may be targeted. Undefined means all. */
  allowedVmids?: number[];
  /** Wrap commands in `sudo -n` for non-root maintenance users. */
  sudo: boolean;
  /** Shell used to interpret commands inside containers. */
  containerShell: string;
};

export type SshErrorType =
  | "missing_upstream_credentials"
  | "invalid_request"
  | "ssh_timeout"
  | "ssh_auth_failed"
  | "ssh_host_key_mismatch"
  | "ssh_connection_error";

export type SshExecOptions = {
  /** Written to the remote command's stdin, which is then closed. */
  stdin?: string;
  timeoutMs?: number;
  maxOutputChars?: number;
  /** Label used in logs and in the response, e.g. "node" or "lxc:101". */
  target?: string;
  requestId?: string;
};

export type SshExecSuccess = {
  ok: boolean;
  host: string;
  user: string;
  target: string;
  command: string;
  exitCode: number | null;
  signal?: string;
  stdout: string;
  stderr: string;
  truncated?: { stdoutDropped: number; stderrDropped: number };
  durationMs: number;
};

export type SshExecFailure = {
  error: {
    type: SshErrorType;
    service: "proxmox_ssh";
    message: string;
    retryable: boolean;
  };
};

export type SshExecResult = SshExecSuccess | SshExecFailure;

export function isSshFailure(result: SshExecResult): result is SshExecFailure {
  return "error" in result;
}

function sshError(type: SshErrorType, message: string, retryable = false): SshExecFailure {
  return { error: { type, service: "proxmox_ssh", message, retryable } };
}

/**
 * Single-quotes a value for POSIX shells, so a command assembled here can never
 * be broken out of by its arguments. `'` is closed, escaped and reopened.
 */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

/** OpenSSH-style fingerprint of a raw public host key blob. */
export function hostKeyFingerprint(key: Buffer): string {
  return `SHA256:${createHash("sha256").update(key).digest("base64").replace(/=+$/u, "")}`;
}

function normalizeFingerprint(value: string): string {
  const trimmed = value.trim();
  return trimmed.startsWith("SHA256:") ? trimmed : `SHA256:${trimmed}`;
}

type SshCredentials = { privateKey?: string; passphrase?: string; password?: string };

/**
 * Credentials are read at call time (like service tokens elsewhere) so a
 * missing key surfaces as a normalized tool error instead of a startup crash.
 */
function resolveCredentials(): SshCredentials | { missing: string } {
  const inlineKey = process.env.PROXMOX_SSH_KEY ?? "";
  const keyPath = process.env.PROXMOX_SSH_KEY_PATH ?? "";
  const password = process.env.PROXMOX_SSH_PASSWORD ?? "";
  const passphrase = process.env.PROXMOX_SSH_KEY_PASSPHRASE || undefined;

  if (inlineKey) {
    // Tolerate keys pasted into .env as a single line with escaped newlines.
    return { privateKey: inlineKey.includes("\\n") ? inlineKey.replaceAll("\\n", "\n") : inlineKey, passphrase };
  }

  if (keyPath) {
    try {
      return { privateKey: readFileSync(keyPath, "utf8"), passphrase };
    } catch (error) {
      return { missing: `PROXMOX_SSH_KEY_PATH could not be read: ${error instanceof Error ? error.message : String(error)}` };
    }
  }

  if (password) {
    return { password };
  }

  return { missing: "Set PROXMOX_SSH_KEY, PROXMOX_SSH_KEY_PATH or PROXMOX_SSH_PASSWORD to authenticate against the Proxmox node." };
}

/** Accumulates stream output up to a character budget, counting what it drops. */
function capturedStream(maxChars: number) {
  const decoder = new StringDecoder("utf8");
  let text = "";
  let dropped = 0;

  return {
    push(chunk: Buffer): void {
      const decoded = decoder.write(chunk);
      if (!decoded) return;

      const room = maxChars - text.length;
      if (room <= 0) {
        dropped += decoded.length;
        return;
      }

      if (decoded.length <= room) {
        text += decoded;
        return;
      }

      text += decoded.slice(0, room);
      dropped += decoded.length - room;
    },
    finish(): { text: string; dropped: number } {
      const rest = decoder.end();
      if (rest) {
        const room = maxChars - text.length;
        if (room > 0) text += rest.slice(0, room);
        if (rest.length > Math.max(room, 0)) dropped += rest.length - Math.max(room, 0);
      }
      return { text, dropped };
    },
  };
}

function classifyConnectionError(error: Error & { level?: string }): SshExecFailure {
  const level = error.level ?? "";

  if (level === "client-authentication") {
    return sshError("ssh_auth_failed", `SSH authentication failed: ${error.message}`);
  }

  if (level === "client-timeout") {
    return sshError("ssh_timeout", `SSH handshake timed out: ${error.message}`, true);
  }

  return sshError("ssh_connection_error", `SSH connection failed: ${error.message}`, true);
}

/** Runs a single command over a fresh SSH connection and returns its output. */
export async function runSshCommand(
  config: ProxmoxSshConfig,
  command: string,
  options: SshExecOptions = {},
): Promise<SshExecResult> {
  if (!command.trim()) {
    return sshError("invalid_request", "command must not be empty.");
  }

  const credentials = resolveCredentials();
  if ("missing" in credentials) {
    return sshError("missing_upstream_credentials", credentials.missing);
  }

  const timeoutMs = options.timeoutMs ?? config.timeoutMs;
  const maxOutputChars = options.maxOutputChars ?? config.maxOutputChars;
  const target = options.target ?? "node";
  const startedAt = performance.now();

  log("info", "ssh_exec_started", {
    service: "proxmox_ssh",
    requestId: options.requestId,
    host: config.host,
    target,
    command,
  });

  const result = await new Promise<SshExecResult>((resolve) => {
    const conn = new Client();
    const stdout = capturedStream(maxOutputChars);
    const stderr = capturedStream(maxOutputChars);
    let exitCode: number | null = null;
    let exitSignal: string | undefined;
    let actualFingerprint = "";
    let settled = false;

    const timer = setTimeout(() => {
      settle(sshError("ssh_timeout", `SSH command exceeded ${timeoutMs}ms and was aborted.`, true));
    }, timeoutMs);

    function settle(value: SshExecResult): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      conn.destroy();
      resolve(value);
    }

    conn.on("error", (error: Error & { level?: string }) => {
      if (config.hostFingerprint && actualFingerprint && actualFingerprint !== normalizeFingerprint(config.hostFingerprint)) {
        settle(
          sshError(
            "ssh_host_key_mismatch",
            `Host key for ${config.host} is ${actualFingerprint}, expected ${normalizeFingerprint(config.hostFingerprint)}. ` +
              "Refusing to connect; update PROXMOX_SSH_HOST_FINGERPRINT only if you know why the key changed.",
          ),
        );
        return;
      }

      settle(classifyConnectionError(error));
    });

    conn.on("ready", () => {
      conn.exec(command, { pty: false }, (error, stream) => {
        if (error) {
          settle(sshError("ssh_connection_error", `Failed to open SSH exec channel: ${error.message}`, true));
          return;
        }

        stream.on("data", (chunk: Buffer) => stdout.push(chunk));
        stream.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
        stream.on("exit", (code: number | null, signal?: string) => {
          exitCode = code;
          exitSignal = signal ?? undefined;
        });
        stream.on("close", (code?: number | null, signal?: string) => {
          if (code !== undefined && code !== null) exitCode = code;
          if (signal) exitSignal = signal;

          const out = stdout.finish();
          const err = stderr.finish();

          settle({
            ok: exitCode === 0,
            host: config.host,
            user: config.user,
            target,
            command,
            exitCode,
            ...(exitSignal ? { signal: exitSignal } : {}),
            stdout: out.text,
            stderr: err.text,
            ...(out.dropped || err.dropped
              ? { truncated: { stdoutDropped: out.dropped, stderrDropped: err.dropped } }
              : {}),
            durationMs: Math.round(performance.now() - startedAt),
          });
        });

        // Always close stdin so commands that read from it cannot hang.
        stream.end(options.stdin ?? "");
      });
    });

    conn.connect({
      host: config.host,
      port: config.port,
      username: config.user,
      ...credentials,
      readyTimeout: Math.min(timeoutMs, 20_000),
      keepaliveInterval: 10_000,
      hostVerifier: (key: Buffer) => {
        actualFingerprint = hostKeyFingerprint(key);
        if (!config.hostFingerprint) return true;
        return actualFingerprint === normalizeFingerprint(config.hostFingerprint);
      },
    });
  });

  if (isSshFailure(result)) {
    log("error", "ssh_exec_failed", {
      service: "proxmox_ssh",
      requestId: options.requestId,
      host: config.host,
      target,
      command,
      durationMs: Math.round(performance.now() - startedAt),
      error: result.error.type,
    });
    return result;
  }

  log(result.ok ? "info" : "error", "ssh_exec_finished", {
    service: "proxmox_ssh",
    requestId: options.requestId,
    host: config.host,
    target,
    command,
    exitCode: result.exitCode,
    durationMs: result.durationMs,
  });

  return result;
}

/** Wraps a command so it runs through `sudo -n` when a non-root user is configured. */
export function nodeCommand(config: ProxmoxSshConfig, command: string): string {
  return config.sudo ? `sudo -n /bin/sh -c ${shellQuote(command)}` : command;
}

export function assertVmidAllowed(config: ProxmoxSshConfig, vmid: number): string | undefined {
  if (!Number.isInteger(vmid) || vmid <= 0) {
    return "vmid must be a positive integer.";
  }

  if (config.allowedVmids && !config.allowedVmids.includes(vmid)) {
    return `Container ${vmid} is not in PROXMOX_SSH_ALLOWED_VMIDS (${config.allowedVmids.join(", ")}).`;
  }

  return undefined;
}

/** Builds the `pct exec` invocation that runs a shell command inside a container. */
export function lxcCommand(config: ProxmoxSshConfig, vmid: number, command: string, shell?: string): string {
  const containerShell = shell || config.containerShell;
  return nodeCommand(config, `pct exec ${vmid} -- ${containerShell} -c ${shellQuote(command)}`);
}

export type LxcListEntry = { vmid: number; status: string; lock?: string; name?: string };

/**
 * Parses `pct list` output. Columns are padded to the header widths, so the
 * header offsets are used to keep an empty Lock column from shifting Name.
 */
export function parsePctList(output: string): LxcListEntry[] {
  const lines = output.split("\n").filter((line) => line.trim());
  const header = lines.shift();
  if (!header || !/^\s*VMID/u.test(header)) {
    return [];
  }

  const columns = ["VMID", "Status", "Lock", "Name"].map((name) => ({ name, start: header.indexOf(name) }));
  const present = columns.filter((column) => column.start >= 0);

  return lines.flatMap((line) => {
    const values: Record<string, string> = {};

    present.forEach((column, index) => {
      const end = index + 1 < present.length ? present[index + 1]!.start : line.length;
      values[column.name] = line.slice(column.start, end).trim();
    });

    const vmid = Number(values.VMID);
    if (!Number.isInteger(vmid)) return [];

    return [
      {
        vmid,
        status: values.Status ?? "",
        ...(values.Lock ? { lock: values.Lock } : {}),
        ...(values.Name ? { name: values.Name } : {}),
      },
    ];
  });
}
