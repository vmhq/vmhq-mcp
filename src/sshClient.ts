import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { StringDecoder } from "node:string_decoder";
import { Client } from "ssh2";
import { log } from "./logger.js";
import { knownHostKey, rememberHostKey } from "./sshKnownHosts.js";

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
  /** Directory where background jobs write their log, pid and status files. */
  jobDir: string;
  /** Days a finished job's files are kept before a later launch prunes them. 0 disables pruning. */
  jobRetentionDays: number;
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
  /** Who is running this, for the audit trail. See RequestContext in mcp.ts. */
  actor?: string;
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

/**
 * Shells accepted for `pct exec` and for the background-job launcher. The shell
 * is the one token in those commands that cannot be quoted away as a single
 * argument list entry without changing its meaning for the operator, so it is
 * restricted to a plain absolute path: no spaces, no shell metacharacters, no
 * relative lookups. Without this a caller-supplied `shell` would be spliced
 * into the node-level command and escape the container entirely, taking
 * PROXMOX_SSH_ALLOWED_VMIDS with it.
 */
const SHELL_PATTERN = /^\/[A-Za-z0-9_.\-\/]{1,127}$/u;

export function isAllowedShell(value: string): boolean {
  return SHELL_PATTERN.test(value);
}

/** Validates a caller-supplied shell, mirroring assertVmidAllowed(). */
export function assertShellAllowed(shell: string | undefined): string | undefined {
  if (shell === undefined) return undefined;
  if (!isAllowedShell(shell)) {
    return "shell must be an absolute path to an interpreter, for example /bin/bash.";
  }
  return undefined;
}

/**
 * Resolves the shell to use and refuses anything the tool layer should already
 * have rejected. Throwing here keeps the command builders safe on their own,
 * so a future call site cannot reintroduce the injection by forgetting the
 * assertShellAllowed() check.
 */
function resolveShell(fallback: string, shell?: string): string {
  const candidate = shell || fallback;
  if (!isAllowedShell(candidate)) {
    throw new Error(`Refusing to build a command with an unsafe shell: ${candidate}`);
  }
  return candidate;
}

/**
 * Patterns whose value is replaced before a command reaches the logs. Commands
 * are logged so the audit trail says what was run, but a maintenance one-liner
 * routinely carries a secret on its argv (`mysql -pSECRET`, `curl -H "Authorization: …"`).
 *
 * This is a reduction in exposure, not a guarantee: a secret in a shape not
 * listed here still gets through. Prefer passing secrets on stdin, which is
 * never logged.
 */
const SECRET_PATTERNS: Array<[RegExp, string]> = [
  // A value is a quoted string or a run of non-space, non-quote characters.
  // Excluding quotes matters: a matcher that swallowed the closing quote left
  // the rest of the command open to the next pattern, which then ate it.
  [/((?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key)\s*[=:]\s*)(?!\*\*\*)(?:"[^"]*"|'[^']*'|[^\s'"]+)/giu, "$1***"],
  [/(-p)(?!\s)(?!\*\*\*)(?:"[^"]*"|'[^']*'|[^\s'"]+)/gu, "$1***"],
  // A header value runs to the closing quote, not to the next space: matching
  // one token here left "Authorization: Bearer <token>" with the token in the
  // log line. The lookahead keeps it off a value an earlier pattern redacted.
  [/((?:authorization|x-auth-token|x-api-key)\s*:\s*)(?!\*\*\*)[^'"\n;&|]+/giu, "$1***"],
  [/(\bBearer\s+)(?!\*\*\*)[^\s'"]+/giu, "$1***"],
];

/** How much of a command survives into a log line. */
const MAX_LOGGED_COMMAND_CHARS = 200;

/**
 * Renders a command for logging: known secret shapes redacted, then truncated.
 * The audit trail added alongside `actor` is the reason the command is still
 * logged at all, so this trims what is written rather than dropping it.
 */
export function redactCommand(command: string, maxChars = MAX_LOGGED_COMMAND_CHARS): string {
  let redacted = command;
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }

  if (redacted.length <= maxChars) {
    return redacted;
  }

  return `${redacted.slice(0, maxChars)}… [${redacted.length - maxChars} more characters]`;
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
    actor: options.actor,
    host: config.host,
    target,
    command: redactCommand(command),
  });

  const result = await new Promise<SshExecResult>((resolve) => {
    const conn = new Client();
    const stdout = capturedStream(maxOutputChars);
    const stderr = capturedStream(maxOutputChars);
    let exitCode: number | null = null;
    let exitSignal: string | undefined;
    let actualFingerprint = "";
    /** Set when a previously pinned key did not match, for the error message. */
    let expectedFingerprint = "";
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

      if (expectedFingerprint && actualFingerprint !== expectedFingerprint) {
        settle(
          sshError(
            "ssh_host_key_mismatch",
            `Host key for ${config.host} is ${actualFingerprint}, but ${expectedFingerprint} was pinned on the first connection. ` +
              "Refusing to connect. If the node's key changed for a reason you know about, remove its entry from " +
              "PROXMOX_SSH_KNOWN_HOSTS_PATH (default ./data/proxmox-known-hosts.json) so it can be pinned again.",
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

        // An explicitly configured fingerprint is the strongest statement the
        // operator can make, so it decides on its own.
        if (config.hostFingerprint) {
          return actualFingerprint === normalizeFingerprint(config.hostFingerprint);
        }

        // Otherwise trust on first use: pin whatever answered the first time
        // and require it from then on, rather than accepting any key forever.
        const pinned = knownHostKey(config.host, config.port);
        if (!pinned) {
          rememberHostKey(config.host, config.port, actualFingerprint);
          return true;
        }

        expectedFingerprint = pinned;
        return actualFingerprint === pinned;
      },
    });
  });

  if (isSshFailure(result)) {
    log("error", "ssh_exec_failed", {
      service: "proxmox_ssh",
      requestId: options.requestId,
      actor: options.actor,
      host: config.host,
      target,
      command: redactCommand(command),
      durationMs: Math.round(performance.now() - startedAt),
      error: result.error.type,
    });
    return result;
  }

  log(result.ok ? "info" : "error", "ssh_exec_finished", {
    service: "proxmox_ssh",
    requestId: options.requestId,
    actor: options.actor,
    host: config.host,
    target,
    command: redactCommand(command),
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
  const containerShell = shellQuote(resolveShell(config.containerShell, shell));
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

/**
 * Background jobs. The real ceiling on a long command is not this server's
 * timeout but the MCP client's: raising `timeoutMs` only moves the disconnect.
 * So the command is detached from the SSH session instead, writes its output to
 * a log file on the target and records its exit code when it ends, and a later
 * call reads the result without anyone holding a connection open.
 */
const JOB_LOG_MARKER = "---vmhq-job-log---";

export const JOB_ID_PATTERN = /^[0-9a-f]{12}$/u;

export function newJobId(): string {
  return randomBytes(6).toString("hex");
}

export type JobPaths = { dir: string; logPath: string; statusPath: string; pidPath: string };

function normalizeJobDir(config: ProxmoxSshConfig): string {
  return config.jobDir.replace(/\/+$/u, "");
}

export function jobPaths(config: ProxmoxSshConfig, jobId: string): JobPaths {
  const dir = normalizeJobDir(config);
  return {
    dir,
    logPath: `${dir}/${jobId}.log`,
    statusPath: `${dir}/${jobId}.status`,
    pidPath: `${dir}/${jobId}.pid`,
  };
}

/**
 * Prunes job files older than the retention window. It runs from the launcher
 * rather than on a timer because this server keeps no state between requests,
 * and it only ever matches the three file names a job creates, so pointing
 * PROXMOX_SSH_JOB_DIR at a shared directory cannot turn it into an rm -rf.
 */
export function jobPurgeCommand(config: ProxmoxSshConfig): string | undefined {
  const days = Math.trunc(config.jobRetentionDays);
  if (!Number.isFinite(days) || days <= 0) return undefined;

  const names = String.raw`\( -name '*.log' -o -name '*.pid' -o -name '*.status' \)`;
  return `find ${shellQuote(normalizeJobDir(config))} -maxdepth 1 -type f ${names} -mtime +${days} -exec rm -f {} ';' 2> /dev/null || true`;
}

/**
 * Builds the script that launches `command` detached. The wrapper records its
 * own pid before starting, so a later status check can tell "still running"
 * from "died without writing an exit code" (node rebooted, OOM killer, ...).
 */
export function backgroundScript(config: ProxmoxSshConfig, command: string, jobId: string, shell?: string): string {
  const paths = jobPaths(config, jobId);
  const runner = shellQuote(resolveShell("/bin/sh", shell));
  // The command runs in a subshell so that an `exit` inside it ends the job
  // rather than the wrapper, which still has to record the exit code.
  const wrapper = [
    `echo $$ > ${shellQuote(paths.pidPath)}`,
    "(",
    command,
    `) > ${shellQuote(paths.logPath)} 2>&1`,
    `echo $? > ${shellQuote(paths.statusPath)}`,
  ].join("\n");
  const quotedWrapper = shellQuote(wrapper);
  // setsid detaches the job from the SSH session's process group entirely;
  // nohup is the fallback for minimal containers that ship without it.
  const detach = `${runner} -c ${quotedWrapper} < /dev/null > /dev/null 2>&1 &`;

  const purge = jobPurgeCommand(config);

  return [
    `mkdir -p ${shellQuote(paths.dir)} || exit 1`,
    ...(purge ? [purge] : []),
    // Creating the log here makes the job observable before the wrapper has
    // had a chance to record its pid, so an immediate status check reads
    // "starting" instead of "no such job".
    `: > ${shellQuote(paths.logPath)} || exit 1`,
    "if command -v setsid > /dev/null 2>&1; then",
    `setsid ${detach}`,
    "else",
    `nohup ${detach}`,
    "fi",
    `echo ${shellQuote(jobId)}`,
  ].join("\n");
}

/** Builds the script that reports a job's state and the tail of its log. */
export function jobStatusScript(config: ProxmoxSshConfig, jobId: string, tailLines = 200): string {
  const paths = jobPaths(config, jobId);
  const status = shellQuote(paths.statusPath);
  const pid = shellQuote(paths.pidPath);
  const logPath = shellQuote(paths.logPath);
  const lines = Math.max(1, Math.trunc(tailLines));

  return [
    `if [ -e ${status} ]; then echo "state=finished"; echo "exitCode=$(cat ${status})";`,
    `elif [ -e ${pid} ] && kill -0 "$(cat ${pid})" 2> /dev/null; then echo "state=running"; echo "pid=$(cat ${pid})";`,
    `elif [ -e ${pid} ]; then echo "state=orphaned";`,
    `elif [ -e ${logPath} ]; then echo "state=starting";`,
    `else echo "state=not_found"; fi`,
    `echo "logBytes=$(wc -c < ${logPath} 2> /dev/null || echo 0)"`,
    `echo ${shellQuote(JOB_LOG_MARKER)}`,
    `tail -n ${lines} ${logPath} 2> /dev/null || true`,
  ].join("\n");
}

export type JobState = "starting" | "running" | "finished" | "orphaned" | "not_found";

export type JobStatus = {
  jobId: string;
  state: JobState;
  exitCode?: number;
  pid?: number;
  logBytes?: number;
  log: string;
};

const JOB_STATES: JobState[] = ["starting", "running", "finished", "orphaned", "not_found"];

export function parseJobStatus(jobId: string, output: string): JobStatus {
  const markerAt = output.indexOf(`${JOB_LOG_MARKER}\n`);
  const header = markerAt === -1 ? output : output.slice(0, markerAt);
  const log = markerAt === -1 ? "" : output.slice(markerAt + JOB_LOG_MARKER.length + 1);

  const fields = new Map<string, string>();
  for (const line of header.split("\n")) {
    const separator = line.indexOf("=");
    if (separator > 0) fields.set(line.slice(0, separator).trim(), line.slice(separator + 1).trim());
  }

  const state = fields.get("state") ?? "";
  const exitCode = Number(fields.get("exitCode"));
  const pid = Number(fields.get("pid"));
  const logBytes = Number(fields.get("logBytes"));

  return {
    jobId,
    state: (JOB_STATES as string[]).includes(state) ? (state as JobState) : "not_found",
    ...(Number.isInteger(exitCode) && fields.has("exitCode") ? { exitCode } : {}),
    ...(Number.isInteger(pid) && fields.has("pid") ? { pid } : {}),
    ...(Number.isInteger(logBytes) ? { logBytes } : {}),
    log,
  };
}
