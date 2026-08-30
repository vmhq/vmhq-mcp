import { afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { Server, utils, type Connection } from "ssh2";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import {
  assertShellAllowed,
  assertVmidAllowed,
  backgroundScript,
  jobPaths,
  jobPurgeCommand,
  jobStatusScript,
  JOB_ID_PATTERN,
  newJobId,
  parseJobStatus,
  hostKeyFingerprint,
  isSshFailure,
  lxcCommand,
  nodeCommand,
  isAllowedShell,
  parsePctList,
  redactCommand,
  runSshCommand,
  shellQuote,
  type ProxmoxSshConfig,
} from "../src/sshClient.js";

process.env.MCP_LOG_LEVEL = "silent";
// Keep host-key pinning out of the project's own data/ directory: without this
// every run of the suite leaves a proxmox-known-hosts.json behind in the repo.
process.env.PROXMOX_SSH_KNOWN_HOSTS_PATH = `${tmpdir()}/vmhq-test-known-hosts-${process.pid}.json`;

const hostKeyPem = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "pkcs1", format: "pem" },
}).privateKey;

const parsedHostKey = utils.parseKey(hostKeyPem);
if (parsedHostKey instanceof Error) throw parsedHostKey;
const expectedFingerprint = hostKeyFingerprint(parsedHostKey.getPublicSSH() as Buffer);

type ExecHandler = (context: { command: string; stdin: string; write: (text: string) => void; writeErr: (text: string) => void; exit: (code: number) => void }) => void;

type TestServer = { port: number; close: () => void };

/** Boots an in-process SSH server so exec behaviour is exercised end to end. */
async function startServer(options: { onExec?: ExecHandler; rejectAuth?: boolean; port?: number; onSignal?: (name: string) => void } = {}): Promise<TestServer> {
  const server = new Server({ hostKeys: [hostKeyPem] }, (client: Connection) => {
    // The host-key tests make the client disconnect mid-handshake, which the
    // server reports as KEY_EXCHANGE_FAILED. Without a listener ssh2 rethrows
    // it as an uncaught exception that lands on whichever test is running by
    // then, so swallow the errors this harness provokes on purpose.
    client.on("error", () => {});
    client.on("authentication", (ctx) => (options.rejectAuth ? ctx.reject(["password"], false) : ctx.accept()));
    client.on("ready", () => {
      client.on("session", (accept) => {
        const session = accept();
        session.on("signal", (acceptSignal, _rejectSignal, info) => {
          options.onSignal?.(info.name);
          acceptSignal?.();
        });
        session.on("exec", (acceptExec, _reject, info) => {
          const stream = acceptExec();
          let stdin = "";
          stream.on("data", (chunk: Buffer) => (stdin += chunk.toString()));
          stream.on("end", () => {
            options.onExec?.({
              command: info.command,
              stdin,
              write: (text) => stream.write(text),
              writeErr: (text) => stream.stderr.write(text),
              exit: (code) => {
                stream.exit(code);
                stream.end();
              },
            });
          });
        });
      });
    });
  });

  server.on("error", () => {});

  // A fixed port lets a test restart "the same host" and check that a pinned
  // key is still accepted.
  await new Promise<void>((resolve) => server.listen(options.port ?? 0, "127.0.0.1", () => resolve()));
  const port = (server.address() as { port: number }).port;

  return { port, close: () => server.close() };
}

function configFor(port: number, overrides: Partial<ProxmoxSshConfig> = {}): ProxmoxSshConfig {
  return {
    host: "127.0.0.1",
    port,
    user: "root",
    timeoutMs: 5_000,
    maxOutputChars: 30_000,
    sudo: false,
    containerShell: "/bin/sh",
    jobDir: "/var/log/vmhq-mcp",
    jobRetentionDays: 30,
    ...overrides,
  };
}

beforeAll(() => {
  process.env.PROXMOX_SSH_PASSWORD = "test-password";
});

afterEach(() => {
  process.env.PROXMOX_SSH_PASSWORD = "test-password";
  delete process.env.PROXMOX_SSH_KEY;
  delete process.env.PROXMOX_SSH_KEY_PATH;
});

describe("runSshCommand", () => {
  test("returns stdout, stderr and the exit code of the remote command", async () => {
    const server = await startServer({
      onExec: ({ command, write, writeErr, exit }) => {
        write(`ran: ${command}`);
        writeErr("warning");
        exit(0);
      },
    });

    const result = await runSshCommand(configFor(server.port), "pveversion");
    server.close();

    if (isSshFailure(result)) throw new Error(`unexpected failure: ${result.error.message}`);
    expect(result.ok).toBe(true);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("ran: pveversion");
    expect(result.stderr).toBe("warning");
    expect(result.target).toBe("node");
  });

  test("reports a non-zero exit without treating it as a transport failure", async () => {
    const server = await startServer({
      onExec: ({ writeErr, exit }) => {
        writeErr("Unit nginx.service not found.");
        exit(4);
      },
    });

    const result = await runSshCommand(configFor(server.port), "systemctl status nginx");
    server.close();

    if (isSshFailure(result)) throw new Error("expected a normal result for a non-zero exit");
    expect(result.ok).toBe(false);
    expect(result.exitCode).toBe(4);
    expect(result.stderr).toContain("nginx.service");
  });

  test("forwards stdin and closes it so commands that read stdin cannot hang", async () => {
    const server = await startServer({
      onExec: ({ stdin, write, exit }) => {
        write(stdin.toUpperCase());
        exit(0);
      },
    });

    const result = await runSshCommand(configFor(server.port), "tee /etc/motd", { stdin: "hello node" });
    server.close();

    if (isSshFailure(result)) throw new Error(`unexpected failure: ${result.error.message}`);
    expect(result.stdout).toBe("HELLO NODE");
  });

  test("caps output at maxOutputChars and reports how much was dropped", async () => {
    const server = await startServer({
      onExec: ({ write, exit }) => {
        write("x".repeat(5_000));
        exit(0);
      },
    });

    const result = await runSshCommand(configFor(server.port), "journalctl -n 100000", { maxOutputChars: 100 });
    server.close();

    if (isSshFailure(result)) throw new Error(`unexpected failure: ${result.error.message}`);
    expect(result.stdout.length).toBe(100);
    expect(result.truncated?.stdoutDropped).toBe(4_900);
  });

  test("aborts a command that outlives the timeout", async () => {
    const server = await startServer({ onExec: () => {} });

    const result = await runSshCommand(configFor(server.port), "sleep 600", { timeoutMs: 300 });
    server.close();

    if (!isSshFailure(result)) throw new Error("expected a timeout failure");
    expect(result.error.type).toBe("ssh_timeout");
    expect(result.error.retryable).toBe(true);
  });

  test("connects when the pinned host fingerprint matches", async () => {
    const server = await startServer({ onExec: ({ write, exit }) => (write("ok"), exit(0)) });

    const result = await runSshCommand(configFor(server.port, { hostFingerprint: expectedFingerprint }), "true");
    server.close();

    if (isSshFailure(result)) throw new Error(`unexpected failure: ${result.error.message}`);
    expect(result.stdout).toBe("ok");
  });

  test("refuses to connect when the host fingerprint does not match", async () => {
    const server = await startServer({ onExec: ({ exit }) => exit(0) });

    const result = await runSshCommand(configFor(server.port, { hostFingerprint: "SHA256:not-the-real-key" }), "true");
    server.close();

    if (!isSshFailure(result)) throw new Error("expected a host key failure");
    expect(result.error.type).toBe("ssh_host_key_mismatch");
    expect(result.error.message).toContain(expectedFingerprint);
  });

  test("normalizes an authentication failure", async () => {
    const server = await startServer({ rejectAuth: true });

    const result = await runSshCommand(configFor(server.port), "true");
    server.close();

    if (!isSshFailure(result)) throw new Error("expected an auth failure");
    expect(result.error.type).toBe("ssh_auth_failed");
  });

  test("reports missing credentials instead of attempting a connection", async () => {
    delete process.env.PROXMOX_SSH_PASSWORD;

    const result = await runSshCommand(configFor(1), "true");

    if (!isSshFailure(result)) throw new Error("expected a credentials failure");
    expect(result.error.type).toBe("missing_upstream_credentials");
    expect(result.error.message).toContain("PROXMOX_SSH_KEY");
  });

  test("rejects an empty command", async () => {
    const result = await runSshCommand(configFor(1), "   ");

    if (!isSshFailure(result)) throw new Error("expected an invalid_request failure");
    expect(result.error.type).toBe("invalid_request");
  });
});

describe("command construction", () => {
  test("shellQuote neutralizes quotes and shell metacharacters", () => {
    expect(shellQuote("rm -rf /")).toBe("'rm -rf /'");
    expect(shellQuote("it's; rm -rf /")).toBe("'it'\\''s; rm -rf /'");
  });

  test("lxcCommand keeps an injected quote inside the pct exec argument", () => {
    const config = configFor(22);
    expect(lxcCommand(config, 101, "systemctl restart nginx")).toBe(
      "pct exec 101 -- '/bin/sh' -c 'systemctl restart nginx'",
    );
    expect(lxcCommand(config, 101, "'; reboot #")).toBe("pct exec 101 -- '/bin/sh' -c ''\\''; reboot #'");
  });

  test("lxcCommand honours a per-call shell override", () => {
    expect(lxcCommand(configFor(22), 101, "echo ${BASH_VERSION}", "/bin/bash")).toBe(
      "pct exec 101 -- '/bin/bash' -c 'echo ${BASH_VERSION}'",
    );
  });

  test("nodeCommand wraps the whole pipeline in sudo when enabled", () => {
    const config = configFor(22, { sudo: true });
    expect(nodeCommand(config, "pct list | grep running")).toBe("sudo -n /bin/sh -c 'pct list | grep running'");
    expect(lxcCommand(config, 101, "uptime")).toBe("sudo -n /bin/sh -c 'pct exec 101 -- '\\''/bin/sh'\\'' -c '\\''uptime'\\'''");
  });

  test("nodeCommand passes the command through untouched without sudo", () => {
    expect(nodeCommand(configFor(22), "pct list | grep running")).toBe("pct list | grep running");
  });
});

/**
 * The `shell` argument is the one part of `pct exec` that is not the quoted
 * command, so an unvalidated value used to be spliced straight into the
 * node-level command: it escaped the container and, with it, the
 * PROXMOX_SSH_ALLOWED_VMIDS allowlist.
 */
describe("shell validation", () => {
  const INJECTIONS = [
    "/bin/sh -c 'id > /tmp/pwned' #",
    "/bin/sh; touch /tmp/pwned;",
    "/bin/sh$(id)",
    "/bin/sh`id`",
    "/bin/sh | id",
    "/bin/sh\nid",
    "sh",
    "../../bin/sh",
    "/bin/sh ",
    "",
  ];

  test("accepts plain absolute interpreter paths", () => {
    for (const shell of ["/bin/sh", "/bin/bash", "/usr/bin/zsh", "/usr/local/bin/fish"]) {
      expect(isAllowedShell(shell)).toBe(true);
      expect(assertShellAllowed(shell)).toBeUndefined();
    }
  });

  test("rejects every shape that could break out of the pct exec argument", () => {
    for (const shell of INJECTIONS) {
      expect(isAllowedShell(shell)).toBe(false);
      expect(assertShellAllowed(shell)).toContain("absolute path");
    }
  });

  test("treats an omitted shell as the configured default", () => {
    expect(assertShellAllowed(undefined)).toBeUndefined();
  });

  test("lxcCommand refuses to build a command with an injected shell", () => {
    const config = configFor(22, { allowedVmids: [101] });
    for (const shell of INJECTIONS.filter(Boolean)) {
      expect(() => lxcCommand(config, 101, "echo harmless", shell)).toThrow("unsafe shell");
    }
  });

  test("backgroundScript refuses to build a launcher with an injected runner", () => {
    expect(() => backgroundScript(configFor(22), "echo hi", "abc123abc123", "/bin/sh; touch /tmp/pwned;")).toThrow(
      "unsafe shell",
    );
  });

  test("a config with an unsafe containerShell cannot build commands either", () => {
    const config = configFor(22, { containerShell: "/bin/sh -c 'id' #" });
    expect(() => lxcCommand(config, 101, "echo hi")).toThrow("unsafe shell");
  });

  /**
   * End-to-end proof under a real shell: `pct` is stubbed so the built command
   * actually runs. A valid override must reach it as one argv entry, and the
   * payload from the old injection must never execute.
   */
  test("passes the shell to pct as a single argument under a real shell", async () => {
    const dir = mkdtempSync(`${tmpdir()}/vmhq-shell-`);
    try {
      writeFileSync(`${dir}/pct`, '#!/bin/sh\nprintf "%s\\n" "$@"\n', { mode: 0o755 });
      const marker = `${dir}/pwned`;

      async function sh(script: string): Promise<string> {
        const proc = Bun.spawn(["/bin/sh", "-c", script], {
          stdout: "pipe",
          stderr: "ignore",
          env: { ...process.env, PATH: `${dir}:${process.env.PATH ?? ""}` },
        });
        const output = await new Response(proc.stdout).text();
        await proc.exited;
        return output;
      }

      const argv = (await sh(lxcCommand(configFor(22), 101, "echo hi", "/bin/bash"))).split("\n");
      expect(argv).toContain("/bin/bash");
      expect(argv).toContain("echo hi");

      // The historical payload is now rejected before a command is ever built,
      // so nothing reaches the node.
      expect(() => lxcCommand(configFor(22), 101, "echo hi", `/bin/sh -c 'touch ${marker}' #`)).toThrow();
      expect(readdirSync(dir)).not.toContain("pwned");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("assertVmidAllowed", () => {
  test("accepts any container when no allowlist is configured", () => {
    expect(assertVmidAllowed(configFor(22), 101)).toBeUndefined();
  });

  test("rejects containers outside the allowlist", () => {
    const config = configFor(22, { allowedVmids: [101, 102] });
    expect(assertVmidAllowed(config, 101)).toBeUndefined();
    expect(assertVmidAllowed(config, 999)).toContain("not in PROXMOX_SSH_ALLOWED_VMIDS");
  });

  test("rejects non-integer and non-positive container IDs", () => {
    expect(assertVmidAllowed(configFor(22), 1.5)).toContain("positive integer");
    expect(assertVmidAllowed(configFor(22), -1)).toContain("positive integer");
  });
});

describe("parsePctList", () => {
  test("parses rows with and without a lock, keeping names aligned", () => {
    const output = [
      "VMID       Status     Lock         Name                ",
      "101        running                 nginx-proxy         ",
      "102        stopped    backup       postgres            ",
      "",
    ].join("\n");

    expect(parsePctList(output)).toEqual([
      { vmid: 101, status: "running", name: "nginx-proxy" },
      { vmid: 102, status: "stopped", lock: "backup", name: "postgres" },
    ]);
  });

  test("returns nothing for unexpected output", () => {
    expect(parsePctList("permission denied")).toEqual([]);
    expect(parsePctList("")).toEqual([]);
  });
});

describe("background jobs", () => {
  test("mints job IDs that survive the tool's own validation", () => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      expect(newJobId()).toMatch(JOB_ID_PATTERN);
    }
  });

  test("puts the log, pid and status files under the configured job directory", () => {
    const paths = jobPaths(configFor(22, { jobDir: "/srv/jobs/" }), "abc123abc123");

    expect(paths).toEqual({
      dir: "/srv/jobs",
      logPath: "/srv/jobs/abc123abc123.log",
      statusPath: "/srv/jobs/abc123abc123.status",
      pidPath: "/srv/jobs/abc123abc123.pid",
    });
  });

  test("detaches the command and keeps it out of the launcher's quoting", () => {
    const script = backgroundScript(configFor(22), "echo 'it works'", "abc123abc123");

    expect(script).toContain("mkdir -p '/var/log/vmhq-mcp'");
    expect(script).toContain("command -v setsid");
    expect(script).toContain("nohup");
    expect(script).toContain("< /dev/null > /dev/null 2>&1 &");
    // The command keeps its own quotes, escaped one level up by the launcher.
    expect(script).toContain(`echo '\\''it works'\\''`);
  });

  test("runs the command in a subshell so an exit still records the status", () => {
    const script = backgroundScript(configFor(22), "exit 3", "abc123abc123");

    expect(script).toContain("(\nexit 3\n)");
    expect(script).toContain("echo $? > '\\''/var/log/vmhq-mcp/abc123abc123.status'\\''");
  });

  test("uses the requested shell inside the container", () => {
    const script = backgroundScript(configFor(22), "echo hi", "abc123abc123", "/bin/bash");

    expect(script).toContain("setsid '/bin/bash' -c ");
    expect(script).toContain("nohup '/bin/bash' -c ");
  });

  test("parses a finished job and splits the log from the header", () => {
    const output = ["state=finished", "exitCode=7", "logBytes=      16", "---vmhq-job-log---", "start", "done", ""].join("\n");

    expect(parseJobStatus("abc123abc123", output)).toEqual({
      jobId: "abc123abc123",
      state: "finished",
      exitCode: 7,
      logBytes: 16,
      log: "start\ndone\n",
    });
  });

  test("parses a running job and an unrecognised one", () => {
    const running = parseJobStatus("abc123abc123", ["state=running", "pid=4242", "logBytes=3", "---vmhq-job-log---", "hi"].join("\n"));
    expect(running).toMatchObject({ state: "running", pid: 4242, log: "hi" });
    expect(running.exitCode).toBeUndefined();

    expect(parseJobStatus("abc123abc123", "sudo: a password is required")).toMatchObject({ state: "not_found", log: "" });
  });

  test("prunes only job files, and only past the retention window", () => {
    const purge = jobPurgeCommand(configFor(22, { jobDir: "/var/log/vmhq-mcp/" }));

    expect(purge).toContain("find '/var/log/vmhq-mcp' -maxdepth 1 -type f");
    expect(purge).toContain(String.raw`\( -name '*.log' -o -name '*.pid' -o -name '*.status' \)`);
    expect(purge).toContain("-mtime +30");
    // A failed prune must never take the launch down with it.
    expect(purge).toContain("|| true");
  });

  test("skips pruning when retention is disabled", () => {
    expect(jobPurgeCommand(configFor(22, { jobRetentionDays: 0 }))).toBeUndefined();
    expect(jobPurgeCommand(configFor(22, { jobRetentionDays: -1 }))).toBeUndefined();
    expect(backgroundScript(configFor(22, { jobRetentionDays: 0 }), "echo hi", "abc123abc123")).not.toContain("find ");
  });

  test("launching a job prunes stale files and leaves recent ones alone", async () => {
    const dir = mkdtempSync(`${tmpdir()}/vmhq-jobs-`);
    const config = configFor(22, { jobDir: dir });
    const ancient = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000);

    for (const name of ["old.log", "old.pid", "old.status"]) {
      writeFileSync(`${dir}/${name}`, "stale");
      utimesSync(`${dir}/${name}`, ancient, ancient);
    }
    // Not a job file, and an old one: the prune must not touch it.
    writeFileSync(`${dir}/keep.txt`, "unrelated");
    utimesSync(`${dir}/keep.txt`, ancient, ancient);
    writeFileSync(`${dir}/recent.log`, "fresh");

    const jobId = newJobId();
    const proc = Bun.spawn(["/bin/sh", "-c", backgroundScript(config, "true", jobId)], { stdout: "ignore", stderr: "ignore" });
    await proc.exited;

    try {
      const left = readdirSync(dir).sort();
      expect(left).not.toContain("old.log");
      expect(left).not.toContain("old.pid");
      expect(left).not.toContain("old.status");
      expect(left).toContain("keep.txt");
      expect(left).toContain("recent.log");
      expect(left).toContain(`${jobId}.log`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  /**
   * The scripts are only ever run by a remote shell, so this executes them
   * locally end to end: it is what caught `exit` in the command aborting the
   * wrapper before it could record the job's exit code.
   */
  test("runs, reports and finishes a real job under /bin/sh", async () => {
    const dir = mkdtempSync(`${tmpdir()}/vmhq-jobs-`);
    const config = configFor(22, { jobDir: dir });
    const jobId = newJobId();

    async function sh(script: string): Promise<string> {
      const proc = Bun.spawn(["/bin/sh", "-c", script], { stdout: "pipe", stderr: "ignore" });
      const output = await new Response(proc.stdout).text();
      await proc.exited;
      return output;
    }

    try {
      const command = `printf "it's running\\n"; sleep 1; printf 'done\\n'; exit 7`;
      await sh(backgroundScript(config, command, jobId));

      // Checked with no delay on purpose: a job must never read as missing
      // between the launcher returning and the wrapper recording its pid.
      const started = parseJobStatus(jobId, await sh(jobStatusScript(config, jobId)));
      expect(["starting", "running"]).toContain(started.state);

      let finished = started;
      for (let attempt = 0; attempt < 40 && finished.state !== "finished"; attempt += 1) {
        await Bun.sleep(100);
        finished = parseJobStatus(jobId, await sh(jobStatusScript(config, jobId)));
      }

      expect(finished.state).toBe("finished");
      expect(finished.exitCode).toBe(7);
      expect(finished.log).toBe("it's running\ndone\n");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 10_000);
});

/**
 * Commands are logged so the audit trail says what was run, but maintenance
 * one-liners routinely carry a secret on their argv. Redaction trims what is
 * written without giving up the trail.
 */
describe("redactCommand", () => {
  test("redacts the shapes a secret usually arrives in", () => {
    // [command, the secret that must not survive]
    const cases: Array<[string, string]> = [
      ["mysql -pSuperSecret123 -e 'show databases'", "SuperSecret123"],
      ["curl -H 'Authorization: Bearer abc.def.ghi' https://api", "abc.def.ghi"],
      ["export DB_PASSWORD=hunter2 && migrate", "hunter2"],
      ["run --token=ghp_aaaabbbbcccc", "ghp_aaaabbbbcccc"],
      ["setup api_key: 'sk-live-1234'", "sk-live-1234"],
      ["curl -H 'X-Auth-Token: minifluxsecret' http://rss", "minifluxsecret"],
      ['deploy --secret="p@ss w0rd"', "p@ss w0rd"],
    ];
    for (const [command, secret] of cases) {
      const redacted = redactCommand(command);
      expect(redacted).not.toContain(secret);
      expect(redacted).toContain("***");
    }
  });

  test("keeps the surrounding command readable instead of eating the rest of the line", () => {
    // Chained patterns used to swallow everything after a redacted value,
    // which costs exactly the audit information the log exists for.
    const redacted = redactCommand("curl -H 'X-Auth-Token: minifluxsecret' http://rss/v1/me");
    expect(redacted).toContain("curl -H");
    expect(redacted).toContain("http://rss/v1/me");
  });

  test("the secret value itself is gone, not merely masked alongside", () => {
    const redacted = redactCommand("mysql -pSuperSecret123 && curl -H 'Authorization: Bearer abc.def'");
    expect(redacted).not.toContain("SuperSecret123");
    expect(redacted).not.toContain("abc.def");
  });

  test("leaves an ordinary maintenance command untouched", () => {
    const command = "systemctl restart nginx && journalctl -u nginx -n 50";
    expect(redactCommand(command)).toBe(command);
  });

  test("truncates a long command and says how much was dropped", () => {
    const redacted = redactCommand("echo " + "x".repeat(500), 200);
    expect(redacted.length).toBeLessThan(260);
    expect(redacted).toContain("more characters]");
  });

  test("redacts before truncating, so a secret past the cutoff cannot survive", () => {
    const redacted = redactCommand(`${"echo padding; ".repeat(30)}mysql -pLATE_SECRET`, 5_000);
    expect(redacted).not.toContain("LATE_SECRET");
  });
});

/**
 * PROXMOX_SSH_HOST_FINGERPRINT is only required for a public node, so a node on
 * a private network used to be reached with no host verification at all — the
 * connection carrying a root shell accepted whatever key answered. Trust on
 * first use closes that without making the operator run ssh-keyscan before the
 * server will start.
 */
describe("host key trust on first use", () => {
  let dir: string;
  const originalPath = process.env.PROXMOX_SSH_KNOWN_HOSTS_PATH;

  beforeEach(() => {
    dir = mkdtempSync(`${tmpdir()}/vmhq-knownhosts-`);
    process.env.PROXMOX_SSH_KNOWN_HOSTS_PATH = `${dir}/known-hosts.json`;
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    if (originalPath === undefined) delete process.env.PROXMOX_SSH_KNOWN_HOSTS_PATH;
    else process.env.PROXMOX_SSH_KNOWN_HOSTS_PATH = originalPath;
  });

  function storeContents(): Record<string, { fingerprint: string }> {
    return JSON.parse(readFileSync(`${dir}/known-hosts.json`, "utf-8")) as Record<string, { fingerprint: string }>;
  }

  function seedStore(host: string, port: number, fingerprint: string): void {
    writeFileSync(
      `${dir}/known-hosts.json`,
      JSON.stringify({ [`${host}:${port}`]: { fingerprint, firstSeenAt: new Date().toISOString() } }),
    );
  }

  test("the first connection pins the key it saw", async () => {
    const server = await startServer({ onExec: ({ write, exit }) => (write("ok"), exit(0)) });
    const result = await runSshCommand(configFor(server.port), "true");
    server.close();

    if (isSshFailure(result)) throw new Error(`unexpected failure: ${result.error.message}`);
    expect(storeContents()[`127.0.0.1:${server.port}`]?.fingerprint).toBe(expectedFingerprint);
  });

  test("the store is written 0600, like the OAuth state file", async () => {
    const server = await startServer({ onExec: ({ exit }) => exit(0) });
    await runSshCommand(configFor(server.port), "true");
    server.close();

    expect(statSync(`${dir}/known-hosts.json`).mode & 0o777).toBe(0o600);
  });

  test("a later connection with the same key still works", async () => {
    const first = await startServer({ onExec: ({ write, exit }) => (write("one"), exit(0)) });
    await runSshCommand(configFor(first.port), "true");
    first.close();

    // Same host key, same port: this is the ordinary case, and it must not
    // start failing just because the key is now pinned.
    const second = await startServer({ onExec: ({ write, exit }) => (write("two"), exit(0)), port: first.port });
    const result = await runSshCommand(configFor(first.port), "true");
    second.close();

    if (isSshFailure(result)) throw new Error(`unexpected failure: ${result.error.message}`);
    expect(result.stdout).toBe("two");
  });

  test("a changed host key is refused, and the error says how to accept it", async () => {
    const server = await startServer({ onExec: ({ exit }) => exit(0) });
    seedStore("127.0.0.1", server.port, "SHA256:a-key-from-before");

    const result = await runSshCommand(configFor(server.port), "true");
    server.close();

    if (!isSshFailure(result)) throw new Error("expected a host key failure");
    expect(result.error.type).toBe("ssh_host_key_mismatch");
    expect(result.error.message).toContain("SHA256:a-key-from-before");
    expect(result.error.message).toContain("PROXMOX_SSH_KNOWN_HOSTS_PATH");
  });

  test("an explicit fingerprint overrides whatever was pinned", async () => {
    const server = await startServer({ onExec: ({ write, exit }) => (write("ok"), exit(0)) });
    seedStore("127.0.0.1", server.port, "SHA256:a-stale-pin");

    const result = await runSshCommand(
      configFor(server.port, { hostFingerprint: expectedFingerprint }),
      "true",
    );
    server.close();

    if (isSshFailure(result)) throw new Error(`unexpected failure: ${result.error.message}`);
    expect(result.stdout).toBe("ok");
  });

  test("an unwritable store does not take the node offline", async () => {
    // A read-only volume should mean "not pinned yet", not "cannot connect".
    process.env.PROXMOX_SSH_KNOWN_HOSTS_PATH = "/proc/vmhq/cannot-write.json";
    const server = await startServer({ onExec: ({ write, exit }) => (write("ok"), exit(0)) });
    const result = await runSshCommand(configFor(server.port), "true");
    server.close();

    if (isSshFailure(result)) throw new Error(`unexpected failure: ${result.error.message}`);
    expect(result.stdout).toBe("ok");
  });
});

describe("timeout", () => {
  test("reports a timeout, and the command is left running on the target", async () => {
    // Deliberately documents the limit rather than papering over it: ssh2 only
    // sends a signal request while the channel is writable, and stdin is closed
    // at exec time, so nothing can reach the remote process from here. Long
    // work belongs in background: true.
    const signals: string[] = [];
    const server = await startServer({
      onExec: () => {
        /* never finishes: the client must time out */
      },
      onSignal: (name) => signals.push(name),
    });

    const result = await runSshCommand(configFor(server.port, { timeoutMs: 700 }), "sleep 60");
    await Bun.sleep(150);
    server.close();

    if (!isSshFailure(result)) throw new Error("expected a timeout failure");
    expect(result.error.type).toBe("ssh_timeout");
    expect(result.error.retryable).toBe(true);
    expect(signals).toEqual([]);
  });
});
