import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { API_CATALOGS, catalogFor, endpointFor, type ApiEndpoint } from "./apiCatalog.js";
import { callService, interpolatePath } from "./serviceClient.js";
import {
  assertShellAllowed,
  assertVmidAllowed,
  backgroundScript,
  isSshFailure,
  jobPaths,
  jobStatusScript,
  JOB_ID_PATTERN,
  lxcCommand,
  newJobId,
  nodeCommand,
  parseJobStatus,
  parsePctList,
  runSshCommand,
  type ProxmoxSshConfig,
} from "./sshClient.js";
import { SERVICE_METHODS, type ServiceDefinition, type ServiceId, type ServiceMethod, type ServiceRequestInput } from "./services.js";

/**
 * Which tools a session gets. "admin" is everything; "read" leaves out the
 * Proxmox exec tools, so a session that ingests untrusted text cannot reach a
 * root shell. Chosen per endpoint in index.ts, not per request.
 */
export type ToolTier = "read" | "admin";

/**
 * Who is making this request and under which request id. Threaded into every
 * upstream call and shell command so the logs name a person, not just a client
 * id: with a root shell on the hypervisor reachable through these tools, "which
 * token" is not an answer to "who ran this".
 */
/**
 * Session inventory, injected rather than imported: importing the OAuth module
 * here would drag its load-time state read into anything that builds a server,
 * including tests that have nothing to do with OAuth.
 */
export type SessionStore = {
  list: () => unknown[];
  revoke: (filter: { actor?: string; clientId?: string; all?: boolean }) => number;
};

export type RequestContext = {
  requestId?: string;
  /** email ?? sub, or "static-token" / "legacy". See actorFor() in oauth/state.ts. */
  actor?: string;
};

const queryValueSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.array(z.union([z.string(), z.number(), z.boolean()])),
]);

const commonRequestFields = {
  query: z.record(queryValueSchema).optional().describe("Optional query string parameters."),
  body: z.unknown().optional().describe("Optional JSON request body for non-GET methods."),
  headers: z.record(z.string()).optional().describe("Optional extra headers. Auth headers are ignored."),
  fields: z.array(z.string()).optional().describe("Optional list of field names to keep from JSON response objects. Useful for large arrays like /api/states to reduce token usage."),
  maxLength: z.number().optional().describe("Optional maximum response length in characters. Responses exceeding this will be truncated."),
};

const serviceRequestSchema = {
  method: z.enum(SERVICE_METHODS).default("GET"),
  path: z.string().min(1).describe("Relative API path inside the service, for example /api/v1/entries."),
  ...commonRequestFields,
};

const apiReferenceSchema = {
  group: z.string().optional().describe("Optional endpoint group, for example entries, qemu, bookmarks or memos."),
  search: z.string().optional().describe("Optional case-insensitive text search across operationId, path and summary."),
};

const apiOperationSchema = {
  operationId: z.string().min(1).describe("Operation ID from the matching *_api_reference tool."),
  pathParams: z.record(z.union([z.string(), z.number()])).optional().describe("Values for path placeholders such as {node}, {vmid}, {memo}."),
  ...commonRequestFields,
};

function responseText(payload: unknown, maxLength?: number): string {
  const threshold = maxLength ?? 8000;
  const pretty = JSON.stringify(payload, null, 2);

  if (pretty.length <= threshold) {
    return pretty;
  }

  const compact = JSON.stringify(payload);
  if (maxLength && compact.length > maxLength) {
    return compact.slice(0, maxLength) + `\n... [truncated: ${compact.length - maxLength} more characters]`;
  }

  return compact;
}

function textResult(payload: unknown, maxLength?: number) {
  return { content: [{ type: "text" as const, text: responseText(payload, maxLength) }] };
}

function errorResult(payload: unknown, maxLength?: number) {
  return { content: [{ type: "text" as const, text: responseText(payload, maxLength) }], isError: true };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function operationBody(endpoint: ApiEndpoint, inputBody: unknown): unknown {
  if (!endpoint.defaultBody) {
    return inputBody;
  }

  if (inputBody === undefined) {
    return { ...endpoint.defaultBody };
  }

  let body = inputBody;

  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      // leave as string
    }
  }

  if (!isPlainObject(body)) {
    return inputBody;
  }

  return { ...endpoint.defaultBody, ...body };
}

function compactCatalog(serviceId: keyof typeof API_CATALOGS, group?: string, search?: string): unknown {
  const catalog = catalogFor(serviceId);
  const normalizedGroup = group?.toLowerCase();
  const normalizedSearch = search?.toLowerCase();
  const endpoints = catalog.endpoints.filter((endpoint) => {
    const groupMatches = !normalizedGroup || endpoint.group.toLowerCase() === normalizedGroup;
    const searchHaystack = `${endpoint.operationId} ${endpoint.method} ${endpoint.path} ${endpoint.summary}`.toLowerCase();
    const searchMatches = !normalizedSearch || searchHaystack.includes(normalizedSearch);
    return groupMatches && searchMatches;
  });

  return {
    service: catalog.service,
    title: catalog.title,
    docsUrl: catalog.docsUrl,
    checkedAt: catalog.checkedAt,
    auth: catalog.auth,
    pagination: catalog.pagination,
    notes: catalog.notes,
    groups: Array.from(new Set(catalog.endpoints.map((endpoint) => endpoint.group))).sort(),
    endpoints,
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const ICON_MIME_BY_EXTENSION: Record<string, string> = {
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  webp: "image/webp",
};

function iconMetadata(iconUrl: string): { src: string; mimeType?: string; sizes?: string[] } {
  const extension = new URL(iconUrl, "http://localhost").pathname.split(".").pop()?.toLowerCase() ?? "";
  const mimeType = ICON_MIME_BY_EXTENSION[extension];
  return {
    src: iconUrl,
    ...(mimeType ? { mimeType } : {}),
    ...(mimeType === "image/svg+xml" ? { sizes: ["any"] } : {}),
  };
}

function registerStatusTools(server: McpServer, services: ServiceDefinition[], enabledServiceIds: Set<ServiceId>, iconUrl: string, tier: ToolTier, ctx: RequestContext, proxmoxSsh?: ProxmoxSshConfig): void {
  server.tool(
    "vmhq_status",
    "Return VMHQ MCP status, enabled services and disabled services. This tool is always available even when no service APIs are configured.",
    {
      ping: z.boolean().optional().describe("If true, attempt a lightweight GET to each enabled service (and an SSH login when Proxmox SSH is configured) to verify it is reachable. Uses a 3 s timeout regardless of the service timeout setting."),
    },
    { title: "VMHQ Status" },
    async ({ ping }: { ping?: boolean }) => {
      const PING_TIMEOUT_MS = 3_000;
      const enabled = services.map((service) => service.id);
      const disabled = (Object.keys(API_CATALOGS) as ServiceId[]).filter((serviceId) => !enabledServiceIds.has(serviceId));

      let pingResults: Record<string, unknown> | undefined;

      if (ping) {
        const entries = await Promise.all(
          services.map(async (service) => {
            if (!service.pingPath) {
              return [service.id, { status: "skipped", reason: "no_ping_path" }] as const;
            }
            const start = performance.now();
            const result = await callService(
              service,
              { method: "GET", path: service.pingPath },
              { timeoutMs: PING_TIMEOUT_MS, operationId: "ping", ...ctx },
            );
            const durationMs = Math.round(performance.now() - start);
            const res = result as Record<string, unknown>;
            if (res.error) {
              const err = res.error as Record<string, unknown>;
              if (err.type === "upstream_timeout") {
                return [service.id, { status: "timeout", durationMs }] as const;
              }
              // upstream_network_error = unreachable; upstream_error = HTTP non-2xx (fall through)
              if (err.type !== "upstream_error") {
                return [service.id, { status: "error", durationMs }] as const;
              }
            }
            const resp = (res.response ?? {}) as Record<string, unknown>;
            return [service.id, { status: resp.ok ? "ok" : "error", httpStatus: resp.status, durationMs }] as const;
          }),
        );
        const results: Record<string, unknown> = Object.fromEntries(entries);

        if (proxmoxSsh) {
          const start = performance.now();
          const sshResult = await runSshCommand(proxmoxSsh, "true", {
            timeoutMs: PING_TIMEOUT_MS,
            target: "node",
            ...ctx,
          });
          const durationMs = Math.round(performance.now() - start);
          results.proxmox_ssh = isSshFailure(sshResult)
            ? { status: sshResult.error.type === "ssh_timeout" ? "timeout" : "error", reason: sshResult.error.type, durationMs }
            : { status: sshResult.ok ? "ok" : "error", durationMs };
        }

        pingResults = results;
      }

      return textResult({
        status: "ok",
        tier,
        ...(tier === "read"
          ? { tierNote: "Read tier: the Proxmox shell tools are not available on this endpoint. Use the admin endpoint for node maintenance." }
          : {}),
        enabledServices: enabled,
        disabledServices: disabled,
        ...(proxmoxSsh
          ? {
              proxmoxSsh: {
                host: proxmoxSsh.host,
                user: proxmoxSsh.user,
                tools:
                  tier === "admin"
                    ? ["proxmox_lxc_list", "proxmox_lxc_exec", "proxmox_node_exec", "proxmox_job_status"]
                    : ["proxmox_lxc_list", "proxmox_job_status"],
                ...(proxmoxSsh.allowedVmids ? { allowedVmids: proxmoxSsh.allowedVmids } : {}),
              },
            }
          : {}),
        ...(pingResults ? { ping: pingResults } : {}),
        iconUrl,
      });
    },
  );

  server.tool(
    "vmhq_find_operation",
    "Search for API operations across all enabled VMHQ services by keyword. Searches operationId, HTTP method, path, and summary in a single call. Use this instead of calling each service's *_api_reference separately when you don't know which service owns an operation.",
    {
      query: z.string().min(1).describe("Case-insensitive keyword to search across operationId, method, path, and summary."),
      method: z.enum(SERVICE_METHODS).optional().describe("Optional HTTP method filter (GET, POST, PUT, PATCH, DELETE)."),
    },
    { title: "VMHQ Find Operation" },
    async ({ query, method }: { query: string; method?: ServiceMethod }) => {
      const normalizedQuery = query.toLowerCase();

      const results = services.flatMap((service) => {
        const catalog = API_CATALOGS[service.id];
        if (!catalog) return [];

        return catalog.endpoints
          .filter((endpoint) => {
            if (method && endpoint.method !== method) return false;
            const haystack = `${endpoint.operationId} ${endpoint.method} ${endpoint.path} ${endpoint.summary}`.toLowerCase();
            return haystack.includes(normalizedQuery);
          })
          .map((endpoint) => ({
            service: service.id,
            serviceTitle: catalog.title,
            operationTool: `${service.id}_operation`,
            operationId: endpoint.operationId,
            method: endpoint.method,
            path: endpoint.path,
            summary: endpoint.summary,
            group: endpoint.group,
            ...(endpoint.destructive ? { destructive: true } : {}),
          }));
      });

      return textResult({ query, total: results.length, results });
    },
  );
}

/**
 * Lets whoever holds the admin tier see and cut the credentials this server has
 * issued. Without it, `POST /oauth/revoke` can only kill a token you already
 * hold — so a token you suspect was leaked, and therefore do not have, is
 * exactly the one you cannot revoke.
 */
function registerSessionTools(server: McpServer, sessions: SessionStore, ctx: RequestContext): void {
  server.tool(
    "vmhq_sessions",
    "List or revoke the OAuth sessions this MCP server has issued. Use action 'list' to see who currently holds a token, and 'revoke' to cut access for a person, a client, or everyone. Revoking removes the access token and its refresh token together, so the session cannot renew itself.",
    {
      action: z.enum(["list", "revoke"]).describe("'list' shows active sessions; 'revoke' cuts them."),
      actor: z.string().optional().describe("For revoke: the person to cut off, by email or OIDC subject, as shown by list."),
      clientId: z.string().optional().describe("For revoke: cut every session belonging to this registered client."),
      all: z.boolean().optional().describe("For revoke: cut every session on the server. Requires no other filter."),
    },
    { title: "VMHQ Sessions", destructiveHint: true },
    async ({ action, actor, clientId, all }: { action: "list" | "revoke"; actor?: string; clientId?: string; all?: boolean }) => {
      if (action === "list") {
        const active = sessions.list();
        return textResult({ total: active.length, sessions: active });
      }

      if (!actor && !clientId && !all) {
        return errorResult({
          error: {
            type: "invalid_request",
            service: "vmhq",
            message: "Revoking needs a filter: pass actor, clientId, or all: true.",
            retryable: false,
          },
        });
      }

      const revoked = sessions.revoke({ actor, clientId, all });
      return textResult({
        revoked,
        filter: all ? { all: true } : { ...(actor ? { actor } : {}), ...(clientId ? { clientId } : {}) },
        by: ctx.actor,
      });
    },
  );
}

function registerServiceTools(server: McpServer, service: ServiceDefinition, upstreamTimeoutMs: number, ctx: RequestContext): void {
  server.tool(
    `${service.id}_api_reference`,
    `Return the documented ${service.title} API operations known by this MCP server, including operation IDs, methods, paths, parameters and notes.`,
    apiReferenceSchema,
    { title: `${service.title} API Reference` },
    async ({ group, search }: { group?: string; search?: string }) => {
      return textResult(compactCatalog(service.id, group, search));
    },
  );

  server.tool(
    `${service.id}_operation`,
    `Call a documented ${service.title} operation by operationId. Use ${service.id}_api_reference first to discover valid operations and required path parameters.`,
    apiOperationSchema,
    { title: `${service.title} Operation` },
    async (input: {
      operationId: string;
      pathParams?: Record<string, string | number>;
      query?: ServiceRequestInput["query"];
      body?: unknown;
      headers?: Record<string, string>;
      fields?: ServiceRequestInput["fields"];
      maxLength?: ServiceRequestInput["maxLength"];
    }) => {
      const endpoint = endpointFor(service.id, input.operationId);

      if (!endpoint) {
        return errorResult({
          error: "unknown_operation",
          operationId: input.operationId,
          hint: `Call ${service.id}_api_reference to list supported operation IDs.`,
        });
      }

      const result = await callService(
        service,
        {
          method: endpoint.method,
          path: interpolatePath(endpoint.path, { ...service.defaultPathParams, ...input.pathParams }),
          query: input.query,
          body: operationBody(endpoint, input.body),
          headers: input.headers,
          fields: input.fields,
          maxLength: input.maxLength,
        },
        { timeoutMs: service.timeoutMs ?? upstreamTimeoutMs, operationId: endpoint.operationId, ...ctx },
      );

      return textResult({ operation: endpoint, result }, input.maxLength);
    },
  );

  server.tool(
    `${service.id}_request`,
    `Call any ${service.title} API endpoint through the configured ${service.title} base URL. Use relative paths only. Common API prefix: ${service.defaultPathPrefix}`,
    serviceRequestSchema,
    { title: `${service.title} Request` },
    async (input: ServiceRequestInput) => {
      const result = await callService(service, input, { timeoutMs: service.timeoutMs ?? upstreamTimeoutMs, ...ctx });
      return textResult(result, input.maxLength);
    },
  );
}

const sshExecFields = {
  stdin: z.string().optional().describe("Optional text piped to the command's stdin. Useful for writing files, e.g. command \"tee /etc/motd\" with the file contents as stdin."),
  timeoutMs: z.number().optional().describe("Optional override for this command's timeout in milliseconds. For anything that may run for minutes prefer background: true: the MCP client gives up long before a raised timeout does, and a foreground command that hits its timeout may keep running on the target — the server asks it to stop but cannot guarantee it, whereas a background job's lifecycle is tracked by proxmox_job_status."),
  background: z.boolean().optional().describe("Run the command detached and return immediately with a jobId. Use it for long maintenance runs (apt upgrade, rsync, builds): the command keeps running on the target even after this call returns, writing stdout and stderr to a log file, and proxmox_job_status reports its progress and final exit code."),
  maxLength: z.number().optional().describe("Optional maximum length in characters for stdout and stderr. Longer output is truncated and the dropped character count is reported."),
};

/**
 * Shell tools for maintaining the Proxmox node. Registered only when
 * PROXMOX_SSH_HOST is configured, because they expose an unrestricted shell:
 * the boundary is the SSH credential itself, not this tool surface.
 *
 * On the "read" tier the two exec tools are left out entirely. Everything this
 * server reads — search results, RSS articles, bookmarks — is third-party text
 * that lands in the same model context as the tools, so a session that only
 * needs to read has no business also holding a root shell. Leaving the tools
 * unregistered is what makes that separation real: an instruction smuggled into
 * an article cannot call a tool the session was never given.
 */
function registerProxmoxSshTools(server: McpServer, ssh: ProxmoxSshConfig, tier: ToolTier, ctx: RequestContext): void {
  const allowlistNote = ssh.allowedVmids
    ? ` Only these container IDs are reachable: ${ssh.allowedVmids.join(", ")}.`
    : "";

  const backgroundNote =
    " For anything that can run for minutes (apt upgrade, rsync, a build) pass background: true instead of raising timeoutMs: the command is detached, this call returns a jobId immediately, and proxmox_job_status reports progress and the final exit code.";

  /**
   * Launches a detached job and reports where its output landed. The launcher
   * itself returns as soon as the job is spawned, so it uses the normal command
   * timeout no matter how long the job will actually run.
   */
  async function launchBackgroundJob(
    vmid: number | undefined,
    command: string,
    options: { shell?: string; stdin?: string; timeoutMs?: number; maxLength?: number },
  ) {
    // A detached job reads from /dev/null, so honouring stdin here would be a
    // lie. Say so instead of dropping the input silently.
    if (options.stdin !== undefined) {
      return errorResult({
        error: {
          type: "invalid_request",
          service: "proxmox_ssh",
          message: "stdin is not supported for background jobs. Write the input to a file first (a foreground exec with stdin), then run the background command against that file.",
          retryable: false,
        },
      });
    }

    const jobId = newJobId();
    const target = vmid === undefined ? "node" : `lxc:${vmid}`;
    const script = backgroundScript(ssh, command, jobId, vmid === undefined ? undefined : options.shell || ssh.containerShell);
    const wrapped = vmid === undefined ? nodeCommand(ssh, script) : lxcCommand(ssh, vmid, script, options.shell);
    const result = await runSshCommand(ssh, wrapped, { timeoutMs: options.timeoutMs, target, ...ctx });

    if (isSshFailure(result) || !result.ok) {
      return errorResult(result, options.maxLength);
    }

    const paths = jobPaths(ssh, jobId);

    return textResult(
      {
        mode: "background",
        jobId,
        host: ssh.host,
        target,
        command,
        logPath: paths.logPath,
        statusPath: paths.statusPath,
        hint: `The job is running detached on ${target}. Check it with proxmox_job_status jobId ${jobId}${vmid === undefined ? "" : ` vmid ${vmid}`}.`,
      },
      options.maxLength,
    );
  }

  server.tool(
    "proxmox_lxc_list",
    `List the LXC containers on the Proxmox node ${ssh.host} with their VMID, status and name, by running pct list over SSH. Call this first to discover container IDs for proxmox_lxc_exec.${allowlistNote}`,
    {},
    { title: "Proxmox LXC List", readOnlyHint: true },
    async () => {
      const result = await runSshCommand(ssh, nodeCommand(ssh, "pct list"), { target: "node", ...ctx });

      if (isSshFailure(result) || !result.ok) {
        return errorResult(result);
      }

      const containers = parsePctList(result.stdout).filter(
        (entry) => !ssh.allowedVmids || ssh.allowedVmids.includes(entry.vmid),
      );

      return textResult({
        host: ssh.host,
        total: containers.length,
        containers,
        ...(containers.length === 0 ? { raw: result.stdout } : {}),
      });
    },
  );

  function registerProxmoxExecTools(): void {
  server.tool(
    "proxmox_lxc_exec",
    `Run a shell command inside an LXC container on ${ssh.host}, via pct exec over SSH. The command string is interpreted by ${ssh.containerShell} inside the container, so pipes, redirects, && and heredocs all work. The container must be running. Use proxmox_lxc_list to find VMIDs. This is a real root shell inside the container: it can install packages, edit configuration and restart services. There is no TTY, so commands must be non-interactive (apt-get -y, DEBIAN_FRONTEND=noninteractive).${backgroundNote}${allowlistNote}`,
    {
      vmid: z.number().int().positive().describe("Container ID (VMID), for example 101."),
      command: z.string().min(1).describe("Shell command to run inside the container, for example: systemctl restart nginx"),
      shell: z.string().optional().describe(`Shell used inside the container. Defaults to ${ssh.containerShell}; use /bin/bash when the command needs bash syntax.`),
      ...sshExecFields,
    },
    { title: "Proxmox LXC Exec", destructiveHint: true, openWorldHint: true },
    async ({ vmid, command, shell, stdin, timeoutMs, maxLength, background }: { vmid: number; command: string; shell?: string; stdin?: string; timeoutMs?: number; maxLength?: number; background?: boolean }) => {
      // The shell lands in the node-level `pct exec` command, so an unvalidated
      // value would run on the hypervisor instead of inside the container.
      const rejection = assertVmidAllowed(ssh, vmid) ?? assertShellAllowed(shell);
      if (rejection) {
        return errorResult({ error: { type: "invalid_request", service: "proxmox_ssh", message: rejection, retryable: false } });
      }

      if (background) {
        return launchBackgroundJob(vmid, command, { shell, stdin, timeoutMs, maxLength });
      }

      const result = await runSshCommand(ssh, lxcCommand(ssh, vmid, command, shell), {
        stdin,
        timeoutMs,
        maxOutputChars: maxLength,
        target: `lxc:${vmid}`,
        ...ctx,
      });

      return isSshFailure(result) ? errorResult(result, maxLength) : textResult(result, maxLength);
    },
  );

  server.tool(
    "proxmox_node_exec",
    `Run a shell command on the Proxmox node ${ssh.host} itself, over SSH. The command string is interpreted by the node shell, so pipes, redirects, && and heredocs all work. Use this to maintain the hypervisor: pct/qm lifecycle commands, pveversion, journalctl, systemctl, apt, zfs/lvm, /etc/pve configuration. There is no TTY, so commands must be non-interactive (apt-get -y, DEBIAN_FRONTEND=noninteractive). To run something inside a container, prefer proxmox_lxc_exec.${backgroundNote}`,
    {
      command: z.string().min(1).describe("Shell command to run on the node, for example: pveversion -v"),
      ...sshExecFields,
    },
    { title: "Proxmox Node Exec", destructiveHint: true, openWorldHint: true },
    async ({ command, stdin, timeoutMs, maxLength, background }: { command: string; stdin?: string; timeoutMs?: number; maxLength?: number; background?: boolean }) => {
      if (background) {
        return launchBackgroundJob(undefined, command, { stdin, timeoutMs, maxLength });
      }

      const result = await runSshCommand(ssh, nodeCommand(ssh, command), {
        stdin,
        timeoutMs,
        maxOutputChars: maxLength,
        target: "node",
        ...ctx,
      });

      return isSshFailure(result) ? errorResult(result, maxLength) : textResult(result, maxLength);
    },
  );

  }

  if (tier === "admin") registerProxmoxExecTools();

  server.tool(
    "proxmox_job_status",
    `Report the state of a background job started with background: true, together with the tail of its log. States: starting, running, finished (with its exit code), orphaned (the process is gone but never recorded an exit code, e.g. the node rebooted or the OOM killer stepped in) and not_found. Jobs keep their log in ${ssh.jobDir} on the target, so a finished job can still be inspected later.`,
    {
      jobId: z.string().min(1).describe("Job ID returned by proxmox_node_exec or proxmox_lxc_exec when called with background: true."),
      vmid: z.number().int().positive().optional().describe("Container the job was started in. Omit for jobs started with proxmox_node_exec."),
      tailLines: z.number().int().positive().optional().describe("How many trailing log lines to return. Defaults to 200."),
      maxLength: z.number().optional().describe("Optional maximum length in characters for the response."),
    },
    { title: "Proxmox Job Status", readOnlyHint: true },
    async ({ jobId, vmid, tailLines, maxLength }: { jobId: string; vmid?: number; tailLines?: number; maxLength?: number }) => {
      // The job ID lands in a shell path, so only IDs this server minted are
      // accepted: anything else could climb out of the job directory.
      if (!JOB_ID_PATTERN.test(jobId)) {
        return errorResult({
          error: { type: "invalid_request", service: "proxmox_ssh", message: "jobId must be a 12-character job ID returned by a background exec.", retryable: false },
        });
      }

      if (vmid !== undefined) {
        const rejection = assertVmidAllowed(ssh, vmid);
        if (rejection) {
          return errorResult({ error: { type: "invalid_request", service: "proxmox_ssh", message: rejection, retryable: false } });
        }
      }

      const script = jobStatusScript(ssh, jobId, tailLines ?? 200);
      const target = vmid === undefined ? "node" : `lxc:${vmid}`;
      const wrapped = vmid === undefined ? nodeCommand(ssh, script) : lxcCommand(ssh, vmid, script);
      const result = await runSshCommand(ssh, wrapped, { maxOutputChars: maxLength, target, ...ctx });

      if (isSshFailure(result)) {
        return errorResult(result, maxLength);
      }

      const status = parseJobStatus(jobId, result.stdout);

      return textResult({ host: ssh.host, target, ...status, ...jobPaths(ssh, jobId) }, maxLength);
    },
  );
}

export type CreateMcpServerOptions = {
  services: ServiceDefinition[];
  iconUrl: string;
  upstreamTimeoutMs?: number;
  requestId?: string;
  /** email ?? sub of the caller, or "static-token" / "legacy". */
  actor?: string;
  proxmoxSsh?: ProxmoxSshConfig;
  /** Defaults to "admin" so an omitted tier can never silently widen access. */
  tier?: ToolTier;
  /** Enables the admin-tier vmhq_sessions tool. Omitted means no such tool. */
  sessions?: SessionStore;
};

export function createMcpServer(options: CreateMcpServerOptions): McpServer {
  const {
    services,
    iconUrl,
    upstreamTimeoutMs = 30_000,
    requestId,
    actor,
    proxmoxSsh,
    tier = "admin",
    sessions,
  } = options;

  const ctx: RequestContext = { requestId, actor };
  const server = new McpServer({
    name: "vmhq-mcp",
    version: "0.1.0",
    icons: [iconMetadata(iconUrl)],
  });

  const enabledServiceIds = new Set(services.map((service) => service.id));

  registerStatusTools(server, services, enabledServiceIds, iconUrl, tier, ctx, proxmoxSsh);

  // Cutting other people's access is an administrative act, not a read.
  if (tier === "admin" && sessions) {
    registerSessionTools(server, sessions, ctx);
  }

  if (proxmoxSsh) {
    registerProxmoxSshTools(server, proxmoxSsh, tier, ctx);
  }

  for (const service of services) {
    registerServiceTools(server, service, upstreamTimeoutMs, ctx);
  }

  return server;
}
