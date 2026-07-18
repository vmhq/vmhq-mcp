import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { PinnedHaEntity } from "./config.js";
import { API_CATALOGS, catalogFor, endpointFor, type ApiEndpoint } from "./apiCatalog.js";
import { callService, interpolatePath } from "./serviceClient.js";
import { SERVICE_METHODS, type ServiceDefinition, type ServiceId, type ServiceMethod, type ServiceRequestInput } from "./services.js";

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
  domain: z.string().optional().describe("Optional Home Assistant domain filter. When the response is an array of objects with entity_id, only items matching domain.* are kept. Example: light, switch, sensor."),
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
  pathParams: z.record(z.union([z.string(), z.number()])).optional().describe("Values for path placeholders such as {node}, {vmid}, {entity_id}."),
  ...commonRequestFields,
};

function responseText(payload: unknown, maxLength?: number): string {
  const compact = JSON.stringify(payload);
  const threshold = maxLength ?? 8000;

  if (compact.length <= threshold) {
    return JSON.stringify(payload, null, 2);
  }

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

function registerStatusTools(server: McpServer, services: ServiceDefinition[], iconUrl: string, requestId?: string): void {
  server.tool(
    "vmhq_status",
    "Return VMHQ MCP status, enabled services and disabled services. This tool is always available even when no service APIs are configured.",
    {
      ping: z.boolean().optional().describe("If true, attempt a lightweight GET to each enabled service to verify it is reachable. Uses a 3 s timeout regardless of the service timeout setting."),
    },
    { title: "VMHQ Status" },
    async ({ ping }: { ping?: boolean }) => {
      const PING_TIMEOUT_MS = 3_000;
      const enabled = services.map((service) => service.id);
      const disabled = (Object.keys(API_CATALOGS) as ServiceId[]).filter((serviceId) => !enabled.includes(serviceId));

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
              { timeoutMs: PING_TIMEOUT_MS, operationId: "ping", requestId },
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
        pingResults = Object.fromEntries(entries);
      }

      return textResult({
        status: "ok",
        enabledServices: enabled,
        disabledServices: disabled,
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

function registerServiceTools(server: McpServer, service: ServiceDefinition, upstreamTimeoutMs: number, requestId?: string): void {
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
      domain?: ServiceRequestInput["domain"];
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
          domain: input.domain,
        },
        { timeoutMs: service.timeoutMs ?? upstreamTimeoutMs, operationId: endpoint.operationId, requestId },
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
      const result = await callService(service, input, { timeoutMs: service.timeoutMs ?? upstreamTimeoutMs, requestId });
      return textResult(result, input.maxLength);
    },
  );
}

function combineNumberSeries(seriesList: number[][]): number[] {
  const maxLen = Math.max(...seriesList.map((series) => series.length));
  const combined = new Array<number>(maxLen).fill(0);

  for (const series of seriesList) {
    // Series are per-time-unit with the most recent value last; align at the end.
    const offset = maxLen - series.length;
    series.forEach((value, i) => {
      combined[offset + i] += value;
    });
  }

  return combined;
}

function combineTopLists(lists: Array<Array<Record<string, unknown>>>): Array<Record<string, number>> {
  const counts = new Map<string, number>();

  for (const list of lists) {
    for (const item of list) {
      for (const [name, count] of Object.entries(item)) {
        if (typeof count === "number") {
          counts.set(name, (counts.get(name) ?? 0) + count);
        }
      }
    }
  }

  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ [name]: count }));
}

export function combineAdguardStats(statsList: Array<Record<string, unknown>>): Record<string, unknown> {
  const keys = new Set(statsList.flatMap((stats) => Object.keys(stats)));
  const combined: Record<string, unknown> = {};

  for (const key of keys) {
    if (key === "avg_processing_time") continue;

    const values = statsList.map((stats) => stats[key]).filter((value) => value !== undefined);

    if (values.every((value) => typeof value === "number")) {
      combined[key] = (values as number[]).reduce((sum, value) => sum + value, 0);
    } else if (values.every((value) => Array.isArray(value) && value.every((item) => typeof item === "number"))) {
      combined[key] = combineNumberSeries(values as number[][]);
    } else if (values.every((value) => Array.isArray(value) && value.every(isPlainObject))) {
      combined[key] = combineTopLists(values as Array<Array<Record<string, unknown>>>);
    } else {
      combined[key] = values[0];
    }
  }

  const withAvg = statsList.filter((stats) => typeof stats.avg_processing_time === "number");
  if (withAvg.length > 0) {
    // Weight by each instance's query count so a busy instance dominates the average.
    const totalQueries = withAvg.reduce((sum, stats) => sum + (typeof stats.num_dns_queries === "number" ? stats.num_dns_queries : 0), 0);
    combined.avg_processing_time =
      totalQueries > 0
        ? withAvg.reduce(
            (sum, stats) =>
              sum + (stats.avg_processing_time as number) * (typeof stats.num_dns_queries === "number" ? stats.num_dns_queries : 0),
            0,
          ) / totalQueries
        : withAvg.reduce((sum, stats) => sum + (stats.avg_processing_time as number), 0) / withAvg.length;
  }

  return combined;
}

function registerAdguardCombinedStatsTool(server: McpServer, adguardServices: ServiceDefinition[], upstreamTimeoutMs: number, requestId?: string): void {
  const instanceIds = adguardServices.map((service) => service.id).join(", ");

  server.tool(
    "adguard_combined_stats",
    `Fetch DNS statistics from every configured AdGuard Home instance (${instanceIds}) in parallel and return per-instance stats plus a combined total: numeric counters are summed, per-time-unit series are summed aligned at the most recent unit, top_* lists are merged and re-sorted, and avg_processing_time is weighted by each instance's query count.`,
    {
      maxLength: z.number().optional().describe("Optional maximum response length in characters. Responses exceeding this will be truncated."),
    },
    { title: "AdGuard Combined Stats" },
    async ({ maxLength }: { maxLength?: number }) => {
      const endpoint = endpointFor("adguard", "stats");
      if (!endpoint) {
        return errorResult({ error: "unknown_operation", operationId: "stats" });
      }

      const results = await Promise.all(
        adguardServices.map((service) =>
          callService(
            service,
            { method: endpoint.method, path: endpoint.path },
            { timeoutMs: service.timeoutMs ?? upstreamTimeoutMs, operationId: "combined_stats", requestId },
          ),
        ),
      );

      type InstanceResult = { service: ServiceId; ok: boolean; stats?: Record<string, unknown>; error?: unknown };
      const instances: InstanceResult[] = adguardServices.map((service, i) => {
        const result = results[i] as Record<string, unknown>;
        const response = result.response as Record<string, unknown> | undefined;
        const body = response?.body;
        return !result.error && isPlainObject(body)
          ? { service: service.id, ok: true, stats: body }
          : { service: service.id, ok: false, error: result.error ?? "non_json_response" };
      });

      const successfulStats = instances.flatMap((instance) => (instance.stats ? [instance.stats] : []));

      if (successfulStats.length === 0) {
        return errorResult({ error: "all_instances_failed", instances }, maxLength);
      }

      return textResult(
        {
          combined: combineAdguardStats(successfulStats),
          combinedFrom: instances.filter((instance) => instance.ok).map((instance) => instance.service),
          ...(successfulStats.length < instances.length ? { partial: true } : {}),
          instances,
        },
        maxLength,
      );
    },
  );
}

function registerHomeAssistantPinnedTool(server: McpServer, service: ServiceDefinition, pinnedHaEntities: PinnedHaEntity[], upstreamTimeoutMs: number, requestId?: string): void {
  const pinnedSummary = pinnedHaEntities
    .map(({ entityId, alias }) => (alias ? `${alias} (${entityId})` : entityId))
    .join(", ");

  server.tool(
    "home_assistant_pinned_entities",
    `Return the current state of your pinned Home Assistant entities: ${pinnedSummary}. Call this first to get entity IDs and states without fetching all entities.`,
    {
      fields: z.array(z.string()).optional().describe("Optional list of state fields to keep per entity, e.g. ['entity_id','state','attributes.friendly_name']."),
    },
    { title: "Home Assistant Pinned Entities" },
    async ({ fields }: { fields?: string[] }) => {
      const results = await Promise.all(
        pinnedHaEntities.map(({ entityId }) =>
          callService(
            service,
            { method: "GET", path: `/api/states/${entityId}`, fields },
            { timeoutMs: service.timeoutMs ?? upstreamTimeoutMs, operationId: "get_state", requestId },
          ),
        ),
      );

      const payload = pinnedHaEntities.map(({ entityId, alias }, i) => ({
        entity_id: entityId,
        ...(alias ? { alias } : {}),
        result: results[i],
      }));
      return textResult(payload);
    },
  );
}

export function createMcpServer(services: ServiceDefinition[], iconUrl: string, upstreamTimeoutMs = 30_000, pinnedHaEntities: PinnedHaEntity[] = [], requestId?: string): McpServer {
  const server = new McpServer({
    name: "vmhq-mcp",
    version: "0.1.0",
    icons: [
      {
        src: iconUrl,
        mimeType: "image/png",
      },
    ],
  });

  registerStatusTools(server, services, iconUrl, requestId);

  for (const service of services) {
    registerServiceTools(server, service, upstreamTimeoutMs, requestId);

    if (service.id === "home_assistant" && pinnedHaEntities.length > 0) {
      registerHomeAssistantPinnedTool(server, service, pinnedHaEntities, upstreamTimeoutMs, requestId);
    }
  }

  const adguardServices = services.filter((service) => service.id === "adguard" || service.id === "adguard2");
  if (adguardServices.length > 1) {
    registerAdguardCombinedStatsTool(server, adguardServices, upstreamTimeoutMs, requestId);
  }

  return server;
}
