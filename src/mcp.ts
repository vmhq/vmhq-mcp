import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { PinnedHaEntity } from "./config.js";
import { API_CATALOGS, catalogFor, endpointFor, type ApiEndpoint } from "./apiCatalog.js";
import { callService, interpolatePath } from "./serviceClient.js";
import { SERVICE_METHODS, type ServiceDefinition, type ServiceId, type ServiceMethod, type ServiceRequestInput } from "./services.js";
import { paperlessUploadStore } from "./uploadStore.js";

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

const paperlessUploadStartSchema = {
  filename: z.string().min(1).describe("PDF filename basename, for example document.pdf. Do not pass a local path."),
  contentType: z.string().optional().describe("MIME type. Defaults to application/pdf."),
  expectedSize: z.number().int().positive().optional().describe("Expected decoded byte size."),
  expectedBase64Length: z.number().int().positive().optional().describe("Expected total base64 character length."),
  title: z.string().optional().describe("Optional Paperless title."),
  correspondent: z.union([z.string(), z.number()]).optional().describe("Optional Paperless correspondent id/name."),
  document_type: z.union([z.string(), z.number()]).optional().describe("Optional Paperless document type id/name."),
  storage_path: z.union([z.string(), z.number()]).optional().describe("Optional Paperless storage path id/name."),
  tags: z.array(z.union([z.string(), z.number()])).optional().describe("Optional Paperless tags."),
  created: z.string().optional().describe("Optional created date, e.g. YYYY-MM-DD."),
};

const paperlessUploadChunkSchema = {
  uploadId: z.string().min(1).describe("Upload ID returned by paperless_upload_start."),
  index: z.number().int().nonnegative().describe("Zero-based chunk index."),
  chunkBase64: z.string().min(1).describe("A base64 content chunk, not a file path or file:// reference."),
};

const paperlessUploadFinishSchema = {
  uploadId: z.string().min(1).describe("Upload ID returned by paperless_upload_start."),
};

const paperlessUploadAbortSchema = paperlessUploadFinishSchema;

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

function uploadErrorResult(message: string) {
  return errorResult({ error: { type: "invalid_upload", service: "paperless", message, retryable: false } });
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

function registerPaperlessUploadTools(server: McpServer, service: ServiceDefinition, upstreamTimeoutMs: number, requestId?: string): void {
  server.tool(
    "paperless_upload_start",
    "Start a chunked Paperless document upload. Use this for PDFs too large to pass as one _base64 value.",
    paperlessUploadStartSchema,
    { title: "Paperless Upload Start" },
    async (input: {
      filename: string;
      contentType?: string;
      expectedSize?: number;
      expectedBase64Length?: number;
      title?: string;
      correspondent?: string | number;
      document_type?: string | number;
      storage_path?: string | number;
      tags?: Array<string | number>;
      created?: string;
    }) => {
      try {
        const { filename, contentType, expectedSize, expectedBase64Length, title, correspondent, document_type, storage_path, tags, created } = input;
        const fields: Record<string, string | number | Array<string | number>> = {};
        if (title !== undefined) fields.title = title;
        if (correspondent !== undefined) fields.correspondent = correspondent;
        if (document_type !== undefined) fields.document_type = document_type;
        if (storage_path !== undefined) fields.storage_path = storage_path;
        if (tags !== undefined) fields.tags = tags;
        if (created !== undefined) fields.created = created;

        return textResult(
          paperlessUploadStore.start({ filename, contentType: contentType ?? "application/pdf", expectedSize, expectedBase64Length, fields }),
        );
      } catch (error) {
        return uploadErrorResult(errorMessage(error));
      }
    },
  );

  server.tool(
    "paperless_upload_chunk",
    "Add one base64 chunk to a Paperless chunked upload. Chunks are zero-indexed.",
    paperlessUploadChunkSchema,
    { title: "Paperless Upload Chunk" },
    async (input: { uploadId: string; index: number; chunkBase64: string }) => {
      try {
        return textResult(paperlessUploadStore.addChunk(input.uploadId, input.index, input.chunkBase64));
      } catch (error) {
        return uploadErrorResult(errorMessage(error));
      }
    },
  );

  server.tool(
    "paperless_upload_finish",
    "Finish a chunked Paperless upload, validate the PDF, and post it to /api/documents/post_document/.",
    paperlessUploadFinishSchema,
    { title: "Paperless Upload Finish" },
    async (input: { uploadId: string }) => {
      try {
        const { session, bytes } = paperlessUploadStore.finish(input.uploadId);
        const result = await callService(
          service,
          {
            method: "POST",
            path: "/api/documents/post_document/",
            body: {
              _multipart: true,
              ...session.fields,
              document: {
                _bytes: bytes,
                filename: session.filename,
                contentType: session.contentType,
              },
            },
          },
          { timeoutMs: service.timeoutMs ?? upstreamTimeoutMs, operationId: "paperless_upload_finish", requestId },
        );

        return textResult({ uploadId: input.uploadId, result });
      } catch (error) {
        return uploadErrorResult(errorMessage(error));
      }
    },
  );

  server.tool(
    "paperless_upload_abort",
    "Abort and delete a pending chunked Paperless upload session.",
    paperlessUploadAbortSchema,
    { title: "Paperless Upload Abort" },
    async (input: { uploadId: string }) => {
      try {
        return textResult(paperlessUploadStore.abort(input.uploadId));
      } catch (error) {
        return uploadErrorResult(errorMessage(error));
      }
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

    if (service.id === "paperless") {
      registerPaperlessUploadTools(server, service, upstreamTimeoutMs, requestId);
    }

    if (service.id === "home_assistant" && pinnedHaEntities.length > 0) {
      registerHomeAssistantPinnedTool(server, service, pinnedHaEntities, upstreamTimeoutMs, requestId);
    }
  }

  return server;
}
