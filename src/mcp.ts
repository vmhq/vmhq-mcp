import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { API_CATALOGS, catalogFor, endpointFor, type ApiEndpoint } from "./apiCatalog.js";
import { callService, interpolatePath } from "./serviceClient.js";
import { SERVICE_METHODS, type ServiceDefinition, type ServiceId, type ServiceRequestInput } from "./services.js";

const queryValueSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.array(z.union([z.string(), z.number(), z.boolean()])),
]);

const serviceRequestSchema = {
  method: z.enum(SERVICE_METHODS).default("GET"),
  path: z.string().min(1).describe("Relative API path inside the service, for example /api/v1/entries."),
  query: z.record(queryValueSchema).optional().describe("Optional query string parameters."),
  body: z.unknown().optional().describe("Optional JSON request body for non-GET methods."),
  headers: z.record(z.string()).optional().describe("Optional extra headers. Auth headers are ignored."),
  fields: z.array(z.string()).optional().describe("Optional list of field names to keep from JSON response objects. Useful for large arrays like /api/states to reduce token usage."),
  maxLength: z.number().optional().describe("Optional maximum response length in characters. Responses exceeding this will be truncated."),
  domain: z.string().optional().describe("Optional Home Assistant domain filter. When the response is an array of objects with entity_id, only items matching domain.* are kept. Example: light, switch, sensor."),
};

const apiReferenceSchema = {
  group: z.string().optional().describe("Optional endpoint group, for example entries, qemu, bookmarks or memos."),
  search: z.string().optional().describe("Optional case-insensitive text search across operationId, path and summary."),
};

const apiOperationSchema = {
  operationId: z.string().min(1).describe("Operation ID from the matching *_api_reference tool."),
  pathParams: z.record(z.union([z.string(), z.number()])).optional().describe("Values for path placeholders such as {node}, {vmid}, {entity_id}."),
  query: z.record(queryValueSchema).optional().describe("Optional query string parameters."),
  body: z.unknown().optional().describe("Optional JSON request body."),
  headers: z.record(z.string()).optional().describe("Optional extra headers. Auth headers are ignored."),
  fields: z.array(z.string()).optional().describe("Optional list of field names to keep from JSON response objects."),
  maxLength: z.number().optional().describe("Optional maximum response length in characters. Responses exceeding this will be truncated."),
  domain: z.string().optional().describe("Optional Home Assistant domain filter. When the response is an array of objects with entity_id, only items matching domain.* are kept."),
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

  if (!isPlainObject(inputBody)) {
    return inputBody;
  }

  return { ...endpoint.defaultBody, ...inputBody };
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

export function createMcpServer(services: ServiceDefinition[], iconUrl: string, upstreamTimeoutMs = 30_000): McpServer {
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

  server.tool(
    "vmhq_status",
    "Return VMHQ MCP status, enabled services and disabled services. This tool is always available even when no service APIs are configured.",
    {},
    { title: "VMHQ Status" },
    async () => {
      const enabled = services.map((service) => service.id);
      const disabled = (Object.keys(API_CATALOGS) as ServiceId[]).filter((serviceId) => !enabled.includes(serviceId));

      return {
        content: [
          {
            type: "text",
            text: responseText({
              status: "ok",
              enabledServices: enabled,
              disabledServices: disabled,
              iconUrl,
            }),
          },
        ],
      };
    },
  );

  for (const service of services) {
    server.tool(
      `${service.id}_api_reference`,
      `Return the documented ${service.title} API operations known by this MCP server, including operation IDs, methods, paths, parameters and notes.`,
      apiReferenceSchema,
      { title: `${service.title} API Reference` },
      async ({ group, search }: { group?: string; search?: string }) => {
        return {
          content: [
            {
              type: "text",
              text: responseText(compactCatalog(service.id, group, search)),
            },
          ],
        };
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
          return {
            content: [
              {
                type: "text",
                text: responseText({
                  error: "unknown_operation",
                  operationId: input.operationId,
                  hint: `Call ${service.id}_api_reference to list supported operation IDs.`,
                }),
              },
            ],
            isError: true,
          };
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
          { timeoutMs: upstreamTimeoutMs, operationId: endpoint.operationId },
        );

        return {
          content: [
            {
              type: "text",
              text: responseText({
                operation: endpoint,
                result,
              }, input.maxLength),
            },
          ],
        };
      },
    );

    server.tool(
      `${service.id}_request`,
      `Call any ${service.title} API endpoint through the configured ${service.title} base URL. Use relative paths only. Common API prefix: ${service.defaultPathPrefix}`,
      serviceRequestSchema,
      { title: `${service.title} Request` },
      async (input: ServiceRequestInput) => {
        const result = await callService(service, input, { timeoutMs: upstreamTimeoutMs });

        return {
          content: [
            {
              type: "text",
              text: responseText(result, input.maxLength),
            },
          ],
        };
      },
    );
  }

  return server;
}
