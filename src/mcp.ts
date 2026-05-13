import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { API_CATALOGS, catalogFor, endpointFor } from "./apiCatalog.js";
import { callService, interpolatePath } from "./serviceClient.js";
import { SERVICE_METHODS, type ServiceDefinition, type ServiceRequestInput } from "./services.js";

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
};

function responseText(payload: unknown): string {
  return JSON.stringify(payload, null, 2);
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

export function createMcpServer(services: ServiceDefinition[]): McpServer {
  const server = new McpServer({
    name: "vmhq-mcp",
    version: "0.1.0",
  });

  for (const service of services) {
    server.tool(
      `${service.id}_api_reference`,
      `Return the documented ${service.title} API operations known by this MCP server, including operation IDs, methods, paths, parameters and notes.`,
      apiReferenceSchema,
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
      async (input: {
        operationId: string;
        pathParams?: Record<string, string | number>;
        query?: ServiceRequestInput["query"];
        body?: unknown;
        headers?: Record<string, string>;
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

        const result = await callService(service, {
          method: endpoint.method,
          path: interpolatePath(endpoint.path, input.pathParams),
          query: input.query,
          body: input.body,
          headers: input.headers,
        });

        return {
          content: [
            {
              type: "text",
              text: responseText({
                operation: endpoint,
                result,
              }),
            },
          ],
        };
      },
    );

    server.tool(
      `${service.id}_request`,
      `Call any ${service.title} API endpoint through the configured ${service.title} base URL. Use relative paths only. Common API prefix: ${service.defaultPathPrefix}`,
      serviceRequestSchema,
      async (input: ServiceRequestInput) => {
        const result = await callService(service, input);

        return {
          content: [
            {
              type: "text",
              text: responseText(result),
            },
          ],
        };
      },
    );
  }

  return server;
}
