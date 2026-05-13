import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { callService } from "./serviceClient.js";
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

function responseText(payload: unknown): string {
  return JSON.stringify(payload, null, 2);
}

export function createMcpServer(services: ServiceDefinition[]): McpServer {
  const server = new McpServer({
    name: "vmhq-mcp",
    version: "0.1.0",
  });

  for (const service of services) {
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
