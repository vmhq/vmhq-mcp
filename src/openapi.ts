import { API_CATALOGS } from "./apiCatalog.js";
import type { ServiceDefinition } from "./services.js";

type OpenApiParameter = {
  name: string;
  in: "path" | "query";
  required: boolean;
  schema: { type: string };
};

type OpenApiOperation = {
  operationId: string;
  summary: string;
  tags: string[];
  parameters: OpenApiParameter[];
  responses: Record<string, unknown>;
  description?: string;
  requestBody?: unknown;
};

type OpenApiPathItem = Partial<Record<string, OpenApiOperation>>;

export function generateOpenApiSpec(services: ServiceDefinition[], publicUrl?: string) {
  const paths: Record<string, OpenApiPathItem> = {};
  const tags: Array<{ name: string; description: string }> = [];

  for (const service of services) {
    const catalog = API_CATALOGS[service.id];
    if (!catalog) continue;

    tags.push({
      name: service.title,
      description: `${catalog.title} - ${catalog.docsUrl}`,
    });

    for (const endpoint of catalog.endpoints) {
      // Create a unique path for the OpenAPI spec to avoid collisions between services
      // We prefix with the service ID to group them logically
      const openApiPath = `/${service.id}${endpoint.path}`;

      if (!paths[openApiPath]) {
        paths[openApiPath] = {};
      }

      const parameters: OpenApiParameter[] = [];

      // Extract path parameters from the path string (e.g., {id})
      const pathParamMatches = endpoint.path.match(/\{([^}]+)\}/g);
      if (pathParamMatches) {
        for (const match of pathParamMatches) {
          const paramName = match.slice(1, -1);
          parameters.push({
            name: paramName,
            in: "path",
            required: true,
            schema: { type: "string" },
          });
        }
      }

      // Add query parameters
      if (endpoint.query) {
        for (const queryParam of endpoint.query) {
          parameters.push({
            name: queryParam,
            in: "query",
            required: false,
            schema: { type: "string" },
          });
        }
      }

      const operation: OpenApiOperation = {
        operationId: `${service.id}_${endpoint.operationId}`,
        summary: endpoint.summary,
        tags: [service.title],
        parameters,
        responses: {
          "200": {
            description: "Successful response",
            content: {
              "application/json": {
                schema: { type: "object" },
              },
            },
          },
        },
      };

      if (endpoint.notes) {
        operation.description = endpoint.notes;
      }

      if (endpoint.body && ["POST", "PUT", "PATCH"].includes(endpoint.method)) {
        operation.requestBody = {
          content: {
            "application/json": {
              schema: {
                type: "object",
                description: typeof endpoint.body === "string" ? endpoint.body : "Request body",
              },
            },
          },
        };
      }

      paths[openApiPath][endpoint.method.toLowerCase()] = operation;
    }
  }

  const servers = [];
  if (publicUrl) {
    servers.push({ url: publicUrl.replace(/\/$/, "") });
  } else {
    servers.push({ url: "/" });
  }

  return {
    openapi: "3.0.3",
    info: {
      title: "vmhq-mcp API Catalog",
      version: "0.1.0",
      description: "Auto-generated OpenAPI specification for the configured MCP services.",
    },
    servers,
    tags,
    paths,
  };
}

export function renderSwaggerUI(openapiUrl: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Swagger UI - vmhq-mcp</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  <style>
    body { margin: 0; padding: 0; }
    .swagger-ui .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" crossorigin></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: ${JSON.stringify(openapiUrl)},
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
      });
    };
  </script>
</body>
</html>`;
}
