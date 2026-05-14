import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createMcpServer } from "./mcp.js";
import { loadConfig } from "./config.js";
import {
  authorizationServerMetadata,
  authorize,
  exchangeToken,
  isOAuthAccessToken,
  protectedResourceMetadata,
  registerClient,
  unauthorized,
} from "./oauth.js";

const config = loadConfig();
const oauthConfig = { publicUrl: config.publicUrl };

function bearerToken(req: Request): string {
  const authorization = req.headers.get("authorization") ?? "";
  const [scheme, token] = authorization.split(/\s+/, 2);
  return scheme?.toLowerCase() === "bearer" ? token ?? "" : "";
}

function json(payload: unknown, init?: ResponseInit): Response {
  return Response.json(payload, init);
}

async function handleMcp(req: Request): Promise<Response> {
  const server = createMcpServer(config.services, config.iconUrl);
  const transport = new WebStandardStreamableHTTPServerTransport();

  await server.connect(transport);

  try {
    return await transport.handleRequest(req);
  } catch (error) {
    console.error("MCP request failed", error);
    return json({ error: "mcp_request_failed" }, { status: 500 });
  }
}

const httpServer = Bun.serve({
  port: config.port,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      return json({
        status: "ok",
        name: "vmhq-mcp",
        mcpUrl: config.publicUrl ? `${config.publicUrl.replace(/\/$/, "")}/mcp` : undefined,
        iconUrl: config.iconUrl,
        services: config.services.map((service) => service.id),
      });
    }

    if (url.pathname === "/.well-known/oauth-protected-resource" || url.pathname === "/.well-known/oauth-protected-resource/mcp") {
      return protectedResourceMetadata(oauthConfig, req);
    }

    if (url.pathname === "/.well-known/oauth-authorization-server" || url.pathname === "/.well-known/openid-configuration") {
      return authorizationServerMetadata(oauthConfig, req);
    }

    if (url.pathname === "/oauth/register" && req.method === "POST") {
      return registerClient(req);
    }

    if (url.pathname === "/oauth/authorize" && req.method === "GET") {
      return authorize(req, config.accessToken);
    }

    if (url.pathname === "/oauth/token" && req.method === "POST") {
      return exchangeToken(req);
    }

    if (url.pathname !== "/mcp") {
      return json({ error: "not_found" }, { status: 404 });
    }

    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Headers": "Authorization, Content-Type, MCP-Protocol-Version",
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    const token = bearerToken(req);
    if (token !== config.accessToken && !isOAuthAccessToken(token)) {
      return unauthorized(oauthConfig, req);
    }

    return handleMcp(req);
  },
});

console.log(`vmhq-mcp listening on http://0.0.0.0:${config.port}/mcp`);
if (config.publicUrl) {
  console.log(`public MCP URL: ${config.publicUrl.replace(/\/$/, "")}/mcp`);
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    httpServer.stop();
    process.exit(0);
  });
}
