import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createMcpServer } from "./mcp.js";
import { loadConfig } from "./config.js";
import { log } from "./logger.js";
import {
  authorizationServerMetadata,
  authorize,
  authorizeForm,
  constantTimeEqual,
  exchangeToken,
  isOAuthAccessToken,
  protectedResourceMetadata,
  registerClient,
  revokeToken,
  unauthorized,
} from "./oauth.js";
import { checkRateLimit } from "./rateLimit.js";

const config = loadConfig();
const oauthConfig = { publicUrl: config.publicUrl, iconUrl: config.iconUrl };

function bearerToken(req: Request): string {
  const authorization = req.headers.get("authorization") ?? "";
  const [scheme, token] = authorization.split(/\s+/, 2);
  return scheme?.toLowerCase() === "bearer" ? token ?? "" : "";
}

function json(payload: unknown, init?: ResponseInit): Response {
  return Response.json(payload, init);
}

function secureResponse(resp: Response): Response {
  const headers = new Headers(resp.headers);
  if (!headers.has("Strict-Transport-Security") && config.publicUrl?.startsWith("https")) {
    headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("X-Permitted-Cross-Domain-Policies", "none");
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

async function handleMcp(req: Request): Promise<Response> {
  const server = createMcpServer(config.services, config.iconUrl, config.upstreamTimeoutMs);
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
    const startedAt = performance.now();

    log("debug", "http_request_started", {
      method: req.method,
      path: url.pathname,
    });

    if (url.pathname === "/health") {
      return secureResponse(json({
        status: "ok",
        name: "vmhq-mcp",
        mcpUrl: config.publicUrl ? `${config.publicUrl.replace(/\/$/, "")}/mcp` : undefined,
        iconUrl: config.iconUrl,
      }));
    }

    if (url.pathname === "/.well-known/oauth-protected-resource" || url.pathname === "/.well-known/oauth-protected-resource/mcp") {
      return secureResponse(protectedResourceMetadata(oauthConfig, req));
    }

    if (url.pathname === "/.well-known/oauth-authorization-server" || url.pathname === "/.well-known/openid-configuration") {
      return secureResponse(authorizationServerMetadata(oauthConfig, req));
    }

    if (url.pathname === "/oauth/register" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_register")) {
        return secureResponse(json({ error: "rate_limited" }, { status: 429 }));
      }
      const token = bearerToken(req);
      if (!constantTimeEqual(token, config.accessToken) && !isOAuthAccessToken(token)) {
        return unauthorized(oauthConfig, req);
      }
      return secureResponse(await registerClient(req, config.accessToken));
    }

    if (url.pathname === "/oauth/authorize" && req.method === "GET") {
      return secureResponse(authorizeForm(req));
    }

    if (url.pathname === "/oauth/authorize" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_authorize")) {
        return secureResponse(json({ error: "rate_limited" }, { status: 429 }));
      }
      return secureResponse(await authorize(req, config.accessToken));
    }

    if (url.pathname === "/oauth/token" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_token")) {
        return secureResponse(json({ error: "rate_limited" }, { status: 429 }));
      }
      return secureResponse(await exchangeToken(req));
    }

    if (url.pathname === "/oauth/revoke" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_revoke")) {
        return secureResponse(json({ error: "rate_limited" }, { status: 429 }));
      }
      return secureResponse(await revokeToken(req));
    }

    if (url.pathname !== "/mcp") {
      return secureResponse(json({ error: "not_found" }, { status: 404 }));
    }

    if (req.method === "OPTIONS") {
      return secureResponse(new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Headers": "Authorization, Content-Type, MCP-Protocol-Version",
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
          "Access-Control-Allow-Origin": config.corsOrigin ?? "*",
        },
      }));
    }

    if (!checkRateLimit(req, "mcp")) {
      return secureResponse(json({ error: "rate_limited" }, { status: 429 }));
    }

    const token = bearerToken(req);
    if (!constantTimeEqual(token, config.accessToken) && !isOAuthAccessToken(token)) {
      return unauthorized(oauthConfig, req);
    }

    const response = await handleMcp(req);
    log("info", "mcp_request_finished", {
      method: req.method,
      path: url.pathname,
      status: response.status,
      durationMs: Math.round(performance.now() - startedAt),
    });
    return secureResponse(response);
  },
});

log("info", "server_started", { url: `http://0.0.0.0:${config.port}/mcp` });
if (config.publicUrl) {
  log("info", "server_public_url", { url: `${config.publicUrl.replace(/\/$/, "")}/mcp` });
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    httpServer.stop();
    process.exit(0);
  });
}
