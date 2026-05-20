import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createMcpServer } from "./mcp.js";
import { loadConfig } from "./config.js";
import { log } from "./logger.js";
import { generateOpenApiSpec, renderSwaggerUI } from "./openapi.js";
import {
  authorizationServerMetadata,
  authorize,
  authorizeForm,
  constantTimeEqual,
  exchangeToken,
  OAUTH_CORS_HEADERS,
  protectedResourceMetadata,
  registerClient,
  revokeToken,
  unauthorized,
  verifyAccessToken,
} from "./oauth.js";
import { checkRateLimit, rateLimitRetryAfterSec } from "./rateLimit.js";

function rateLimited(req: Request, bucket: string): Response {
  return json(
    { error: "rate_limited" },
    {
      status: 429,
      headers: { "Retry-After": String(rateLimitRetryAfterSec(req, bucket)) },
    },
  );
}

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

async function handleMcp(req: Request, token: string, requestId: string): Promise<Response> {
  const server = createMcpServer(config.services, config.iconUrl, config.upstreamTimeoutMs, requestId);
  const transport = new WebStandardStreamableHTTPServerTransport();

  await server.connect(transport);

  const authInfo = verifyAccessToken(token);

  try {
    return await transport.handleRequest(req, { authInfo });
  } catch (error) {
    console.error("MCP request failed", error);
    return json({ error: "mcp_request_failed" }, { status: 500 });
  }
}

const AUTHENTICATED_PATHS = new Set(["/mcp", "/openapi.json", "/docs"]);

const httpServer = Bun.serve({
  port: config.port,
  async fetch(req) {
    const url = new URL(req.url);
    const startedAt = performance.now();
    const requestId = crypto.randomUUID().slice(0, 8);

    log("debug", "http_request_started", {
      method: req.method,
      path: url.pathname,
      requestId,
    });

    if (url.pathname === "/health") {
      return secureResponse(json({
        status: "ok",
        name: "vmhq-mcp",
        mcpUrl: config.publicUrl ? `${config.publicUrl.replace(/\/$/, "")}/mcp` : undefined,
        iconUrl: config.iconUrl,
      }));
    }

    // CORS preflight for OAuth and discovery endpoints
    if (req.method === "OPTIONS" && (
      url.pathname.startsWith("/.well-known/") ||
      url.pathname.startsWith("/oauth/")
    )) {
      return new Response(null, {
        status: 204,
        headers: {
          ...OAUTH_CORS_HEADERS,
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return secureResponse(protectedResourceMetadata(oauthConfig, req));
    }

    if (url.pathname === "/.well-known/oauth-authorization-server" || url.pathname === "/.well-known/openid-configuration") {
      return secureResponse(authorizationServerMetadata(oauthConfig, req));
    }

    if (url.pathname === "/oauth/register" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_register")) {
        return secureResponse(rateLimited(req, "oauth_register"));
      }
      return secureResponse(await registerClient(req));
    }

    if (url.pathname === "/oauth/authorize" && req.method === "GET") {
      return secureResponse(authorizeForm(req, oauthConfig));
    }

    if (url.pathname === "/oauth/authorize" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_authorize")) {
        return secureResponse(rateLimited(req, "oauth_authorize"));
      }
      return secureResponse(await authorize(req, config.accessToken, oauthConfig));
    }

    if (url.pathname === "/oauth/token" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_token")) {
        return secureResponse(rateLimited(req, "oauth_token"));
      }
      return secureResponse(await exchangeToken(req));
    }

    if (url.pathname === "/oauth/revoke" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_revoke")) {
        return secureResponse(rateLimited(req, "oauth_revoke"));
      }
      return secureResponse(await revokeToken(req));
    }

    if (!AUTHENTICATED_PATHS.has(url.pathname)) {
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
      return secureResponse(rateLimited(req, "mcp"));
    }

    const token = bearerToken(req);
    const isStaticToken = constantTimeEqual(token, config.accessToken);
    const isOauth = !isStaticToken && !!verifyAccessToken(token);

    if (!isStaticToken && !isOauth) {
      return unauthorized(oauthConfig, req);
    }

    if (url.pathname === "/openapi.json") {
      const spec = generateOpenApiSpec(config.services, config.publicUrl);
      return secureResponse(Response.json(spec));
    }

    if (url.pathname === "/docs") {
      const openapiUrl = config.publicUrl
        ? `${config.publicUrl.replace(/\/$/, "")}/openapi.json`
        : `${new URL(req.url).origin}/openapi.json`;
      return secureResponse(
        new Response(renderSwaggerUI(openapiUrl), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
      );
    }

    const response = await handleMcp(req, isOauth ? token : "", requestId);
    log("info", "mcp_request_finished", {
      method: req.method,
      path: url.pathname,
      status: response.status,
      durationMs: Math.round(performance.now() - startedAt),
      requestId,
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
