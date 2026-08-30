import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { createMcpServer, type ToolTier } from "./mcp.js";
import { loadConfig } from "./config.js";
import { log } from "./logger.js";
import { generateOpenApiSpec, renderSwaggerUI, SWAGGER_UI_CSP } from "./openapi.js";
import {
  authorizationServerMetadata,
  beginAuthorize,
  listSessions,
  constantTimeEqual,
  exchangeToken,
  OAUTH_CORS_HEADERS,
  oauthCallback,
  protectedResourceMetadata,
  registerClient,
  revokeSessions,
  revokeToken,
  unauthorized,
  verifyAccessToken,
} from "./oauth.js";
import { checkRateLimit, rateLimitRetryAfterSec, type ClientIpOptions } from "./rateLimit.js";
import { requestBodyTooLarge } from "./httpGuards.js";

function rateLimited(req: Request, bucket: string, ipOpts: ClientIpOptions): Response {
  return json(
    { error: "rate_limited" },
    {
      status: 429,
      headers: { "Retry-After": String(rateLimitRetryAfterSec(req, bucket, ipOpts)) },
    },
  );
}

const config = loadConfig();
const oauthConfig = {
  publicUrl: config.publicUrl,
  iconUrl: config.iconUrl,
  pocketId: config.pocketId,
  grantSummary: config.grantSummary,
};
const iconSvg = await Bun.file(new URL("./assets/icon.svg", import.meta.url)).text();
// Services and publicUrl are fixed at startup, so the spec never changes across requests.
const openApiSpecJson = JSON.stringify(generateOpenApiSpec(config.services, config.publicUrl));

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

/**
 * Who to name in the logs for this request. OAuth tokens carry the identity
 * PocketID asserted; the static token has no person behind it, and tokens
 * issued before identities were recorded read as "legacy".
 */
function actorFrom(authInfo: AuthInfo | undefined): string {
  if (!authInfo) return "static-token";
  const actor = authInfo.extra?.actor;
  return typeof actor === "string" && actor ? actor : "legacy";
}

async function handleMcp(req: Request, authInfo: AuthInfo | undefined, requestId: string, tier: ToolTier): Promise<Response> {
  const server = createMcpServer({
    services: config.services,
    iconUrl: config.iconUrl,
    upstreamTimeoutMs: config.upstreamTimeoutMs,
    requestId,
    actor: actorFrom(authInfo),
    proxmoxSsh: config.proxmoxSsh,
    tier,
    sessions: { list: listSessions, revoke: revokeSessions },
  });
  // Off unless MCP_ALLOWED_HOSTS is set: see the note in loadConfig().
  const transport = new WebStandardStreamableHTTPServerTransport(
    config.allowedHosts.length > 0
      ? {
          enableDnsRebindingProtection: true,
          allowedHosts: config.allowedHosts,
          ...(config.publicUrl ? { allowedOrigins: [new URL(config.publicUrl).origin] } : {}),
        }
      : {},
  );

  await server.connect(transport);

  try {
    return await transport.handleRequest(req, { authInfo });
  } catch (error) {
    log("error", "mcp_request_failed", {
      requestId,
      actor: actorFrom(authInfo),
      error: error instanceof Error ? error.message : String(error),
      ...(error instanceof Error && error.stack ? { stack: error.stack } : {}),
    });
    return json({ error: "mcp_request_failed" }, { status: 500 });
  }
}

/**
 * The MCP endpoints, and the tool tier each one hands out.
 *
 * `/mcp` keeps every tool, so existing clients are unaffected. `/mcp/read` is
 * the endpoint to point a day-to-day client at: same services, same auth, but
 * no Proxmox shell. Everything this server reads (search results, RSS articles,
 * bookmarks) is text written by someone else that lands in the same model
 * context as the tool list, so a session that only reads should not also be
 * holding a root shell on the hypervisor.
 */
const MCP_ENDPOINTS: Record<string, ToolTier> = {
  "/mcp": "admin",
  "/mcp/read": "read",
};

const AUTHENTICATED_PATHS = new Set([...Object.keys(MCP_ENDPOINTS), "/openapi.json", "/docs"]);

/**
 * Resource identifiers this server answers for, matching what
 * protectedResourceMetadata() advertises. Both endpoints are the same server —
 * the tool tier is decided by the path, not by the token — so a token bound to
 * either is accepted on either.
 */
function expectedResources(): string[] {
  const root = config.publicUrl?.replace(/\/$/, "");
  if (!root) return [];
  return Object.keys(MCP_ENDPOINTS).map((path) => `${root}${path}`);
}

const httpServer = Bun.serve({
  port: config.port,
  async fetch(req, server) {
    const url = new URL(req.url);
    const ipOpts: ClientIpOptions = { socketIp: server.requestIP(req)?.address };
    const startedAt = performance.now();
    const requestId = crypto.randomUUID().slice(0, 8);

    log("debug", "http_request_started", {
      method: req.method,
      path: url.pathname,
      requestId,
    });

    if (req.method === "POST" && requestBodyTooLarge(req)) {
      return secureResponse(json({ error: "payload_too_large" }, { status: 413 }));
    }

    if (url.pathname === "/icon.svg") {
      return secureResponse(new Response(iconSvg, {
        headers: {
          "Content-Type": "image/svg+xml",
          "Cache-Control": "public, max-age=86400",
          // Icons must be fetchable cross-origin by web MCP clients (claude.ai)
          "Access-Control-Allow-Origin": "*",
          "Cross-Origin-Resource-Policy": "cross-origin",
        },
      }));
    }

    if (url.pathname === "/health") {
      return secureResponse(json({
        status: "ok",
        name: "vmhq-mcp",
        mcpUrl: config.publicUrl ? `${config.publicUrl.replace(/\/$/, "")}/mcp` : undefined,
        mcpReadUrl: config.publicUrl ? `${config.publicUrl.replace(/\/$/, "")}/mcp/read` : undefined,
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

    // RFC 9728 allows the resource path to be appended to the well-known path,
    // which is how a client discovers /mcp/read rather than assuming /mcp.
    const PRM_PREFIX = "/.well-known/oauth-protected-resource";
    if (url.pathname === PRM_PREFIX || url.pathname.startsWith(`${PRM_PREFIX}/`)) {
      const resourcePath = url.pathname.slice(PRM_PREFIX.length) || "/mcp";
      if (!(resourcePath in MCP_ENDPOINTS)) {
        return secureResponse(json({ error: "not_found" }, { status: 404 }));
      }
      return secureResponse(protectedResourceMetadata(oauthConfig, req, resourcePath));
    }

    if (url.pathname === "/.well-known/oauth-authorization-server" || url.pathname === "/.well-known/openid-configuration") {
      return secureResponse(authorizationServerMetadata(oauthConfig, req));
    }

    if (url.pathname === "/oauth/register" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_register", ipOpts)) {
        return secureResponse(rateLimited(req, "oauth_register", ipOpts));
      }
      return secureResponse(await registerClient(req));
    }

    if (url.pathname === "/oauth/authorize" && req.method === "GET") {
      if (!checkRateLimit(req, "oauth_authorize", ipOpts)) {
        return secureResponse(rateLimited(req, "oauth_authorize", ipOpts));
      }
      return secureResponse(await beginAuthorize(req, oauthConfig));
    }

    if (url.pathname === "/oauth/callback" && req.method === "GET") {
      if (!checkRateLimit(req, "oauth_authorize", ipOpts)) {
        return secureResponse(rateLimited(req, "oauth_authorize", ipOpts));
      }
      return secureResponse(await oauthCallback(req, oauthConfig));
    }

    if (url.pathname === "/oauth/token" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_token", ipOpts)) {
        return secureResponse(rateLimited(req, "oauth_token", ipOpts));
      }
      return secureResponse(await exchangeToken(req));
    }

    if (url.pathname === "/oauth/revoke" && req.method === "POST") {
      if (!checkRateLimit(req, "oauth_revoke", ipOpts)) {
        return secureResponse(rateLimited(req, "oauth_revoke", ipOpts));
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
          // No wildcard fallback: an unset MCP_CORS_ORIGIN means no browser
          // origin was ever intended, and non-browser MCP clients send no
          // Origin at all. The OAuth endpoints keep their `*`, which discovery
          // genuinely needs.
          ...(config.corsOrigin ? { "Access-Control-Allow-Origin": config.corsOrigin } : {}),
        },
      }));
    }

    if (!checkRateLimit(req, "mcp", ipOpts)) {
      return secureResponse(rateLimited(req, "mcp", ipOpts));
    }

    const token = bearerToken(req);
    const isStaticToken = constantTimeEqual(token, config.accessToken);
    const oauthInfo = isStaticToken ? undefined : verifyAccessToken(token, expectedResources());

    if (!isStaticToken && !oauthInfo) {
      // A failed attempt burns a much narrower budget than a successful call,
      // so probing tokens cannot hide inside the ordinary /mcp allowance.
      if (!checkRateLimit(req, "mcp_auth_failure", ipOpts)) {
        return secureResponse(rateLimited(req, "mcp_auth_failure", ipOpts));
      }
      return secureResponse(
        unauthorized(oauthConfig, req, url.pathname in MCP_ENDPOINTS ? url.pathname : "/mcp"),
      );
    }

    if (url.pathname === "/openapi.json") {
      return secureResponse(
        new Response(openApiSpecJson, { headers: { "Content-Type": "application/json" } }),
      );
    }

    if (url.pathname === "/docs") {
      const openapiUrl = config.publicUrl
        ? `${config.publicUrl.replace(/\/$/, "")}/openapi.json`
        : `${url.origin}/openapi.json`;
      return secureResponse(
        new Response(renderSwaggerUI(openapiUrl), {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": SWAGGER_UI_CSP,
          },
        }),
      );
    }

    const response = await handleMcp(req, oauthInfo, requestId, MCP_ENDPOINTS[url.pathname] ?? "admin");
    log("info", "mcp_request_finished", {
      method: req.method,
      path: url.pathname,
      status: response.status,
      durationMs: Math.round(performance.now() - startedAt),
      requestId,
      actor: actorFrom(oauthInfo),
    });
    return secureResponse(response);
  },
});

log("info", "server_started", { url: `http://0.0.0.0:${config.port}/mcp` });
if (config.publicUrl) {
  const root = config.publicUrl.replace(/\/$/, "");
  log("info", "server_public_url", { url: `${root}/mcp`, readUrl: `${root}/mcp/read` });
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    httpServer.stop();
    process.exit(0);
  });
}
