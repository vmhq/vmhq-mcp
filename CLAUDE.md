# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
bun install          # install dependencies
bun run dev          # start with watch mode (auto-reload)
bun run start        # start without watch
bun run typecheck    # type-check with tsc --noEmit (no compilation output)
bun test             # run the Bun test suite
```

Correctness gates are `bun run typecheck` and `bun test`. The current tests live under `tests/` and cover OAuth behavior plus service client URL/auth/error handling. CI runs both gates before building the Docker image.

## Architecture

The server is a **stateless Bun HTTP server** that wraps personal self-hosted APIs behind a single authenticated MCP endpoint.

**Primary MCP request flow:**

```
HTTP client → /mcp → rate limit → Bearer or OAuth token check → McpServer (per-request) → callService() → upstream API
```

The HTTP server also exposes `/health`, OAuth discovery metadata, dynamic client registration, authorization, token exchange, and token revocation endpoints.

- `index.ts` — Bun HTTP server. Routes `/health`, OAuth metadata/endpoints, `/mcp`, and OpenAPI endpoints (`/openapi.json`, `/docs`). Every `/mcp` request creates a fresh `McpServer` + transport pair. Bearer auth (`MCP_ACCESS_TOKEN`) or a valid OAuth access token is enforced for `/mcp`, `/openapi.json`, and `/docs`. Responses are wrapped with common security headers.
- `oauth.ts` — OAuth protected-resource and authorization-server metadata, public dynamic client registration (`/oauth/register`), authorization-code + PKCE flow, token revocation, access-token hashing, and persisted OAuth state.
- `rateLimit.ts` — In-memory per-IP rate limits for OAuth endpoints and `/mcp`.
- `logger.ts` — Structured runtime logging controlled by `MCP_LOG_LEVEL`.
- `mcp.ts` — Registers `vmhq_status` plus three MCP tools per enabled service: `*_api_reference`, `*_operation`, `*_request`. Tool names are derived from `service.id`.
- `config.ts` — Reads env vars and maps declarative service registry entries into the `ServiceDefinition[]` array. `requireEnv()` throws at startup for missing required vars; optional vars use `readEnv()` with fallbacks.
- `serviceRegistry.ts` — Declarative service metadata: env vars, auth mode, default path prefix, default base URL, optional `enabledWhenEnv`, and default path params.
- `services.ts` — Types only: `ServiceDefinition`, `ServiceAuth` (five auth modes), `ServiceRequestInput`.
- `serviceClient.ts` — `callService()` builds the URL, injects auth headers, blocks dangerous request headers (`BLOCKED_REQUEST_HEADERS`), applies upstream timeouts, logs structured request events, and returns structured success or normalized error objects. `interpolatePath()` handles `{param}` substitution.
- `apiCatalog.ts` — Static catalog of known API endpoints for each service (`ApiCatalog` / `ApiEndpoint`). `catalogFor()` and `endpointFor()` are the lookup helpers used by `*_api_reference` and `*_operation`.
- `uploadStore.ts` — In-memory `UploadStore` class that manages chunked Paperless uploads: start/addChunk/finish/abort lifecycle, TTL expiry (15 min), PDF magic-byte validation, max decoded size (50 MB), and base64-only chunk validation. The singleton `paperlessUploadStore` is used by the Paperless tools in `mcp.ts`.
- `openapi.ts` — Generates the OpenAPI 3.0.3 spec from the enabled service catalogs (`generateOpenApiSpec`) and renders Swagger UI HTML (`renderSwaggerUI`). Both `/openapi.json` and `/docs` are auth-protected.

## Adding a new service

1. Add `ServiceId` union member in `services.ts`.
2. Add a declarative entry in `SERVICE_REGISTRY` in `serviceRegistry.ts`.
3. Add an `ApiCatalog` entry to `API_CATALOGS` in `apiCatalog.ts`.
4. Update `.env.example` and `README.md`.
5. Add or update tests when changing auth, URL construction, OAuth behavior, error normalization, or endpoint catalogs.

The three service MCP tools are registered automatically from enabled `services` in `mcp.ts` — no changes needed there unless the generic tool behavior changes.

## Auth modes

| type | behavior |
|------|----------|
| `bearer` | `Authorization: Bearer <token>` |
| `header` | Custom header name (e.g., `X-Auth-Token`) |
| `prefixed` | `Authorization: <prefix><token>` (Proxmox PVEAPIToken= style) |
| `static` | Fixed header name/value pair built at startup |
| `none` | No auth header added |

## Environment variables

`MCP_ACCESS_TOKEN` is the only hard requirement to start. Service `*_BASE_URL` vars are optional; an unset or empty base URL disables that service. Registry entries with `enabledWhenEnv` are disabled unless that env var is present. Service tokens are read lazily at request time from `process.env` — missing tokens produce a normalized `missing_upstream_credentials` tool error instead of crashing.

OAuth client registrations, authorization codes (5 min TTL), and access token hashes persist to `MCP_OAUTH_STATE_PATH` (default `./data/oauth-state.json`). Authorization codes are single-use. `/oauth/register` is public by design for Dynamic Client Registration, while registration still validates HTTPS redirect URIs and is rate-limited in memory. OAuth and `/mcp` routes are rate-limited in memory using `CF-Connecting-IP`, `X-Real-IP`, or `X-Forwarded-For`. `MCP_CORS_ORIGIN`, `MCP_UPSTREAM_TIMEOUT_MS`, `MCP_LOG_LEVEL`, `MCP_PUBLIC_URL`, and `MCP_ICON_URL` tune runtime behavior.
