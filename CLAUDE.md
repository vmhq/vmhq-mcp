# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
bun install          # install dependencies
bun run dev          # start with watch mode (auto-reload)
bun run start        # start without watch
bun run typecheck    # type-check with tsc --noEmit (no compilation output)
```

No test suite exists yet. Type checking is the main correctness gate.

## Architecture

The server is a **stateless Bun HTTP server** that wraps personal self-hosted APIs behind a single authenticated MCP endpoint.

**Request flow:**

```
HTTP client → Bearer token check → /mcp → McpServer (per-request) → callService() → upstream API
```

- `index.ts` — Bun HTTP server. Every `/mcp` request creates a fresh `McpServer` + transport pair. Bearer auth (`MCP_ACCESS_TOKEN`) is enforced before handing off to MCP.
- `mcp.ts` — Registers three MCP tools per service: `*_api_reference`, `*_operation`, `*_request`. Tool names are derived from `service.id`.
- `config.ts` — Reads env vars and maps declarative service registry entries into the `ServiceDefinition[]` array. `requireEnv()` throws at startup for missing required vars; optional vars use `readEnv()` with fallbacks.
- `serviceRegistry.ts` — Declarative service metadata: env vars, auth mode, default path prefix, and default path params.
- `services.ts` — Types only: `ServiceDefinition`, `ServiceAuth` (five auth modes), `ServiceRequestInput`.
- `serviceClient.ts` — `callService()` builds the URL, injects auth headers, blocks dangerous request headers (`BLOCKED_REQUEST_HEADERS`), applies upstream timeouts, logs structured request events, and returns structured success or normalized error objects. `interpolatePath()` handles `{param}` substitution.
- `apiCatalog.ts` — Static catalog of known API endpoints for each service (`ApiCatalog` / `ApiEndpoint`). `catalogFor()` and `endpointFor()` are the lookup helpers used by `*_api_reference` and `*_operation`.

## Adding a new service

1. Add `ServiceId` union member in `services.ts`.
2. Add a declarative entry in `SERVICE_REGISTRY` in `serviceRegistry.ts`.
3. Add an `ApiCatalog` entry to `API_CATALOGS` in `apiCatalog.ts`.
4. Update `.env.example` and `README.md`.

The three MCP tools are registered automatically from `services` in `mcp.ts` — no changes needed there.

## Auth modes

| type | behavior |
|------|----------|
| `bearer` | `Authorization: Bearer <token>` |
| `header` | Custom header name (e.g., `X-Auth-Token`) |
| `prefixed` | `Authorization: <prefix><token>` (Proxmox PVEAPIToken= style) |
| `static` | Fixed header name/value pair built at startup |
| `none` | No auth header added |

## Environment variables

`MCP_ACCESS_TOKEN` is the only hard requirement to start. Service `*_BASE_URL` vars are optional; an unset or empty base URL disables that service. Service tokens are read lazily at request time from `process.env` — missing tokens produce a normalized `missing_upstream_credentials` tool error instead of crashing.

OAuth client registrations and access token hashes persist to `MCP_OAUTH_STATE_PATH` (default `./data/oauth-state.json`). Authorization codes are in-memory, short-lived, and single-use.
