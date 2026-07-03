# AGENTS.md

See also `CLAUDE.md` for architecture, request flow, auth modes, and adding new services.

## Runtime

Bun only. There is no Node.js fallback, no `npm`, no `npx`. All scripts use `bun`.

```bash
bun install       # frozen lockfile via bun.lock (or bun.lockb)
bun run dev       # bun --watch src/index.ts (hot reload)
bun run start     # bun src/index.ts (production)
bun run typecheck # tsc --noEmit
bun test          # bun test
```

The `build` script is a misnomer — it only type-checks. There is no compilation step, no `dist/` directory. Bun runs `.ts` files directly from `src/`.

Correctness gates are `bun run typecheck` and `bun test`. The current test suite covers OAuth behavior and service client URL/auth/error handling under `tests/`.

## Environment variables

Only `MCP_ACCESS_TOKEN` is required at startup (server crashes without it). All other env vars are optional. `MCP_PORT` sets the listen port (defaults to `3010`).

A service is silently **disabled** when its `*_BASE_URL` is empty or unset. No error, no tools registered.

`HOME_ASSISTANT_PINNED_ENTITIES` is an optional comma-separated list of Home Assistant entity IDs, each with an optional `:Alias` suffix:

```
HOME_ASSISTANT_PINNED_ENTITIES=light.tira_led_tv:RGB TV,switch.tv,sensor.temperatura_exterior:Temp Exterior
```

When set, a `home_assistant_pinned_entities` tool is registered that fetches those entity states in parallel. The tool description lists all aliases so the agent can identify entities by friendly name before calling the tool. When unset, the tool is not registered and there is no overhead.

The `static` auth type (used by Proxmox) sets a fixed `headerName: value` pair directly at startup (no env lookup at request time).

Miniflux auth mode is controlled by `MINIFLUX_AUTH_MODE`:
- `x-auth-token` (default) → `X-Auth-Token` header
- `bearer` → standard `Authorization: Bearer` header

## OAuth, rate limiting, and security headers

`src/oauth.ts` (implementation under `src/oauth/`) makes the server an OAuth bridge: it implements OAuth metadata, public dynamic client registration (`/oauth/register`), authorization-code + PKCE exchange, token revocation, and protected-resource challenges, while delegating the interactive user login to a PocketID OIDC instance (`src/oauth/pocketid.ts`). `GET /oauth/authorize` redirects the browser to PocketID; `GET /oauth/callback` exchanges the PocketID code and issues the MCP authorization code. PocketID is configured via `POCKETID_ISSUER` / `POCKETID_CLIENT_ID` / `POCKETID_CLIENT_SECRET` (optional `POCKETID_SCOPES`); register `<MCP_PUBLIC_URL>/oauth/callback` as the OIDC client redirect URI. Client registrations, short-lived authorization codes (5 min TTL), pending PocketID transactions (10 min TTL), and OAuth access token hashes are persisted to `MCP_OAUTH_STATE_PATH` (defaults to `./data/oauth-state.json`). Authorization codes are single-use and pruned periodically. Stored OAuth access tokens are SHA-256 hashes; `isOAuthAccessToken()` hashes the presented token and checks expiry. Bearer token auth still compares directly against `MCP_ACCESS_TOKEN` for non-OAuth clients.

`src/rateLimit.ts` applies in-memory per-IP limits to OAuth endpoints and `/mcp`, using `CF-Connecting-IP`, `X-Real-IP`, then `X-Forwarded-For`. `src/index.ts` wraps responses with security headers and exposes OAuth discovery endpoints, `/health`, `/mcp`, and the OpenAPI documentation endpoints (`/openapi.json` and `/docs`, both protected by Bearer auth).

## Docker

Image: `ghcr.io/vmhq/vmhq-mcp`. Dockerfile copies source `.ts` files and runs them with `bun` directly (no build step). CI installs dependencies, runs `bun run typecheck`, runs `bun test`, then builds the Docker image. Pushes to `main` publish to GHCR; PRs build but don't push.

## Code conventions

- All imports use `.js` extensions (Bun/NodeNext resolution).
- `src/services.ts` defines the `ServiceAuth` union and `ServiceDefinition` type — every service addition touches this file.
- `src/apiCatalog.ts` exports `API_CATALOGS: Record<ServiceId, ApiCatalog>` — the only runtime data source for `*_api_reference` and `*_operation`.
- `src/serviceRegistry.ts` declares service metadata in one registry; `src/config.ts` maps registry entries to `ServiceDefinition[]` and skips unconfigured services. Each entry carries an optional `pingPath` — a lightweight GET path (e.g. `/api/`) used by `vmhq_status` when called with `ping: true` to verify reachability with a 3 s timeout.
- `src/oauth.ts`, `src/rateLimit.ts`, and `src/logger.ts` are active runtime modules; keep docs and tests aligned when changing auth, request limits, or structured logging.
- `src/openapi.ts` generates the OpenAPI 3.0.3 spec and Swagger UI; both `/openapi.json` and `/docs` require Bearer or OAuth authentication.
- Response body parsing in `serviceClient.ts` returns `null` for empty bodies, parsed JSON for `application/json`, raw text otherwise.
