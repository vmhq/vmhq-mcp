# AGENTS.md

See also `CLAUDE.md` for architecture, request flow, auth modes, and adding new services.

## Runtime

Bun only. There is no Node.js fallback, no `npm`, no `npx`. All scripts use `bun`.

```bash
bun install       # frozen lockfile via bun.lock (or bun.lockb)
bun run dev       # bun --watch src/index.ts (hot reload)
bun run start     # bun src/index.ts (production)
bun run typecheck # tsc --noEmit (the only correctness gate; no test suite)
```

The `build` script is a misnomer — it only type-checks. There is no compilation step, no `dist/` directory. Bun runs `.ts` files directly from `src/`.

## Environment variables

Only `MCP_ACCESS_TOKEN` is required at startup (server crashes without it). All other env vars are optional.

A service is silently **disabled** when its `*_BASE_URL` is empty or unset. No error, no tools registered.

The `static` auth type (used by Proxmox) is not listed in the CLAUDE.md auth table. It sets a fixed `headerName: value` pair directly (no env lookup at request time).

Miniflux auth mode is controlled by `MINIFLUX_AUTH_MODE`:
- `x-auth-token` (default) → `X-Auth-Token` header
- `bearer` → standard `Authorization: Bearer` header

## OAuth

Entirely in-memory. Client registrations, authorization codes, and access tokens are lost on restart. No persistence layer exists. OAuth tokens are validated via `isOAuthAccessToken()` which checks a `Set<string>`. Bearer token auth uses a simple string comparison against `MCP_ACCESS_TOKEN`.

## Docker

Image: `ghcr.io/vmhq/vmhq-mcp`. Dockerfile copies source `.ts` files and runs them with `bun` directly (no build step). CI builds and pushes on push to `main`; PRs build but don't push.

## Code conventions

- All imports use `.js` extensions (Bun/NodeNext resolution).
- `src/services.ts` defines the `ServiceAuth` union and `ServiceDefinition` type — every service addition touches this file.
- `src/apiCatalog.ts` exports `API_CATALOGS: Record<ServiceId, ApiCatalog>` — the only runtime data source for `*_api_reference` and `*_operation`.
- `src/config.ts` `optionalService()` returns `undefined` to skip unconfigured services; the `.filter()` in `loadConfig()` removes them.
- Response body parsing in `serviceClient.ts` returns `null` for empty bodies, parsed JSON for `application/json`, raw text otherwise.
