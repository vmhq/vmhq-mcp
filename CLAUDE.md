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

- `index.ts` — Bun HTTP server. Routes `/health`, `/icon.svg` (public, same-origin server icon per the MCP `icons` spec field), OAuth metadata/endpoints, `/mcp`, and OpenAPI endpoints (`/openapi.json`, `/docs`). Every `/mcp` request creates a fresh `McpServer` + transport pair. Bearer auth (`MCP_ACCESS_TOKEN`) or a valid OAuth access token is enforced for `/mcp`, `/openapi.json`, and `/docs`. Responses are wrapped with common security headers.
- `oauth.ts` — Barrel re-exporting the OAuth implementation under `oauth/`. The server is an **OAuth bridge**: it stays the authorization server toward MCP clients (protected-resource + AS metadata, public DCR at `/oauth/register`, authorization-code + PKCE, token issuance/revocation, access-token hashing, persisted state) but delegates the human login step to a PocketID OIDC instance. `oauth/pocketid.ts` is the OIDC client (discovery + auth URL + code exchange). `GET /oauth/authorize` validates the client/redirect/PKCE, stores a pending transaction (`pendingAuth`), and redirects the browser to PocketID; `GET /oauth/callback` exchanges the PocketID code and then issues the MCP authorization code bound to the original client request. There is no static-token authorization form anymore.
- `rateLimit.ts` — In-memory per-IP rate limits for OAuth endpoints and `/mcp`.
- `logger.ts` — Structured runtime logging controlled by `MCP_LOG_LEVEL`.
- `mcp.ts` — Registers `vmhq_status` plus three MCP tools per enabled service: `*_api_reference`, `*_operation`, `*_request`. Tool names are derived from `service.id`. Also registers `home_assistant_pinned_entities` when Home Assistant is enabled and `HOME_ASSISTANT_PINNED_ENTITIES` is set.
- `config.ts` — Reads env vars and maps declarative service registry entries into the `ServiceDefinition[]` array. `requireEnv()` throws at startup for missing required vars; optional vars use `readEnv()` with fallbacks.
- `serviceRegistry.ts` — Declarative service metadata: env vars, auth mode, default path prefix, default base URL, optional `enabledWhenEnv`, default path params, and optional `pingPath` (lightweight health-check path used by `vmhq_status` when `ping: true`).
- `services.ts` — Types only: `ServiceDefinition`, `ServiceAuth` (five auth modes), `ServiceRequestInput`.
- `serviceClient.ts` — `callService()` builds the URL, injects auth headers, blocks dangerous request headers (`BLOCKED_REQUEST_HEADERS`), applies upstream timeouts, logs structured request events, and returns structured success or normalized error objects. `interpolatePath()` handles `{param}` substitution.
- `apiCatalog.ts` — Static catalog of known API endpoints for each service (`ApiCatalog` / `ApiEndpoint`). `catalogFor()` and `endpointFor()` are the lookup helpers used by `*_api_reference` and `*_operation`.
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

`HOME_ASSISTANT_PINNED_ENTITIES` is an optional comma-separated list of entity IDs (with optional `:Alias` suffix) that activates the `home_assistant_pinned_entities` tool. Example: `light.tira_led_tv:RGB TV,switch.tv,sensor.temperatura_exterior:Temp Exterior`. When unset, the tool is not registered.

`POCKETID_ISSUER`, `POCKETID_CLIENT_ID`, and `POCKETID_CLIENT_SECRET` (plus optional `POCKETID_SCOPES`, default `openid profile email`) configure the upstream PocketID OIDC provider for the interactive OAuth login. All three must be set together; when any is missing, `pocketId` is left undefined and `/oauth/authorize` returns an error page (the static `MCP_ACCESS_TOKEN` bearer still works for machine access). Register `<MCP_PUBLIC_URL>/oauth/callback` as the OIDC client's redirect URI in PocketID, and restrict access via PocketID's per-client allowed groups.

OAuth client registrations, authorization codes (5 min TTL), pending PocketID transactions (`pendingAuth`, 10 min TTL), and access token hashes persist to `MCP_OAUTH_STATE_PATH` (default `./data/oauth-state.json`). Authorization codes and pending transactions are single-use. `/oauth/register` is public by design for Dynamic Client Registration, while registration still validates HTTPS redirect URIs and is rate-limited in memory. OAuth (including `/oauth/callback`, sharing the `oauth_authorize` bucket) and `/mcp` routes are rate-limited in memory using `CF-Connecting-IP`, `X-Real-IP`, or `X-Forwarded-For`. `MCP_PORT` (default `3010`), `MCP_CORS_ORIGIN`, `MCP_UPSTREAM_TIMEOUT_MS`, `MCP_LOG_LEVEL`, `MCP_PUBLIC_URL`, and `MCP_ICON_URL` tune runtime behavior.

<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->