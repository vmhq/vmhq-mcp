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
- `mcp.ts` — `createMcpServer()` takes an options object including a `ToolTier` (`"read"` | `"admin"`, defaulting to `"admin"` so an omitted tier cannot silently widen access). On the read tier `proxmox_lxc_exec` and `proxmox_node_exec` are never registered, which is what keeps untrusted text pulled in by the service tools from reaching a root shell; `index.ts` maps `/mcp` → admin and `/mcp/read` → read via `MCP_ENDPOINTS`, and each endpoint gets its own RFC 9728 metadata document at `/.well-known/oauth-protected-resource[/path]`. Registers `vmhq_status` (which reports the active tier) plus three MCP tools per enabled service: `*_api_reference`, `*_operation`, `*_request`. Tool names are derived from `service.id`. Also registers `home_assistant_pinned_entities` when Home Assistant is enabled and `HOME_ASSISTANT_PINNED_ENTITIES` is set, and `proxmox_lxc_list` / `proxmox_lxc_exec` / `proxmox_node_exec` / `proxmox_job_status` when `PROXMOX_SSH_HOST` is set.
- `config.ts` — Reads env vars and maps declarative service registry entries into the `ServiceDefinition[]` array. `requireEnv()` throws at startup for missing required vars; optional vars use `readEnv()` with fallbacks.
- `serviceRegistry.ts` — Declarative service metadata: env vars, auth mode, default path prefix, default base URL, optional `enabledWhenEnv`, default path params, and optional `pingPath` (lightweight health-check path used by `vmhq_status` when `ping: true`).
- `services.ts` — Types only: `ServiceDefinition`, `ServiceAuth` (five auth modes), `ServiceRequestInput`.
- `sshClient.ts` — `runSshCommand()` opens a per-call SSH connection to the Proxmox node (via `ssh2`), runs one command, caps and returns its output, and normalizes transport failures. Also holds `shellQuote()`, `nodeCommand()`, `lxcCommand()`, `assertVmidAllowed()` and `parsePctList()`. Only used by the Proxmox SSH tools; every other upstream is HTTP.
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

`PROXMOX_INSECURE_TLS=true` disables TLS certificate verification for the Proxmox upstream only, for nodes serving the self-signed PVE cluster CA on `:8006`. It is resolved declaratively via `insecureTlsEnv` in `serviceRegistry.ts` and applied as a per-request `tls: { rejectUnauthorized: false }` option on that service's `fetch`, so every other upstream keeps verifying normally (unlike the process-wide `NODE_TLS_REJECT_UNAUTHORIZED=0`). `readInsecureTls()` throws at startup if the flag is set while the base URL points at a public host, as checked by `isPrivateHost()`.

`PROXMOX_SSH_HOST` enables SSH shell tools for the Proxmox node (`proxmox_lxc_list`, `proxmox_lxc_exec`, `proxmox_node_exec`, `proxmox_job_status`), implemented in `src/sshClient.ts` on top of the `ssh2` client. This is the one upstream that is not HTTP: the Proxmox REST API has no exec endpoint for LXC containers, so commands run inside a container go over SSH via `pct exec`. The tools expose an unrestricted remote shell by design — the agent is meant to maintain the node — so the SSH credential is the security boundary, not the tool surface. Credentials (`PROXMOX_SSH_KEY`, `PROXMOX_SSH_KEY_PATH`, `PROXMOX_SSH_KEY_PASSPHRASE`, `PROXMOX_SSH_PASSWORD`) are read lazily at request time like service tokens, so a missing key produces a normalized `missing_upstream_credentials` error. `loadProxmoxSshConfig()` throws at startup when the node is public and `PROXMOX_SSH_HOST_FINGERPRINT` is unset, reusing `isPrivateHost()` the same way `PROXMOX_INSECURE_TLS` does. `PROXMOX_SSH_ALLOWED_VMIDS` optionally restricts which containers `proxmox_lxc_exec` can reach, `PROXMOX_SSH_SUDO=true` wraps commands in `sudo -n /bin/sh -c` for non-root users (which elevates but cannot restrict: a per-binary sudoers rule is useless against `sh -c '<arbitrary>'`, so narrowing has to come from the credential — a dedicated node user or a forced `command=` in `authorized_keys`), and `PROXMOX_SSH_TIMEOUT_MS` / `PROXMOX_SSH_MAX_OUTPUT` bound each call. Both exec tools accept `background: true`, which detaches the command (`setsid`, falling back to `nohup`) and returns a `jobId` instead of waiting: the ceiling on a long command is the MCP client's own timeout, not `PROXMOX_SSH_TIMEOUT_MS`, so raising `timeoutMs` cannot fix it. `backgroundScript()` writes the job's pid, output and exit code under `PROXMOX_SSH_JOB_DIR` (default `/var/log/vmhq-mcp`) and runs the command in a subshell so an `exit` in it does not stop the wrapper from recording the status; `proxmox_job_status` reads them back via `jobStatusScript()` / `parseJobStatus()` as `starting` / `running` / `finished` / `orphaned` / `not_found`. Files age out after `PROXMOX_SSH_JOB_RETENTION_DAYS` (default 30, `0` disables): `jobPurgeCommand()` runs from the launcher rather than a timer, since the server keeps no state between requests, and it matches only the `.log` / `.pid` / `.status` names a job creates. Job IDs are minted by the server and validated against `JOB_ID_PATTERN` before they reach a path. Commands built for `pct exec` are single-quoted through `shellQuote()`, so a command string can never break out of its argument. The interpreter itself is the other half of that guarantee: `PROXMOX_SSH_CONTAINER_SHELL` and the per-call `shell` argument are restricted to a plain absolute path by `isAllowedShell()` (rejected at startup and at the tool boundary via `assertShellAllowed()`, and refused again inside `lxcCommand()` / `backgroundScript()`), because an unvalidated shell would be spliced into the node-level command and escape both the container and `PROXMOX_SSH_ALLOWED_VMIDS`. Every call is logged as `ssh_exec_started` / `ssh_exec_finished` / `ssh_exec_failed`.

`sshKnownHosts.ts` pins the node's SSH host key on first use when `PROXMOX_SSH_HOST_FINGERPRINT` is unset, recording it at `PROXMOX_SSH_KNOWN_HOSTS_PATH` (default `./data/proxmox-known-hosts.json`, written atomically at `0600` like the OAuth state) and refusing a later key change with `ssh_host_key_mismatch`; an explicit fingerprint always wins, and an unwritable store logs `ssh_host_key_pin_failed` rather than blocking the connection. `redactCommand()` masks known secret shapes and truncates to 200 characters before a command reaches the `ssh_exec_*` logs — the response to the caller keeps the full command. `callService()` follows redirects manually (`redirect: "manual"`, GET only, max 3 hops) and refuses any hop that leaves the configured origin with `upstream_redirect_blocked`: fetch strips `Authorization` cross-origin but not header-named credentials like Miniflux's `X-Auth-Token`, and `buildUrl()`'s origin check only covers the first URL.

`HOME_ASSISTANT_PINNED_ENTITIES` is an optional comma-separated list of entity IDs (with optional `:Alias` suffix) that activates the `home_assistant_pinned_entities` tool. Example: `light.tira_led_tv:RGB TV,switch.tv,sensor.temperatura_exterior:Temp Exterior`. When unset, the tool is not registered.

`POCKETID_ISSUER`, `POCKETID_CLIENT_ID`, and `POCKETID_CLIENT_SECRET` (plus optional `POCKETID_SCOPES`, default `openid profile email`) configure the upstream PocketID OIDC provider for the interactive OAuth login. All three must be set together; when any is missing, `pocketId` is left undefined and `/oauth/authorize` returns an error page (the static `MCP_ACCESS_TOKEN` bearer still works for machine access). Register `<MCP_PUBLIC_URL>/oauth/callback` as the OIDC client's redirect URI in PocketID, and restrict access via PocketID's per-client allowed groups.

Every issued token carries the identity PocketID asserted: `exchangePocketIdCode()` verifies the `id_token` against the provider's JWKS (signature, `iss`, `aud`, `exp`) and returns `{subject, email}`, which is bound to the authorization code and then to the token, exposed through `AuthInfo.extra.actor`, and named in every `ssh_exec_*`, `upstream_request_*` and `mcp_request_*` log line via the `RequestContext` threaded through `createMcpServer()`. Tokens issued before this existed still authenticate and log as `legacy`; a static `MCP_ACCESS_TOKEN` logs as `static-token`. `MCP_ALLOWED_SUBJECTS` optionally restricts who may sign in (unset = PocketID's groups remain the only gate). Access tokens last 24h (`MCP_OAUTH_TOKEN_TTL_S`) and are renewed with refresh tokens lasting 30 days (`MCP_OAUTH_REFRESH_TTL_S`) that **rotate on every use**; replaying a rotated token revokes its whole family (`revokeFamily()`, tracked via `consumedRefreshTokens`) and logs `oauth_refresh_reuse_detected`. The admin-tier `vmhq_sessions` tool lists and revokes active sessions — its store is injected through `CreateMcpServerOptions.sessions` so `mcp.ts` never imports the OAuth module. OAuth client registrations, authorization codes (5 min TTL), pending PocketID transactions (`pendingAuth`, 10 min TTL), access token hashes, refresh tokens and consumed-refresh records persist to `MCP_OAUTH_STATE_PATH` (default `./data/oauth-state.json`). Authorization codes and pending transactions are single-use. `/oauth/register` is public by design for Dynamic Client Registration, while registration still validates HTTPS redirect URIs and is rate-limited in memory. Because that makes any stranger able to register a client and ask the one person who can sign in to approve it, `MCP_ALLOWED_REDIRECT_HOSTS` restricts which hosts may receive an authorization code (`isAllowedRedirectTarget()`, enforced at registration and re-checked at `/oauth/authorize` so clients persisted earlier cannot bypass it; loopback and private-use schemes are always allowed since they deliver to a local app). When it is unset every host is accepted and `loadConfig()` logs `oauth_redirect_allowlist_not_configured` at startup. The consent page (`renderAuthorizeConsent()`) leads with the redirect destination and with `config.grantSummary` — what the token can actually reach, built by `describeGrants()` — because `client_name` is self-reported by the registrant and is shown as unverified. OAuth (including `/oauth/callback`, sharing the `oauth_authorize` bucket) and `/mcp` routes are rate-limited in memory using `CF-Connecting-IP`, `X-Real-IP`, or `X-Forwarded-For`; set `MCP_TRUST_PROXY=false` (default `true`) to ignore those headers if the server is ever reachable without a trusted reverse proxy in front of it, since they're otherwise spoofable and would let a caller dodge per-IP limits. `MCP_ALLOWED_HOSTS` (comma-separated Host header values) turns on the MCP transport's DNS-rebinding protection, with `allowedOrigins` derived from `MCP_PUBLIC_URL`; it is opt-in because deriving the host automatically would make `/mcp` reject everything the moment a reverse proxy forwards a different `Host`. The `/mcp` preflight no longer falls back to `Access-Control-Allow-Origin: *` when `MCP_CORS_ORIGIN` is unset (the OAuth endpoints keep their `*`, which discovery needs). `verifyAccessToken()` takes the resource identifiers this server answers for and rejects a token bound to any other audience (RFC 8707 §2); tokens with no `resource` are unaffected. `exchangeToken()` also refuses a code whose client is no longer registered. A failed authentication consumes a separate `mcp_auth_failure` bucket (10/min per IP) instead of the general `/mcp` allowance, and `POCKETID_ISSUER` must use https unless it points at a private host.

`MCP_PORT` (default `3010`), `MCP_CORS_ORIGIN`, `MCP_UPSTREAM_TIMEOUT_MS`, `MCP_LOG_LEVEL`, `MCP_PUBLIC_URL`, and `MCP_ICON_URL` tune runtime behavior.

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