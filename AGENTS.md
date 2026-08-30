# AGENTS.md

See also `CLAUDE.md` for architecture, request flow, auth modes, and adding new services.

## Runtime

Bun only. There is no Node.js fallback, no `npm`, no `npx`. All scripts use `bun`.

```bash
bun install       # frozen lockfile via bun.lock
bun run dev       # bun --watch src/index.ts (hot reload)
bun run start     # bun src/index.ts (production)
bun run typecheck # tsc --noEmit (no compilation output)
bun test          # bun test
```

The `build` script is a misnomer — it only type-checks. There is no compilation step, no `dist/` directory. Bun runs `.ts` files directly from `src/`.

Correctness gates are `bun run typecheck` and `bun test`. The current test suite covers OAuth behavior and service client URL/auth/error handling under `tests/`. CI runs both gates before building the Docker image.

## Auth modes

| type | behavior |
|------|----------|
| bearer | `Authorization: Bearer ***` |
| header | Custom header name (e.g., `X-Auth-Token`) |
| prefixed | `Authorization: ***` (Proxmox PVEAPIToken= style) |
| static | Fixed header name/value pair built at startup |
| none | No auth header added |

## Environment variables

Only `MCP_ACCESS_TOKEN` is required at startup (server crashes without it). All other env vars are optional. `MCP_PORT` sets the listen port (defaults to `3010`).

A service is silently **disabled** when its `*_BASE_URL` is empty or unset. No error, no tools registered. Registry entries with `enabledWhenEnv` are disabled unless that env var is present. Service tokens are read lazily at request time from `process.env` — missing tokens produce a normalized `missing_upstream_credentials` tool error instead of crashing.

`PROXMOX_INSECURE_TLS=true` disables TLS certificate verification for the Proxmox upstream only, for nodes serving the self-signed PVE cluster CA on `:8006`. It is resolved declaratively via `insecureTlsEnv` in `serviceRegistry.ts` and applied as a per-request `tls: { rejectUnauthorized: false }` option on that service's `fetch`, so every other upstream keeps verifying normally (unlike the process-wide `NODE_TLS_REJECT_UNAUTHORIZED=0`). `readInsecureTls()` throws at startup if the flag is set while the base URL points at a public host, as checked by `isPrivateHost()`.

`PROXMOX_SSH_HOST` enables SSH shell tools for the Proxmox node (`proxmox_lxc_list`, `proxmox_lxc_exec`, `proxmox_node_exec`, `proxmox_job_status`), implemented in `src/sshClient.ts` on top of the `ssh2` client. This is the one upstream that is not HTTP: the Proxmox REST API has no exec endpoint for LXC containers, so commands run inside a container go over SSH via `pct exec`. `createMcpServer()` takes a `ToolTier`: `index.ts` maps `/mcp` to `"admin"` and `/mcp/read` to `"read"`, and the read tier never registers `proxmox_lxc_exec` / `proxmox_node_exec`, so a session that ingests untrusted text (search results, RSS, bookmarks) has no shell tool for an injected instruction to call. The tools expose an unrestricted remote shell by design — the agent is meant to maintain the node — so the SSH credential is the security boundary, not the tool surface. Credentials (`PROXMOX_SSH_KEY`, `PROXMOX_SSH_KEY_PATH`, `PROXMOX_SSH_KEY_PASSPHRASE`, `PROXMOX_SSH_PASSWORD`) are read lazily at request time like service tokens, so a missing key produces a normalized `missing_upstream_credentials` error. `loadProxmoxSshConfig()` throws at startup when the node is public and `PROXMOX_SSH_HOST_FINGERPRINT` is unset, reusing `isPrivateHost()` the same way `PROXMOX_INSECURE_TLS` does. `PROXMOX_SSH_ALLOWED_VMIDS` optionally restricts which containers `proxmox_lxc_exec` can reach, `PROXMOX_SSH_SUDO=true` wraps commands in `sudo -n /bin/sh -c` for non-root users (which elevates but cannot restrict: a per-binary sudoers rule is useless against `sh -c '<arbitrary>'`, so narrowing has to come from the credential — a dedicated node user or a forced `command=` in `authorized_keys`), and `PROXMOX_SSH_TIMEOUT_MS` / `PROXMOX_SSH_MAX_OUTPUT` bound each call. Both exec tools accept `background: true`, which detaches the command (`setsid`, falling back to `nohup`) and returns a `jobId` instead of waiting: the ceiling on a long command is the MCP client's own timeout, not `PROXMOX_SSH_TIMEOUT_MS`, so raising `timeoutMs` cannot fix it. `backgroundScript()` writes the job's pid, output and exit code under `PROXMOX_SSH_JOB_DIR` (default `/var/log/vmhq-mcp`) and runs the command in a subshell so an `exit` in it does not stop the wrapper from recording the status; `proxmox_job_status` reads them back via `jobStatusScript()` / `parseJobStatus()` as `starting` / `running` / `finished` / `orphaned` / `not_found`. Files age out after `PROXMOX_SSH_JOB_RETENTION_DAYS` (default 30, `0` disables): `jobPurgeCommand()` runs from the launcher rather than a timer, since the server keeps no state between requests, and it matches only the `.log` / `.pid` / `.status` names a job creates. Job IDs are minted by the server and validated against `JOB_ID_PATTERN` before they reach a path. Commands built for `pct exec` are single-quoted through `shellQuote()`, so a command string can never break out of its argument. The interpreter itself is the other half of that guarantee: `PROXMOX_SSH_CONTAINER_SHELL` and the per-call `shell` argument are restricted to a plain absolute path by `isAllowedShell()` (rejected at startup and at the tool boundary via `assertShellAllowed()`, and refused again inside `lxcCommand()` / `backgroundScript()`), because an unvalidated shell would be spliced into the node-level command and escape both the container and `PROXMOX_SSH_ALLOWED_VMIDS`. Every call is logged as `ssh_exec_started` / `ssh_exec_finished` / `ssh_exec_failed`.

`sshKnownHosts.ts` pins the node's SSH host key on first use when `PROXMOX_SSH_HOST_FINGERPRINT` is unset, recording it at `PROXMOX_SSH_KNOWN_HOSTS_PATH` (default `./data/proxmox-known-hosts.json`, written atomically at `0600` like the OAuth state) and refusing a later key change with `ssh_host_key_mismatch`; an explicit fingerprint always wins, and an unwritable store logs `ssh_host_key_pin_failed` rather than blocking the connection. `redactCommand()` masks known secret shapes and truncates to 200 characters before a command reaches the `ssh_exec_*` logs — the response to the caller keeps the full command. `callService()` follows redirects manually (`redirect: "manual"`, GET only, max 3 hops) and refuses any hop that leaves the configured origin with `upstream_redirect_blocked`: fetch strips `Authorization` cross-origin but not header-named credentials like Miniflux's `X-Auth-Token`, and `buildUrl()`'s origin check only covers the first URL.

`HOME_ASSISTANT_PINNED_ENTITIES` is an optional comma-separated list of Home Assistant entity IDs, each with an optional `:Alias` suffix:

```
HOME_ASSISTANT_PINNED_ENTITIES=light.tira_led_tv:RGB TV,switch.tv,sensor.temperatura_exterior:Temp Exterior
```

When set, a `home_assistant_pinned_entities` tool is registered that fetches those entity states in parallel. The tool description lists all aliases so the agent can identify entities by friendly name before calling the tool. When unset, the tool is not registered and there is no overhead.

The `static` auth type (used by Proxmox) sets a fixed `headerName: value` pair directly at startup (no env lookup at request time).

Miniflux auth mode is controlled by `MINIFLUX_AUTH_MODE`:
- `x-auth-token` (default) → `X-Auth-Token` header
- `bearer` → standard `Authorization: ***` header

## OAuth, rate limiting, and security headers

`src/oauth.ts` (implementation under `src/oauth/`) makes the server an OAuth bridge: it implements OAuth metadata, public dynamic client registration (`/oauth/register`), authorization-code + PKCE exchange, token revocation, and protected-resource challenges, while delegating the interactive user login to a PocketID OIDC instance (`src/oauth/pocketid.ts`). `GET /oauth/authorize` redirects the browser to PocketID; `GET /oauth/callback` exchanges the PocketID code and issues the MCP authorization code. There is no static-token authorization form anymore. Because registration is public, `MCP_ALLOWED_REDIRECT_HOSTS` restricts which hosts may receive an authorization code (`isAllowedRedirectTarget()`, enforced at registration and re-checked at `/oauth/authorize`; loopback and private-use schemes always pass, and an unset value accepts every host and logs `oauth_redirect_allowlist_not_configured` at startup). The consent page leads with the redirect destination and with `config.grantSummary` from `describeGrants()`, since `client_name` is self-reported. PocketID is configured via `POCKETID_ISSUER` / `POCKETID_CLIENT_ID` / `POCKETID_CLIENT_SECRET` (optional `POCKETID_SCOPES`, default `openid profile email`); register `<MCP_PUBLIC_URL>/oauth/callback` as the OIDC client redirect URI. The verified `id_token` identity (`sub`/`email`) is bound to the token and named in every log line as `actor` (`legacy` for tokens predating this, `static-token` for `MCP_ACCESS_TOKEN`); `MCP_ALLOWED_SUBJECTS` optionally gates who may sign in. Access tokens last 24h and rotate through refresh tokens (30d) whose replay revokes the whole family; `vmhq_sessions` (admin tier) lists and revokes sessions. Client registrations, short-lived authorization codes (5 min TTL), pending PocketID transactions (`pendingAuth`, 10 min TTL), OAuth access token hashes, refresh tokens and consumed-refresh records are persisted to `MCP_OAUTH_STATE_PATH` (defaults to `./data/oauth-state.json`). Authorization codes are single-use and pruned periodically. Stored OAuth access tokens are SHA-256 hashes; `isOAuthAccessToken()` hashes the presented token and checks expiry. Bearer token auth still compares directly against `MCP_ACCESS_TOKEN` for non-OAuth clients. All three PocketID vars must be set together; when any is missing, `/oauth/authorize` returns an error page but the static `MCP_ACCESS_TOKEN` bearer still works for machine access.

`src/rateLimit.ts` applies in-memory per-IP limits to OAuth endpoints and `/mcp`, using `CF-Connecting-IP`, `X-Real-IP`, then `X-Forwarded-For`; set `MCP_TRUST_PROXY=false` (default `true`) to ignore those headers if the server is ever reachable without a trusted reverse proxy in front of it, since they're otherwise spoofable and would let a caller dodge per-IP limits. `src/index.ts` wraps responses with security headers and exposes OAuth discovery endpoints, `/health`, `/icon.svg` (public, same-origin server icon per the MCP `icons` spec field), `/mcp`, and the OpenAPI documentation endpoints (`/openapi.json` and `/docs`, both protected by Bearer auth). OAuth routes (including `/oauth/callback`, sharing the `oauth_authorize` bucket) and `/mcp` are rate-limited in memory. `MCP_PORT` (default `3010`), `MCP_CORS_ORIGIN`, `MCP_UPSTREAM_TIMEOUT_MS`, `MCP_LOG_LEVEL`, `MCP_PUBLIC_URL`, and `MCP_ICON_URL` tune runtime behavior.

## Docker

Image: `ghcr.io/vmhq/vmhq-mcp`. Dockerfile copies source `.ts` files and runs them with `bun` directly (no build step). CI installs dependencies, runs `bun run typecheck`, runs `bun test`, then builds the Docker image. Pushes to `main` publish to GHCR; PRs build but don't push.

## Code conventions

- All imports use `.js` extensions (Bun/NodeNext resolution).
- `src/services.ts` defines the `ServiceAuth` union and `ServiceDefinition` type — every service addition touches this file.
- `src/apiCatalog.ts` exports `API_CATALOGS: Record<ServiceId, ApiCatalog>` — the only runtime data source for `*_api_reference` and `*_operation`.
- `src/serviceRegistry.ts` declares service metadata in one registry; `src/config.ts` maps registry entries to `ServiceDefinition[]` and skips unconfigured services. Each entry carries an optional `pingPath` — a lightweight GET path (e.g. `/api/`) used by `vmhq_status` when called with `ping: true` to verify reachability with a 3 s timeout.
- `src/oauth.ts`, `src/rateLimit.ts`, and `src/logger.ts` are active runtime modules; keep docs and tests aligned when changing auth, request limits, or structured logging.
- `src/openapi.ts` generates the OpenAPI 3.0.3 spec from the enabled service catalogs (`generateOpenApiSpec`) and renders Swagger UI HTML (`renderSwaggerUI`); both `/openapi.json` and `/docs` require Bearer or OAuth authentication.
- Response body parsing in `serviceClient.ts` returns `null` for empty bodies, parsed JSON for `application/json`, raw text otherwise.
