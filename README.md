# vmhq-mcp

Remote MCP server that exposes personal self-hosted APIs to AI agents from a single authenticated entry point.

The server protects the MCP endpoint with its own bearer token (`MCP_ACCESS_TOKEN`) and keeps real service credentials in server-side environment variables.

## Included services

- Home Assistant
- Miniflux
- Karakeep
- SearXNG
- Proxmox
- Memos
- AdGuard Home

Each service's real URL is configured only in `.env`. Every service is optional: if you don't define its `*_BASE_URL`, the MCP server starts normally and simply doesn't register that service's tools.

Each service exposes three tool types:

- `*_api_reference`: lists the documented operations the MCP knows about.
- `*_operation`: executes a documented operation by `operationId`.
- `*_request`: calls any relative endpoint as an escape hatch for new or uncatalogued endpoints.

Proxmox additionally supports optional SSH shell tools, so an agent can maintain the node and its LXC containers. See [Proxmox SSH](#proxmox-ssh).

## Local development

```bash
bun install
cp .env.example .env
bun run dev
```

The MCP endpoint is available at:

```text
http://localhost:3010/mcp
```

The server also exposes an OpenAPI 3.0.3 specification and an interactive Swagger UI for discovering the available tools and endpoints. These endpoints are protected by the same `MCP_ACCESS_TOKEN` (Bearer auth) as the main `/mcp` endpoint:

- `GET /openapi.json` — Live OpenAPI specification scoped to currently configured services.
- `GET /docs` — Interactive Swagger UI.

## Docker Compose

```bash
cp .env.example .env
docker compose up -d --build
```

Full example:

```yaml
services:
  vmhq-mcp:
    image: ghcr.io/vmhq/vmhq-mcp:latest
    env_file:
      - path: .env
        required: false
    ports:
      - "${HOST_PORT:-3010}:${MCP_PORT:-3010}"
    volumes:
      - vmhq-mcp-data:/app/data
    restart: unless-stopped

volumes:
  vmhq-mcp-data:
```

The `vmhq-mcp-data` Docker volume persists OAuth state (registered clients, short-lived authorization codes, and token hashes) across container restarts.

## Example .env

```dotenv
# MCP server
MCP_PORT=3010
HOST_PORT=3010
MCP_PUBLIC_URL=https://mcp.example.com
# Optional. Defaults to <MCP_PUBLIC_URL>/icon.svg (served same-origin, per the MCP icons spec).
# Set only to override with a different icon.
# MCP_ICON_URL=https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/lovable.svg
# Required. Minimum 32 characters; the server refuses to start with a weaker token.
# Generate one with: openssl rand -base64 48
MCP_ACCESS_TOKEN=change-me

# PocketID identity provider (interactive OAuth login)
# When all three are set, the OAuth authorize flow delegates user authentication
# to your PocketID instance. The static MCP_ACCESS_TOKEN bearer keeps working
# for machine-to-machine access. In PocketID, create an OIDC client and register
# this redirect/callback URI: <MCP_PUBLIC_URL>/oauth/callback
# Restrict who can sign in via the OIDC client's allowed groups in PocketID.
POCKETID_ISSUER=https://id.example.com
POCKETID_CLIENT_ID=
POCKETID_CLIENT_SECRET=
# Optional OIDC scopes (space-separated). Defaults to "openid profile email".
# POCKETID_SCOPES=openid profile email

# Service base URLs
# Leave a URL empty to disable that service.
HOME_ASSISTANT_BASE_URL=https://home-assistant.example.com
MINIFLUX_BASE_URL=https://miniflux.example.com
KARAKEEP_BASE_URL=https://karakeep.example.com
SEARXNG_BASE_URL=https://searxng.example.com
PROXMOX_BASE_URL=https://proxmox.example.com
MEMOS_BASE_URL=https://memos.example.com
ADGUARD_BASE_URL=https://adguard.example.com

# Service credentials
HOME_ASSISTANT_TOKEN=
# Pinned Home Assistant entities — comma-separated entity_id, optionally with :Alias suffix.
# Activates home_assistant_pinned_entities tool so agents skip the full get_states call.
# HOME_ASSISTANT_PINNED_ENTITIES=light.tira_led_tv:RGB TV,switch.tv,sensor.temperatura_exterior:Temp Exterior
MINIFLUX_TOKEN=
KARAKEEP_TOKEN=
MEMOS_TOKEN=
ADGUARD_USERNAME=
ADGUARD_PASSWORD=

# Proxmox API token
# Token ID format: USER@REALM!TOKENID
PROXMOX_TOKEN_ID=root@pam!mcp
PROXMOX_TOKEN_SECRET=
# Skip TLS verification for Proxmox only (self-signed PVE cluster CA on :8006).
# Only accepted when PROXMOX_BASE_URL points at a private-network host.
# PROXMOX_INSECURE_TLS=true

# Proxmox SSH (shell access for a maintainer agent)
# Setting PROXMOX_SSH_HOST registers proxmox_lxc_list, proxmox_lxc_exec and
# proxmox_node_exec. The Proxmox REST API has no exec endpoint for LXC, so
# running commands inside a container means SSH + pct exec on the node.
# WARNING: these tools are an unrestricted shell on the hypervisor. Whoever can
# call /mcp can run anything the SSH user can run. Scope the SSH credential
# itself (dedicated user + restricted sudoers) if you want narrower access.
# PROXMOX_SSH_HOST=192.168.1.10
# PROXMOX_SSH_PORT=22
# PROXMOX_SSH_USER=root
# One of the three below. The key never leaves the server.
# PROXMOX_SSH_KEY_PATH=/app/data/ssh/id_ed25519
# PROXMOX_SSH_KEY="-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"
# PROXMOX_SSH_KEY_PASSPHRASE=
# PROXMOX_SSH_PASSWORD=
# Pinned host key, OpenSSH format. Required when the node is not on a private
# network. Get it with: ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -
# PROXMOX_SSH_HOST_FINGERPRINT=SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Set true when PROXMOX_SSH_USER is not root; commands run via sudo -n.
# PROXMOX_SSH_SUDO=false
# Restrict which containers proxmox_lxc_exec can reach. Empty means all of them.
# PROXMOX_SSH_ALLOWED_VMIDS=101,102
# Default shell used inside containers. Alpine guests have no bash.
# PROXMOX_SSH_CONTAINER_SHELL=/bin/sh
# Per-command timeout and output cap. Defaults: 120000 ms and 30000 characters.
# PROXMOX_SSH_TIMEOUT_MS=120000
# PROXMOX_SSH_MAX_OUTPUT=30000

# Optional auth/header overrides
MINIFLUX_AUTH_MODE=x-auth-token

# Optional runtime/security settings
# Restrict CORS to a specific origin (e.g. https://claude.ai). Defaults to *.
# MCP_CORS_ORIGIN=https://claude.ai
# Timeout for upstream API calls. Defaults to 30000.
# MCP_UPSTREAM_TIMEOUT_MS=30000
# Structured log level: silent, error, info, debug. Defaults to info.
# MCP_LOG_LEVEL=info
# Path for persisting OAuth state inside the container (matches the vmhq-mcp-data:/app/data Docker volume).
# Stored OAuth access tokens are persisted as SHA-256 hashes.
# The data/ directory is gitignored — runtime OAuth state must never be committed.
# MCP_OAUTH_STATE_PATH=/app/data/oauth-state.json
# Access token lifetime in seconds for OAuth-issued tokens. Defaults to 2592000 (30 days).
# MCP_OAUTH_TOKEN_TTL_S=2592000
# Whether to trust reverse-proxy IP headers for per-IP rate limiting. Defaults to true.
# Set to false if this server is ever reachable without a trusted reverse proxy in front
# of it, since those headers are otherwise spoofable and let a caller dodge rate limits.
# When false, rate limits are keyed by the real socket IP instead.
# MCP_TRUST_PROXY=true
```

## Codex configuration

Remote configuration example:

```toml
[mcp_servers.vmhq]
url = "https://mcp.example.com/mcp"
bearer_token_env_var = "VMHQ_MCP_ACCESS_TOKEN"
```

The value of `VMHQ_MCP_ACCESS_TOKEN` must match `MCP_ACCESS_TOKEN` on the server. `MCP_PUBLIC_URL` is optional for running the server, but it documents and exposes the public URL that MCP clients should use, visible at `/health`.

### Personal Codex marketplace

This repo includes a personal Codex marketplace at `.agents/plugins/marketplace.json` and a wrapper plugin at `plugins/vmhq-mcp/`.

To install from this checkout:

```bash
codex plugin marketplace add /Users/vicentem/Github/vmhq-mcp
```

To install from GitHub:

```bash
codex plugin marketplace add vmhq/vmhq-mcp --ref main
```

In the Codex UI, use:

- Source: `vmhq/vmhq-mcp`
- Git ref: `main`
- Sparse paths: leave empty

The plugin registers the remote MCP at `https://mcp.vmhq.cl/mcp` and reads the bearer token from `VMHQ_MCP_API_KEY`. No secrets are stored in the repo.

## Claude configuration

In Claude, add a custom connector pointing to:

```text
https://mcp.example.com/mcp
```

Leave the advanced OAuth Client ID and OAuth Client Secret fields empty. The server publishes OAuth metadata and supports public Dynamic Client Registration at `/oauth/register`, so Claude can register itself and obtain a token automatically before authorization.

When you click **Authorize**, the server redirects you to your **PocketID** instance to sign in (passkey). After a successful PocketID login you briefly see a “Connected” page and return to Claude automatically. If OAuth fails after a server reset or state wipe, remove the connector in Claude and add it again so it re-registers.

Claude.ai registers `https://claude.ai/api/mcp/auth_callback` as its web redirect URI. Older clients may send `https://claude.ai/callback`; the server maps that alias to the canonical callback automatically.

`MCP_ACCESS_TOKEN` is still available as a direct bearer token for clients that support it (e.g. `curl` testing or Codex-style configurations). Do not paste it into Claude's advanced OAuth Client ID/Secret fields.

### PocketID setup

The interactive OAuth login delegates user authentication to a self-hosted [PocketID](https://pocket-id.org/docs/introduction) instance via OIDC. The MCP server stays the OAuth authorization server toward MCP clients (DCR + PKCE + token issuance); it adds PocketID only as the upstream identity provider for the human login step.

1. In PocketID, create a new **OIDC client** for vmhq-mcp.
2. Register the callback/redirect URI: `<MCP_PUBLIC_URL>/oauth/callback` (e.g. `https://mcp.example.com/oauth/callback`).
3. Restrict who can sign in by assigning the allowed user groups to that OIDC client in PocketID.
4. Copy the generated **Client ID** and **Client Secret** into `POCKETID_CLIENT_ID` / `POCKETID_CLIENT_SECRET`, and set `POCKETID_ISSUER` to your PocketID base URL.

If the `POCKETID_*` vars are not set, the interactive `/oauth/authorize` flow returns an error page; the static `MCP_ACCESS_TOKEN` bearer still works for machine access.

## MCP tools

`vmhq_status` is always available and shows which services are enabled or disabled.

For each service:

- `home_assistant_api_reference`, `home_assistant_operation`, `home_assistant_request`
- `home_assistant_pinned_entities` — fetches your configured pinned entities in parallel (enabled by `HOME_ASSISTANT_PINNED_ENTITIES`)
- `miniflux_api_reference`, `miniflux_operation`, `miniflux_request`
- `karakeep_api_reference`, `karakeep_operation`, `karakeep_request`
- `searxng_api_reference`, `searxng_operation`, `searxng_request`
- `proxmox_api_reference`, `proxmox_operation`, `proxmox_request`
- `proxmox_lxc_list`, `proxmox_lxc_exec`, `proxmox_node_exec` — SSH shell tools (enabled by `PROXMOX_SSH_HOST`)
- `memos_api_reference`, `memos_operation`, `memos_request`
- `adguard_api_reference`, `adguard_operation`, `adguard_request`

Recommended agent workflow:

1. For Home Assistant, call `home_assistant_pinned_entities` first to get the IDs and current state of your most-used entities (if configured).
2. Call `*_api_reference` with `group` or `search` to discover available operations.
3. Pick an `operationId`.
4. Run `*_operation` with `pathParams`, `query`, and/or `body`.
5. Use `*_request` only when the service's documentation has an endpoint not yet in the local catalogue.

Example:

```json
{
  "operationId": "list_entries",
  "query": {
    "status": "unread",
    "limit": 20
  }
}
```

Example with path parameters:

```json
{
  "operationId": "qemu_start",
  "pathParams": {
    "node": "pve",
    "vmid": 101
  }
}
```

## Proxmox SSH

The Proxmox REST API has no exec endpoint for LXC containers — only QEMU guests expose one, through the guest agent. Running a command inside a container therefore means SSHing into the node and calling `pct exec`. Setting `PROXMOX_SSH_HOST` enables three tools for that:

- `proxmox_lxc_list` — runs `pct list` and returns the containers as JSON (`vmid`, `status`, `lock`, `name`).
- `proxmox_lxc_exec` — runs a shell command inside a container: `pct exec <vmid> -- /bin/sh -c '<command>'`.
- `proxmox_node_exec` — runs a shell command on the node itself (`pveversion`, `systemctl`, `journalctl`, `apt`, `zfs`, …).

Both exec tools take a full command string interpreted by a remote shell, so pipes, redirects, `&&` and heredocs work as typed. They also accept `stdin` (handy for writing files with `tee`), a per-call `timeoutMs`, and `maxLength` to cap output. Non-zero exit codes come back as a normal result with `exitCode`, `stdout` and `stderr`; only transport problems (timeout, auth, host key, connection) are returned as errors.

```json
{
  "vmid": 101,
  "command": "systemctl restart nginx && systemctl is-active nginx"
}
```

**These tools are a real shell on the hypervisor.** Anyone who can call `/mcp` can run anything the SSH user can run — that is the point when the agent is the node's maintainer, but it means the SSH credential, not the tool surface, is the security boundary. Recommended setup:

- Give the MCP its own SSH key, used by nothing else, and mount it read-only (`PROXMOX_SSH_KEY_PATH`).
- To narrow access below root, create a dedicated node user, grant it exactly the commands you want in `sudoers`, and set `PROXMOX_SSH_SUDO=true`.
- Set `PROXMOX_SSH_ALLOWED_VMIDS` when the agent only maintains some containers.
- Pin the node's host key with `PROXMOX_SSH_HOST_FINGERPRINT`. It is required when the node is not on a private network, and the server refuses to start without it there.
- Every command is logged as a structured `ssh_exec_started` / `ssh_exec_finished` event, so `MCP_LOG_LEVEL=info` gives you an audit trail.

Each command opens its own SSH connection; nothing is kept between requests, matching the stateless design of the rest of the server.

## Free-form requests

The `*_request` tools accept:

- `method`: `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`.
- `path`: relative path within the service, e.g. `/api/v1/entries`.
- `query`: optional query parameters.
- `body`: optional JSON body.
- `headers`: optional additional headers, filtered to prevent overriding auth headers.

The response returns the status code, useful response headers, and the body as text or JSON.

## Mirrors

| Platform | URL |
|----------|-----|
| GitHub | https://github.com/vmhq/vmhq-mcp |

## Verified API sources

The local catalogue was built from the official documentation reviewed on 2026-05-13:

- Home Assistant REST API: https://developers.home-assistant.io/docs/api/rest/
- Miniflux API: https://miniflux.app/docs/api.html
- Karakeep API: https://docs.karakeep.app/api/karakeep-api/
- SearXNG Search API: https://docs.searxng.org/dev/search_api.html
- Proxmox VE API viewer/docs: https://pve.proxmox.com/pve-docs/api-viewer/index.html
- Memos API latest: https://usememos.com/docs/api/latest
- AdGuard Home API (OpenAPI spec): https://github.com/AdguardTeam/AdGuardHome/tree/master/openapi
