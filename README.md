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
- NextDNS
- Paperless-ngx

Each service's real URL is configured only in `.env`. Every service is optional: if you don't define its `*_BASE_URL`, the MCP server starts normally and simply doesn't register that service's tools.

Each service exposes three tool types:

- `*_api_reference`: lists the documented operations the MCP knows about.
- `*_operation`: executes a documented operation by `operationId`.
- `*_request`: calls any relative endpoint as an escape hatch for new or uncatalogued endpoints.

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
MCP_ICON_URL=https://cdn.jsdelivr.net/gh/selfhst/icons/png/mcphub.png
MCP_ACCESS_TOKEN=change-me

# Service base URLs
# Leave a URL empty to disable that service.
HOME_ASSISTANT_BASE_URL=https://home-assistant.example.com
MINIFLUX_BASE_URL=https://miniflux.example.com
KARAKEEP_BASE_URL=https://karakeep.example.com
SEARXNG_BASE_URL=https://searxng.example.com
PROXMOX_BASE_URL=https://proxmox.example.com
MEMOS_BASE_URL=https://memos.example.com
NEXTDNS_BASE_URL=https://api.nextdns.io
PAPERLESS_BASE_URL=https://paperless.example.com

# Service credentials
HOME_ASSISTANT_TOKEN=
MINIFLUX_TOKEN=
KARAKEEP_TOKEN=
MEMOS_TOKEN=
NEXTDNS_API_KEY=
NEXTDNS_PROFILE_ID=your-profile-id
PAPERLESS_TOKEN=

# Proxmox API token
# Token ID format: USER@REALM!TOKENID
PROXMOX_TOKEN_ID=root@pam!mcp
PROXMOX_TOKEN_SECRET=

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
# MCP_OAUTH_STATE_PATH=/app/data/oauth-state.json
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

In the browser authorization form, enter your server `MCP_ACCESS_TOKEN` (not an OAuth access token). After you click **Authorize**, you should briefly see a “Connected” page and then return to Claude automatically. If OAuth fails after a server reset or state wipe, remove the connector in Claude and add it again so it re-registers.

Claude.ai registers `https://claude.ai/api/mcp/auth_callback` as its web redirect URI. Older clients may send `https://claude.ai/callback`; the server maps that alias to the canonical callback automatically.

Do not paste `MCP_ACCESS_TOKEN` into Claude's advanced OAuth Client ID/Secret fields. That token is still available for clients that support direct bearer tokens, such as `curl` testing or Codex-style configurations.

## MCP tools

`vmhq_status` is always available and shows which services are enabled or disabled.

For each service:

- `home_assistant_api_reference`, `home_assistant_operation`, `home_assistant_request`
- `miniflux_api_reference`, `miniflux_operation`, `miniflux_request`
- `karakeep_api_reference`, `karakeep_operation`, `karakeep_request`
- `searxng_api_reference`, `searxng_operation`, `searxng_request`
- `proxmox_api_reference`, `proxmox_operation`, `proxmox_request`
- `memos_api_reference`, `memos_operation`, `memos_request`
- `nextdns_api_reference`, `nextdns_operation`, `nextdns_request`
- `paperless_api_reference`, `paperless_operation`, `paperless_request`
- `paperless_upload_start`, `paperless_upload_chunk`, `paperless_upload_finish`, `paperless_upload_abort` for chunked Paperless document uploads

Recommended agent workflow:

1. Call `*_api_reference` with `group` or `search`.
2. Pick an `operationId`.
3. Run `*_operation` with `pathParams`, `query`, and/or `body`.
4. Use `*_request` only when the service's documentation has an endpoint not yet in the local catalogue.

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

## Free-form requests

The `*_request` tools accept:

- `method`: `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`.
- `path`: relative path within the service, e.g. `/api/v1/entries`.
- `query`: optional query parameters.
- `body`: optional JSON body.
- `headers`: optional additional headers, filtered to prevent overriding auth headers.

The response returns the status code, useful response headers, and the body as text or JSON.

### Paperless document uploads

For small files, `paperless_operation(operationId="post_document")` and `paperless_request` support multipart bodies with a real base64 payload:

```json
{
  "_multipart": true,
  "title": "Document title",
  "document": {
    "_base64": "<real base64 bytes, not a path>",
    "filename": "document.pdf",
    "contentType": "application/pdf"
  }
}
```

For larger files, use the chunked upload tools:

1. `paperless_upload_start` with filename, optional metadata, and expected size/length.
2. `paperless_upload_chunk` repeatedly with zero-based base64 chunks.
3. `paperless_upload_finish` to validate, assemble, and send the PDF to Paperless.
4. `paperless_upload_abort` to discard a pending upload.

`_base64` and `chunkBase64` must contain real base64 data. Do not pass local paths or `file://` URLs.

## Mirrors

| Platform | URL |
|----------|-----|
| GitHub | https://github.com/vmhq/vmhq-mcp |
| Radicle | `rad:zAW6yz62TaQrWzt992k2QVnxwKrG` — [Radicle Network](https://radicle.network/nodes/rosa.radicle.xyz/rad%3AzAW6yz62TaQrWzt992k2QVnxwKrG) |

## Verified API sources

The local catalogue was built from the official documentation reviewed on 2026-05-13:

- Home Assistant REST API: https://developers.home-assistant.io/docs/api/rest/
- Miniflux API: https://miniflux.app/docs/api.html
- Karakeep API: https://docs.karakeep.app/api/karakeep-api/
- SearXNG Search API: https://docs.searxng.org/dev/search_api.html
- Proxmox VE API viewer/docs: https://pve.proxmox.com/pve-docs/api-viewer/index.html
- Memos API latest: https://usememos.com/docs/api/latest
- NextDNS API: https://nextdns.io/api
- Paperless-ngx REST API: https://docs.paperless-ngx.com/api/
