# vmhq-mcp

MCP remoto para exponer APIs personales a agentes de IA desde un unico punto de entrada.

El servidor protege el endpoint MCP con un bearer token propio (`MCP_ACCESS_TOKEN`) y mantiene las credenciales reales de cada servicio en variables de entorno del lado servidor.

## Servicios incluidos

- Home Assistant
- Miniflux
- Karakeep
- SearXNG
- Proxmox
- Memos
- NextDNS

Las URLs reales de cada servicio se configuran solo en `.env`. Cada servicio es opcional: si no defines su `*_BASE_URL`, el MCP arranca igual y no registra las herramientas de ese servicio.

Cada servicio expone tres tipos de herramientas:

- `*_api_reference`: muestra las operaciones documentadas que conoce el MCP.
- `*_operation`: ejecuta una operacion documentada por `operationId`.
- `*_request`: llama cualquier endpoint relativo como escape hatch para endpoints nuevos o no catalogados.

## Desarrollo local

```bash
bun install
cp .env.example .env
bun run dev
```

El endpoint MCP queda disponible en:

```text
http://localhost:3010/mcp
```

## Docker Compose

```bash
cp .env.example .env
docker compose up -d --build
```

Ejemplo completo:

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

El volumen Docker `vmhq-mcp-data` persiste el estado OAuth (clientes registrados y hashes de tokens) entre reinicios del contenedor.

## .env de ejemplo

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

# Service credentials
HOME_ASSISTANT_TOKEN=
MINIFLUX_TOKEN=
KARAKEEP_TOKEN=
MEMOS_TOKEN=
NEXTDNS_API_KEY=
NEXTDNS_PROFILE_ID=your-profile-id

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

## Configuracion en Codex

Ejemplo de configuracion remota:

```toml
[mcp_servers.vmhq]
url = "https://mcp.example.com/mcp"
bearer_token_env_var = "VMHQ_MCP_ACCESS_TOKEN"
```

El valor de `VMHQ_MCP_ACCESS_TOKEN` debe coincidir con `MCP_ACCESS_TOKEN` en el servidor. `MCP_PUBLIC_URL` es opcional para ejecutar el servidor, pero sirve para documentar y exponer en `/health` la URL publica que deben usar los clientes MCP.

### Marketplace personal para Codex

Este repo incluye un marketplace personal de Codex en `.agents/plugins/marketplace.json` y un plugin wrapper en `plugins/vmhq-mcp/`.

Para instalarlo desde este checkout:

```bash
codex plugin marketplace add /Users/vicentem/Github/vmhq-mcp
```

Para instalarlo desde GitHub:

```bash
codex plugin marketplace add vmhq/vmhq-mcp --ref main
```

En la UI de Codex, usa:

- Origen: `vmhq/vmhq-mcp`
- Referencia de Git: `main`
- Rutas dispersas: dejar vacio

El plugin registra el MCP remoto `https://mcp.vmhq.cl/mcp` y lee el bearer token desde `VMHQ_MCP_API_KEY`. No guarda secretos en el repo.

## Configuracion en Claude

En Claude, agrega un conector personalizado con:

```text
https://mcp.example.com/mcp
```

Deja vacios los campos avanzados de OAuth Client ID y OAuth Client Secret. El servidor publica metadata OAuth y soporta Dynamic Client Registration publico en `/oauth/register`, por lo que Claude puede registrarse y obtener su token automaticamente antes de la autorizacion.

No pegues `MCP_ACCESS_TOKEN` en los campos OAuth de Claude. Ese token sigue existiendo para clientes que soportan bearer token directo, como pruebas con `curl` o configuraciones tipo Codex.

## Herramientas MCP

`vmhq_status` siempre esta disponible y muestra que servicios estan habilitados o deshabilitados.

Por cada servicio existen:

- `home_assistant_api_reference`, `home_assistant_operation`, `home_assistant_request`
- `miniflux_api_reference`, `miniflux_operation`, `miniflux_request`
- `karakeep_api_reference`, `karakeep_operation`, `karakeep_request`
- `searxng_api_reference`, `searxng_operation`, `searxng_request`
- `proxmox_api_reference`, `proxmox_operation`, `proxmox_request`
- `memos_api_reference`, `memos_operation`, `memos_request`
- `nextdns_api_reference`, `nextdns_operation`, `nextdns_request`

Flujo recomendado para agentes:

1. Consultar `*_api_reference` con `group` o `search`.
2. Elegir un `operationId`.
3. Ejecutar `*_operation` con `pathParams`, `query` y/o `body`.
4. Usar `*_request` solo cuando la documentacion del servicio tenga un endpoint que aun no este en el catalogo local.

Ejemplo:

```json
{
  "operationId": "list_entries",
  "query": {
    "status": "unread",
    "limit": 20
  }
}
```

Ejemplo con parametros de ruta:

```json
{
  "operationId": "qemu_start",
  "pathParams": {
    "node": "pve",
    "vmid": 101
  }
}
```

## Llamadas libres

Las herramientas `*_request` reciben:

- `method`: `GET`, `POST`, `PUT`, `PATCH` o `DELETE`.
- `path`: ruta relativa dentro del servicio, por ejemplo `/api/v1/entries`.
- `query`: parametros opcionales.
- `body`: cuerpo JSON opcional.
- `headers`: headers adicionales opcionales, filtrados para no permitir reemplazar auth.

La respuesta devuelve status, headers utiles y cuerpo en texto o JSON.

## Fuentes de API verificadas

El catalogo local se construyo desde la documentacion oficial revisada el 2026-05-13:

- Home Assistant REST API: https://developers.home-assistant.io/docs/api/rest/
- Miniflux API: https://miniflux.app/docs/api.html
- Karakeep API: https://docs.karakeep.app/api/karakeep-api/
- SearXNG Search API: https://docs.searxng.org/dev/search_api.html
- Proxmox VE API viewer/docs: https://pve.proxmox.com/pve-docs/api-viewer/index.html
- Memos API latest: https://usememos.com/docs/api/latest
- NextDNS API: https://nextdns.io/api
