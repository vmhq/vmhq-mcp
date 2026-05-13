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

Las URLs reales de cada servicio se configuran solo en `.env`.

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
      - .env
    ports:
      - "${HOST_PORT:-3010}:${MCP_PORT:-3010}"
    restart: unless-stopped
```

## .env de ejemplo

```dotenv
# MCP server
MCP_PORT=3010
HOST_PORT=3010
MCP_PUBLIC_URL=https://mcp.example.com
MCP_ACCESS_TOKEN=change-me

# Service base URLs
HOME_ASSISTANT_BASE_URL=https://home-assistant.example.com
MINIFLUX_BASE_URL=https://miniflux.example.com
KARAKEEP_BASE_URL=https://karakeep.example.com
SEARXNG_BASE_URL=https://searxng.example.com
PROXMOX_BASE_URL=https://proxmox.example.com
MEMOS_BASE_URL=https://memos.example.com

# Service credentials
HOME_ASSISTANT_TOKEN=
MINIFLUX_TOKEN=
KARAKEEP_TOKEN=
PROXMOX_TOKEN=
MEMOS_TOKEN=

# Optional auth/header overrides
MINIFLUX_AUTH_MODE=x-auth-token
PROXMOX_AUTH_PREFIX=PVEAPIToken=
```

## Configuracion en Codex

Ejemplo de configuracion remota:

```toml
[mcp_servers.vmhq]
url = "https://mcp.example.com/mcp"
bearer_token_env_var = "VMHQ_MCP_ACCESS_TOKEN"
```

El valor de `VMHQ_MCP_ACCESS_TOKEN` debe coincidir con `MCP_ACCESS_TOKEN` en el servidor. `MCP_PUBLIC_URL` es opcional para ejecutar el servidor, pero sirve para documentar y exponer en `/health` la URL publica que deben usar los clientes MCP.

## Herramientas MCP

Por cada servicio existen:

- `home_assistant_api_reference`, `home_assistant_operation`, `home_assistant_request`
- `miniflux_api_reference`, `miniflux_operation`, `miniflux_request`
- `karakeep_api_reference`, `karakeep_operation`, `karakeep_request`
- `searxng_api_reference`, `searxng_operation`, `searxng_request`
- `proxmox_api_reference`, `proxmox_operation`, `proxmox_request`
- `memos_api_reference`, `memos_operation`, `memos_request`

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
