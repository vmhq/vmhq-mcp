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
- Perplexity via OpenRouter (sonar-pro, sonar-reasoning-pro, sonar-deep-research)
- NextDNS

Las URLs reales de cada servicio se configuran solo en `.env`. Cada servicio es opcional: si no defines su `*_BASE_URL` (o su API key en el caso de Perplexity), el MCP arranca igual y no registra las herramientas de ese servicio.

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
      - ./data:/app/data
    restart: unless-stopped
```

El volumen `./data` persiste el estado OAuth (clientes registrados y tokens) entre reinicios del contenedor.

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

# Perplexity via OpenRouter
# Habilita busqueda con los modelos sonar-pro, sonar-reasoning-pro y sonar-deep-research.
# Obtener clave en https://openrouter.ai/keys
OPENROUTER_API_KEY=
# OPENROUTER_BASE_URL=https://openrouter.ai/api/v1  # solo si usas un proxy

# Optional auth/header overrides
MINIFLUX_AUTH_MODE=x-auth-token

# Optional security settings
# Restrict CORS to a specific origin (e.g. https://claude.ai). Defaults to *.
# MCP_CORS_ORIGIN=https://claude.ai
# Path for persisting OAuth state inside the container (matches the ./data:/app/data volume).
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

## Configuracion en Claude

En Claude, agrega un conector personalizado con:

```text
https://mcp.example.com/mcp
```

Deja vacios los campos avanzados de OAuth Client ID y OAuth Client Secret. El servidor publica metadata OAuth y soporta Dynamic Client Registration, por lo que Claude puede registrarse y obtener su token automaticamente.

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
- `perplexity_api_reference`, `perplexity_operation`, `perplexity_request`
- `nextdns_api_reference`, `nextdns_operation`, `nextdns_request`

### Perplexity via OpenRouter

El servicio `perplexity` expone tres operaciones que corresponden a los tres modelos disponibles:

| operationId | Modelo | Velocidad | Cuando usar |
|---|---|---|---|
| `search_sonar_pro` | `perplexity/sonar-pro` | Rapido | Noticias, precios, datos actuales, preguntas directas. **Usar por defecto.** |
| `search_sonar_reasoning_pro` | `perplexity/sonar-reasoning-pro` | Medio | Comparaciones, sintesis de fuentes contradictorias, recomendaciones con justificacion logica. |
| `deep_research` | `perplexity/sonar-deep-research` | Lento | Informes de mercado, revision de literatura, investigaciones con muchas fuentes citadas. |

Las respuestas incluyen citas inline (`[1]`, `[2]`, ...) en el contenido y un array `citations` con las URLs en la raiz de la respuesta.

Al final de cada respuesta entregada al usuario debe aparecer la firma:

```
Elaborado con Perplexity [Nombre del modelo]
```

Ejemplos: `Elaborado con Perplexity Sonar Pro` / `Elaborado con Perplexity Sonar Reasoning Pro` / `Elaborado con Perplexity Sonar Deep Research`.

Ejemplo de llamada con `perplexity_operation`:

```json
{
  "operationId": "search_sonar_pro",
  "body": {
    "model": "perplexity/sonar-pro",
    "messages": [{ "role": "user", "content": "¿Cual es el precio actual del Bitcoin?" }],
    "max_tokens": 1024
  }
}
```

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
- OpenRouter API: https://openrouter.ai/docs
- NextDNS API: https://nextdns.io/api
