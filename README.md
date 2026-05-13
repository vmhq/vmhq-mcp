# vmhq-mcp

MCP remoto para exponer APIs personales de VMHQ a agentes de IA desde un unico punto de entrada.

El servidor protege el endpoint MCP con un bearer token propio (`MCP_ACCESS_TOKEN`) y mantiene las credenciales reales de cada servicio en variables de entorno del lado servidor.

## Servicios incluidos

- Home Assistant: `https://iot.vmhq.cl`
- Miniflux: `https://miniflux.vmhq.cl`
- Karakeep: `https://karakeep.vmhq.cl`
- SearXNG: `https://searx.vmhq.cl`
- Proxmox: `https://pve.vmhq.cl`
- Memos: `https://memos.vmhq.cl`

Cada servicio expone una herramienta MCP generica `*_request` para llamar cualquier endpoint de su API sin entregar los tokens al agente.

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

## Configuracion en Codex

Ejemplo de configuracion remota:

```toml
[mcp_servers.vmhq]
url = "https://tu-dominio/mcp"
bearer_token_env_var = "VMHQ_MCP_ACCESS_TOKEN"
```

El valor de `VMHQ_MCP_ACCESS_TOKEN` debe coincidir con `MCP_ACCESS_TOKEN` en el servidor.

## Herramientas MCP

- `home_assistant_request`
- `miniflux_request`
- `karakeep_request`
- `searxng_request`
- `proxmox_request`
- `memos_request`

Todas reciben:

- `method`: `GET`, `POST`, `PUT`, `PATCH` o `DELETE`.
- `path`: ruta relativa dentro del servicio, por ejemplo `/api/v1/entries`.
- `query`: parametros opcionales.
- `body`: cuerpo JSON opcional.
- `headers`: headers adicionales opcionales, filtrados para no permitir reemplazar auth.

La respuesta devuelve status, headers utiles y cuerpo en texto o JSON.
