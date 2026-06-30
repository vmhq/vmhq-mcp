---
name: vmhq-mcp
description: Use when the user asks to work with their personal VMHQ MCP services, including Home Assistant, Miniflux, Karakeep, SearXNG, Proxmox, Memos, and AdGuard Home.
---

# VMHQ MCP

Use the `vmhq` MCP server for personal infrastructure and self-hosted service tasks.

## Services

- Home Assistant: smart home status and control through the MCP tools.
- Miniflux: RSS feed and article workflows.
- Karakeep: saved links and knowledge capture.
- SearXNG: private metasearch.
- Proxmox: VM and node operations.
- Memos: notes and memo workflows.
- AdGuard Home: DNS filtering, query log, stats, and DHCP operations.

## Workflow

1. Start with `vmhq_status` to confirm which services are enabled.
2. Use each service's `*_api_reference` tool before calling `*_operation`.
3. Prefer `*_operation` with a documented `operationId`.
4. Use `*_request` only when a needed endpoint is not yet in the local API catalog.

The plugin does not include secrets. Codex reads the bearer token from `VMHQ_MCP_API_KEY`.
