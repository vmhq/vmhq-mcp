# Security remediation — 2026-09-04

Baseline: `ceaedfba980c40ad49b75178c1d0aea81a21e479`.

## Implementation plan and completion

1. **Completed — browser-bound OAuth consent.** Create an unapproved transaction with a browser-secret hash. Show the client name and destination only (the capability list was removed: the page is reachable by any registrant and disclosed the node address and service inventory). Require a same-origin POST with that transaction's HttpOnly, SameSite=Lax cookie before producing the PocketID redirect. Require the same cookie and prior approval at callback, before exchanging the provider code. HTTPS responses set Secure on the cookie. Reject legacy pending transactions without a browser binding.
2. **Completed — read-tier request policy.** Match the normalized URL against catalogued non-destructive GET paths, reject unknown routes, and reject Miniflux `update_content` values other than `false` (absence is allowed). Apply the same policy to operation, generic request and redirect hops. Mark AdGuard logout destructive.
3. **Completed — fail-closed SSH host verification.** Only ENOENT permits a new store. Invalid JSON, invalid entries, read failures and write failures stop the connection before command execution and return `ssh_host_key_store_failed`. Explicit fingerprints still take precedence.
4. **Completed — vulnerable dependency.** Raise the qs override to `^6.16.0`, update the Bun lockfile and add `bun audit` to CI before image publication.
5. **Completed — OIDC discovery hardening.** Require the discovered issuer to equal the configured issuer. Require HTTPS endpoints, allowing HTTP only on the same origin as an explicitly configured HTTP provider. Reject credential-bearing endpoint URLs and token-endpoint redirects.
6. **Completed — regression verification.** Verify consent bypass attempts, legitimate consent/callback, cookie substitution, cross-origin approval and replay; both MCP tools and mutation URL variants; redirect policy; SSH persistence failures; invalid OIDC discovery.

## Validation

- `bun run typecheck`: passed.
- `bun test`: 264 passed, 0 failed, across 12 files.
- `bun audit`: no vulnerabilities found on 2026-09-04.
- `git diff --check`: passed.

Tests use simulated upstreams and local HTTP/SSH servers. Production services were not contacted or changed. No commit, push or deployment was performed.

## Compatibility and rollout

- Existing access/refresh tokens retain their current semantics. Pending authorizations created before this change must restart. Browser cookies and same-origin POSTs must reach the application; set MCP_PUBLIC_URL to the external origin used for OAuth.
- Read-tier generic calls are now limited to catalogued routes. Add a reviewed GET route to the catalog when a legitimate read operation is missing; use admin for write operations. Miniflux article fetching remains available with `update_content=false` or omitted.
- The SSH known-hosts volume must be readable/writable and valid, unless an explicit verified fingerprint is configured. Repair the store on error; do not delete a legitimate pin without verifying the host out of band.
- Discovery metadata must match POCKETID_ISSUER exactly. Cross-origin HTTP provider endpoints and redirected token exchanges now fail.
- The existing default trust of proxy headers and compatibility for tokens without a resource remain unchanged. Pin MCP_TRUSTED_IP_HEADER to a header overwritten by the actual proxy (or set MCP_TRUST_PROXY=false for direct access), configure MCP_PUBLIC_URL, and use explicitly resource-bound read tokens. These require deployment-specific verification; they are not claimed as production fixes here.

## Source references

- [MCP consent / confused deputy guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Miniflux fetch-content semantics](https://miniflux.app/docs/api.html#fetch-original-article)
- [qs array limit advisory](https://github.com/advisories/GHSA-x5fp-wj9c-mxmx)
- [qs isBuffer advisory](https://github.com/advisories/GHSA-4mjr-xmp4-gh2g)
- [OIDC discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

# Security remediation — 2026-09-27

Follow-up to a review of the state after the 2026-09-04 round. Findings 2–6 of that review are addressed here; finding 1 (the day-to-day connector pointing at `/mcp`) is a deployment change, described under rollout.

## Changes

1. **Tokens bound to a tier.** `/oauth/authorize` binds every request to `<MCP_PUBLIC_URL>/mcp` or `/mcp/read`. A request without `resource` gets `/mcp/read`; a resource naming another server is refused. Tokens persisted without a resource are judged as `/mcp/read` tokens, so they no longer open the admin tier. `MCP_PUBLIC_URL` is required when PocketID is configured, because without it the audience check was skipped.
2. **Pending authorizations bounded.** `pendingAuth` is in memory only (no state-file rewrite per anonymous `/oauth/authorize`), capped at 100 in total and 3 per client, oldest first; the global cap never evicts a pinned admin client's entries, so a flood cannot interrupt the owner's sign-in. A pending authorization no longer marks its client as holding a credential, so an anonymous caller cannot fill all 200 client slots and block registration with 503.
3. **Admin clients pinned.** `MCP_ADMIN_CLIENT_IDS` lists the clients allowed to start an admin authorization or use an admin token; others get an error page naming their id (authorize) or a 401 (on `/mcp`). Pinned clients are never aged out or evicted. This closes the consent-phishing path where a stranger's freshly registered client (for example another claude.ai account) sends an ordinary looking consent link.
4. **Static token scoped.** `MCP_STATIC_TOKEN_TIER` = `read` (default) | `admin` | `off`. `/openapi.json` and `/docs` count as admin. With `off`, `MCP_ACCESS_TOKEN` is optional and an empty bearer never matches.
5. **Upstream headers.** Method-override (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`), forwarding (`Forwarded`, `X-Forwarded-*`, `X-Real-IP`) and `Proxy-Authorization` headers are dropped on every tier; the read tier forwards only `Accept`, `Accept-Language`, `If-None-Match`, `If-Modified-Since` and `Range`. Headers are merged case-insensitively with the credential set last. Invalid header names return `invalid_request`.
6. **Read-only upstream credential.** `PROXMOX_READ_TOKEN_ID` / `PROXMOX_READ_TOKEN_SECRET` back the read tier with a Proxmox token that should hold only PVEAuditor.
7. **Verified emails only.** `MCP_ALLOWED_SUBJECTS` matches an email only when the id_token asserts `email_verified: true`; `vmhq_sessions` lists each session's `subject`, and startup warns when the allowlist holds emails.
8. **Image.** `oven/bun:1.3-alpine` pinned by digest, production-only install, Dependabot for Docker, GitHub Actions and Bun.

## Rollout

- Point the day-to-day connector at `/mcp/read`; keep a separate `/mcp` connector for maintenance and never "always allow" the exec tools.
- Connectors on `/mcp` whose tokens were issued without a resource must reconnect once.
- Connect the admin connector, copy the client id from the error page (or the `oauth_admin_client_not_pinned` log line) into `MCP_ADMIN_CLIENT_IDS`, restart, connect again.
- Replace emails in `MCP_ALLOWED_SUBJECTS` with the subject shown by `vmhq_sessions`.
- Set `MCP_STATIC_TOKEN_TIER=admin` only if a client needs the static token on `/mcp`.
- Optional: create a PVEAuditor API token and set `PROXMOX_READ_TOKEN_ID` / `PROXMOX_READ_TOKEN_SECRET`.
- Still deployment-specific and unchanged: pin `MCP_TRUSTED_IP_HEADER=cf-connecting-ip` behind Cloudflare, set `MCP_ALLOWED_REDIRECT_HOSTS=claude.ai`.
