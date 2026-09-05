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
