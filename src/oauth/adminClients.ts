/**
 * Clients allowed to obtain a token for the admin endpoint, from
 * MCP_ADMIN_CLIENT_IDS (comma separated). Unset means every registered client
 * may, which is the pre-existing behaviour; loadConfig() warns about it.
 *
 * Kept apart from state.ts, which loads the persisted state on import, so the
 * configuration can read it without side effects.
 */
export function adminClientIds(): string[] {
  return (process.env.MCP_ADMIN_CLIENT_IDS ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function isAdminClient(clientId: string, pinned = adminClientIds()): boolean {
  return pinned.length === 0 || pinned.includes(clientId);
}
