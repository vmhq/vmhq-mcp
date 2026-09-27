/**
 * The MCP endpoints this server exposes, and the tool tier each one hands out.
 *
 * Shared by the HTTP router (which picks the tier from the path) and the OAuth
 * server (which binds every token to one of these resources), so the two can
 * never disagree about what `/mcp/read` means.
 */
export type ToolTier = "read" | "admin";

export const ADMIN_MCP_PATH = "/mcp";
export const READ_MCP_PATH = "/mcp/read";

/**
 * `/mcp` keeps every tool. `/mcp/read` is the endpoint to point a day-to-day
 * client at: same services, same auth, but no Proxmox shell and nothing that
 * writes. Everything this server reads (search results, RSS articles,
 * bookmarks) is text written by someone else that lands in the same model
 * context as the tool list, so a session that only reads should not also be
 * holding a root shell on the hypervisor.
 */
export const MCP_ENDPOINTS: Record<string, ToolTier> = {
  [ADMIN_MCP_PATH]: "admin",
  [READ_MCP_PATH]: "read",
};

/**
 * How far the static MCP_ACCESS_TOKEN reaches, from MCP_STATIC_TOKEN_TIER.
 * It names no person, never expires and cannot be revoked short of editing the
 * environment, so by default it opens the read endpoint only.
 */
export type StaticTokenTier = ToolTier | "off";

export const STATIC_TOKEN_TIERS: readonly StaticTokenTier[] = ["admin", "read", "off"];

/** Whether the static token may open a route of the given tier. */
export function staticTokenOpens(tokenTier: StaticTokenTier, routeTier: ToolTier): boolean {
  if (tokenTier === "off") return false;
  return tokenTier === "admin" || routeTier === "read";
}
