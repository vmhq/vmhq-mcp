import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { staticTokenOpens } from "../src/mcpEndpoints.js";

/**
 * Which credential opens which endpoint, checked against a running server:
 * the static token by MCP_STATIC_TOKEN_TIER, unbound tokens only on the read
 * endpoint, and the admin endpoint only for clients in MCP_ADMIN_CLIENT_IDS.
 */
const statePath = join(import.meta.dir, ".tier-test-state.json");
const STATIC = "s".repeat(48);
const PINNED = "vmhq_mine";
const OTHER = "vmhq_someone_else";
const TOKENS = {
  pinnedAdmin: "vmhq_mcp_pinned_admin",
  otherAdmin: "vmhq_mcp_other_admin",
  unbound: "vmhq_mcp_unbound",
};

let baseUrl: string;
let proc: ReturnType<typeof Bun.spawn>;

const sha256 = (value: string) => createHash("sha256").update(value).digest("base64url");

async function waitForHealth(url: string): Promise<void> {
  for (let i = 0; i < 80; i++) {
    try {
      if ((await fetch(`${url}/health`)).ok) return;
    } catch {
      // not up yet
    }
    await Bun.sleep(50);
  }
  throw new Error("server did not start");
}

beforeAll(async () => {
  const port = 39600 + Math.floor(Math.random() * 200);
  baseUrl = `http://127.0.0.1:${port}`;
  const stored = (clientId: string, resource?: string) => ({
    clientId,
    scopes: ["mcp"],
    ...(resource ? { resource } : {}),
    identity: { subject: "user-123" },
    expiresAt: Date.now() + 3_600_000,
  });
  writeFileSync(
    statePath,
    JSON.stringify({
      clients: [PINNED, OTHER].map((id) => [id, { clientId: id, clientIdIssuedAt: Math.floor(Date.now() / 1000), redirectUris: ["http://localhost/cb"] }]),
      accessTokens: [
        [sha256(TOKENS.pinnedAdmin), stored(PINNED, `${baseUrl}/mcp`)],
        [sha256(TOKENS.otherAdmin), stored(OTHER, `${baseUrl}/mcp`)],
        [sha256(TOKENS.unbound), stored(PINNED)],
      ],
    }),
  );

  proc = Bun.spawn(["bun", join(import.meta.dir, "..", "src", "index.ts")], {
    env: {
      ...process.env,
      MCP_ACCESS_TOKEN: STATIC,
      MCP_PUBLIC_URL: baseUrl,
      MCP_ADMIN_CLIENT_IDS: PINNED,
      MCP_PORT: String(port),
      MCP_LOG_LEVEL: "silent",
      MCP_OAUTH_STATE_PATH: statePath,
    },
    stdout: "ignore",
    stderr: "ignore",
  });
  await waitForHealth(baseUrl);
});

afterAll(() => {
  proc.kill();
  rmSync(statePath, { force: true });
  rmSync(`${statePath}.tmp`, { force: true });
});

/** Status of an MCP initialize call; anything but 401 means the token got in. */
async function statusWith(token: string, path: string): Promise<number> {
  const res = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "tier-test", version: "1" } },
    }),
  });
  await res.body?.cancel();
  return res.status;
}

describe("static token tier", () => {
  test("defaults to the read endpoint only", async () => {
    expect(await statusWith(STATIC, "/mcp/read")).toBe(200);
    expect(await statusWith(STATIC, "/mcp")).toBe(401);
    const docs = await fetch(`${baseUrl}/docs`, { headers: { Authorization: `Bearer ${STATIC}` } });
    expect(docs.status).toBe(401);
  });

  test("staticTokenOpens covers every combination", () => {
    expect(staticTokenOpens("admin", "admin")).toBe(true);
    expect(staticTokenOpens("admin", "read")).toBe(true);
    expect(staticTokenOpens("read", "admin")).toBe(false);
    expect(staticTokenOpens("read", "read")).toBe(true);
    expect(staticTokenOpens("off", "admin")).toBe(false);
    expect(staticTokenOpens("off", "read")).toBe(false);
  });
});

describe("OAuth tokens by endpoint", () => {
  test("a pinned client's admin token opens both endpoints", async () => {
    expect(await statusWith(TOKENS.pinnedAdmin, "/mcp")).toBe(200);
    expect(await statusWith(TOKENS.pinnedAdmin, "/mcp/read")).toBe(200);
  });

  test("an admin token from a client that is not pinned is refused on /mcp", async () => {
    expect(await statusWith(TOKENS.otherAdmin, "/mcp")).toBe(401);
    // Pinning governs the admin tier only; reading stays available.
    expect(await statusWith(TOKENS.otherAdmin, "/mcp/read")).toBe(200);
  });

  test("a token issued without a resource is read-only", async () => {
    expect(await statusWith(TOKENS.unbound, "/mcp/read")).toBe(200);
    expect(await statusWith(TOKENS.unbound, "/mcp")).toBe(401);
  });
});
