import { describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer, operationBody, type SessionStore, type ToolTier } from "../src/mcp.js";
import type { ApiEndpoint } from "../src/apiCatalog.js";
import type { ProxmoxSshConfig } from "../src/sshClient.js";
import type { ServiceDefinition } from "../src/services.js";

describe("operationBody", () => {
  test("returns inputBody unchanged when no defaultBody", () => {
    const endpoint: ApiEndpoint = { operationId: "get_me", method: "GET", path: "/v1/me", group: "users", summary: "Get user." };
    expect(operationBody(endpoint, { foo: "bar" })).toEqual({ foo: "bar" });
  });

  test("returns defaultBody copy when no inputBody", () => {
    const endpoint: ApiEndpoint = {
      operationId: "create_item",
      method: "POST",
      path: "/v1/items",
      group: "items",
      summary: "Create item.",
      defaultBody: { enabled: true },
    };
    expect(operationBody(endpoint, undefined)).toEqual({ enabled: true });
  });

  test("merges defaultBody with caller body, caller wins on conflict", () => {
    const endpoint: ApiEndpoint = {
      operationId: "create_item",
      method: "POST",
      path: "/v1/items",
      group: "items",
      summary: "Create item.",
      defaultBody: { enabled: true, category: "default" },
    };
    const body = operationBody(endpoint, {
      enabled: false,
      name: "Example",
    });
    expect(body).toEqual({
      enabled: false,
      category: "default",
      name: "Example",
    });
  });

  test("parses JSON string body and merges with defaultBody", () => {
    const endpoint: ApiEndpoint = {
      operationId: "create_item",
      method: "POST",
      path: "/v1/items",
      group: "items",
      summary: "Create item.",
      defaultBody: { enabled: true },
    };
    const body = operationBody(endpoint, JSON.stringify({ name: "Hello", count: 2 }));
    expect(body).toEqual({
      enabled: true,
      name: "Hello",
      count: 2,
    });
  });

  test("preserves non-JSON string bodies", () => {
    const endpoint: ApiEndpoint = {
      operationId: "create_item",
      method: "POST",
      path: "/v1/items",
      group: "items",
      summary: "Create item.",
      defaultBody: { enabled: true },
    };
    expect(operationBody(endpoint, "raw body")).toBe("raw body");
  });
});

const sshConfig: ProxmoxSshConfig = {
  host: "pve.lan",
  port: 22,
  user: "root",
  timeoutMs: 5_000,
  maxOutputChars: 30_000,
  sudo: false,
  containerShell: "/bin/sh",
  jobDir: "/var/log/vmhq-mcp",
  jobRetentionDays: 30,
};

const searxng: ServiceDefinition = {
  id: "searxng",
  title: "SearXNG",
  baseUrl: "http://searxng.lan",
  auth: { type: "none" },
  defaultPathPrefix: "/",
};

/** Records what vmhq_sessions was asked to do, without touching real OAuth state. */
function fakeSessions(): SessionStore & { revokeCalls: Array<Record<string, unknown>> } {
  const revokeCalls: Array<Record<string, unknown>> = [];
  return {
    revokeCalls,
    list: () => [{ clientId: "vmhq_abc", actor: "vicente@example.com", renewable: true }],
    revoke: (filter) => {
      revokeCalls.push(filter);
      return 2;
    },
  };
}

/** Lists the tools an MCP client actually sees on a given tier. */
async function toolsFor(tier: ToolTier, proxmoxSsh: ProxmoxSshConfig | null = sshConfig): Promise<string[]> {
  const server = createMcpServer({
    services: [searxng],
    iconUrl: "https://x/icon.svg",
    proxmoxSsh: proxmoxSsh ?? undefined,
    tier,
    sessions: fakeSessions(),
  });
  const client = new Client({ name: "test", version: "0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    const { tools } = await client.listTools();
    return tools.map((tool) => tool.name).sort();
  } finally {
    await client.close();
  }
}

/**
 * The shell tools and the tools that pull in third-party text (search results,
 * RSS, bookmarks) share one model context, so an instruction hidden in a fetched
 * page can reach whatever the session holds. The read tier exists so a session
 * can hold one without the other; these tests are what keeps that true.
 */
describe("tool tiers", () => {
  test("the admin tier exposes both exec tools", async () => {
    const tools = await toolsFor("admin");
    expect(tools).toContain("proxmox_node_exec");
    expect(tools).toContain("proxmox_lxc_exec");
  });

  test("the read tier exposes no way to execute anything", async () => {
    const tools = await toolsFor("read");
    expect(tools).not.toContain("proxmox_node_exec");
    expect(tools).not.toContain("proxmox_lxc_exec");
    expect(tools.filter((name) => name.includes("exec"))).toEqual([]);
  });

  test("the read tier keeps the read-only Proxmox tools and every service tool", async () => {
    const tools = await toolsFor("read");
    for (const name of [
      "proxmox_lxc_list",
      "proxmox_job_status",
      "searxng_request",
      "searxng_operation",
      "searxng_api_reference",
      "vmhq_status",
      "vmhq_find_operation",
    ]) {
      expect(tools).toContain(name);
    }
  });

  test("the two tiers differ by exactly the exec tools, nothing else", async () => {
    const [admin, read] = await Promise.all([toolsFor("admin"), toolsFor("read")]);
    expect(admin.filter((name) => !read.includes(name))).toEqual([
      "proxmox_lxc_exec",
      "proxmox_node_exec",
      "vmhq_sessions",
    ]);
    expect(read.filter((name) => !admin.includes(name))).toEqual([]);
  });

  test("an omitted tier stays admin, so a new call site cannot silently widen access", async () => {
    const server = createMcpServer({ services: [searxng], iconUrl: "https://x/icon.svg", proxmoxSsh: sshConfig });
    const client = new Client({ name: "test", version: "0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toContain("proxmox_node_exec");
    } finally {
      await client.close();
    }
  });

  test("vmhq_status reports the tier it is running under", async () => {
    for (const tier of ["read", "admin"] as const) {
      const server = createMcpServer({ services: [searxng], iconUrl: "https://x/icon.svg", proxmoxSsh: sshConfig, tier });
      const client = new Client({ name: "test", version: "0" });
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
      try {
        const result = await client.callTool({ name: "vmhq_status", arguments: {} });
        const text = (result.content as Array<{ text: string }>)[0]!.text;
        const status = JSON.parse(text) as { tier: string; proxmoxSsh?: { tools: string[] } };
        expect(status.tier).toBe(tier);
        expect(status.proxmoxSsh?.tools.includes("proxmox_node_exec")).toBe(tier === "admin");
      } finally {
        await client.close();
      }
    }
  });

  test("without SSH configured there are no proxmox tools on either tier", async () => {
    const [admin, read] = await Promise.all([toolsFor("admin", null), toolsFor("read", null)]);
    expect(admin.some((name) => name.startsWith("proxmox_"))).toBe(false);
    expect(read.some((name) => name.startsWith("proxmox_"))).toBe(false);
    // The tiers still differ: revoking sessions is administrative on its own,
    // independently of whether a shell is reachable.
    expect(admin.filter((name) => !read.includes(name))).toEqual(["vmhq_sessions"]);
  });
});

describe("vmhq_sessions", () => {
  async function connect(tier: ToolTier, sessions: SessionStore) {
    const server = createMcpServer({ services: [searxng], iconUrl: "https://x/icon.svg", tier, sessions });
    const client = new Client({ name: "test", version: "0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    return client;
  }

  async function call(client: Client, args: Record<string, unknown>) {
    const result = await client.callTool({ name: "vmhq_sessions", arguments: args });
    return {
      isError: result.isError === true,
      payload: JSON.parse((result.content as Array<{ text: string }>)[0]!.text) as Record<string, unknown>,
    };
  }

  test("cutting other people's access is an admin act, absent from the read tier", async () => {
    expect(await toolsFor("admin")).toContain("vmhq_sessions");
    expect(await toolsFor("read")).not.toContain("vmhq_sessions");
  });

  test("is not registered at all when no session store is wired in", async () => {
    const server = createMcpServer({ services: [searxng], iconUrl: "https://x/icon.svg", tier: "admin" });
    const client = new Client({ name: "test", version: "0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name)).not.toContain("vmhq_sessions");
    } finally {
      await client.close();
    }
  });

  test("list returns the inventory", async () => {
    const client = await connect("admin", fakeSessions());
    try {
      const { payload } = await call(client, { action: "list" });
      expect(payload.total).toBe(1);
      expect((payload.sessions as Array<{ actor: string }>)[0]!.actor).toBe("vicente@example.com");
    } finally {
      await client.close();
    }
  });

  test("revoke passes the filter through and reports the count", async () => {
    const sessions = fakeSessions();
    const client = await connect("admin", sessions);
    try {
      const { payload } = await call(client, { action: "revoke", actor: "vicente@example.com" });
      expect(payload.revoked).toBe(2);
      expect(sessions.revokeCalls).toEqual([{ actor: "vicente@example.com", clientId: undefined, all: undefined }]);
    } finally {
      await client.close();
    }
  });

  test("revoking with no filter is refused rather than treated as revoke-all", async () => {
    const sessions = fakeSessions();
    const client = await connect("admin", sessions);
    try {
      const { isError, payload } = await call(client, { action: "revoke" });
      expect(isError).toBe(true);
      expect(JSON.stringify(payload)).toContain("needs a filter");
      expect(sessions.revokeCalls).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test("records who performed the revocation", async () => {
    const server = createMcpServer({
      services: [searxng],
      iconUrl: "https://x/icon.svg",
      tier: "admin",
      sessions: fakeSessions(),
      actor: "vicente@example.com",
    });
    const client = new Client({ name: "test", version: "0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const { payload } = await call(client, { action: "revoke", all: true });
      expect(payload.by).toBe("vicente@example.com");
    } finally {
      await client.close();
    }
  });
});
