import { afterEach, describe, expect, test } from "bun:test";
import { buildUrl, callService, interpolatePath } from "../src/serviceClient.js";
import type { ServiceDefinition } from "../src/services.js";

process.env.MCP_LOG_LEVEL = "silent";

const baseService: ServiceDefinition = {
  id: "miniflux",
  title: "Miniflux",
  baseUrl: "https://example.com/v1",
  auth: { type: "none" },
  defaultPathPrefix: "/v1",
};

const servers: Array<{ stop: () => void }> = [];

afterEach(() => {
  for (const server of servers.splice(0)) {
    server.stop();
  }
});

describe("interpolatePath", () => {
  test("encodes path parameters", () => {
    expect(interpolatePath("/api/states/{entity_id}", { entity_id: "light.office lamp" })).toBe("/api/states/light.office%20lamp");
  });

  test("throws for missing path parameters", () => {
    expect(() => interpolatePath("/nodes/{node}/qemu/{vmid}", { node: "pve" })).toThrow("Missing required path parameter: vmid");
  });
});

describe("buildUrl", () => {
  test("preserves configured base path", () => {
    const url = buildUrl(baseService, { method: "GET", path: "/entries", query: { limit: 10 } });
    expect(url.href).toBe("https://example.com/v1/entries?limit=10");
  });

  test("rejects absolute paths", () => {
    expect(() => buildUrl(baseService, { method: "GET", path: "https://evil.test/" })).toThrow("Absolute URLs are not allowed");
  });
});

describe("callService", () => {
  test("filters blocked request headers and parses JSON", async () => {
    let seenAuthorization: string | null = null;
    let seenCustom: string | null = null;

    const server = Bun.serve({
      port: 0,
      fetch(req) {
        seenAuthorization = req.headers.get("authorization");
        seenCustom = req.headers.get("x-custom");
        return Response.json([{ id: 1, title: "Entry", secret: "hidden" }]);
      },
    });
    servers.push(server);

    const service: ServiceDefinition = { ...baseService, baseUrl: `http://127.0.0.1:${server.port}/api` };
    const result = await callService(
      service,
      {
        method: "GET",
        path: "/entries",
        headers: { Authorization: "Bearer bad", "X-Custom": "ok" },
        fields: ["id", "title"],
      },
      { timeoutMs: 1_000 },
    );

    expect(seenAuthorization).toBeNull();
    expect(String(seenCustom)).toBe("ok");
    expect(result).toMatchObject({
      response: {
        ok: true,
        status: 200,
        body: [{ id: 1, title: "Entry" }],
      },
    });
  });

  test("returns normalized missing credential error", async () => {
    delete process.env.MINIFLUX_TOKEN;
    const result = await callService(
      { ...baseService, auth: { type: "bearer", tokenEnv: "MINIFLUX_TOKEN" } },
      { method: "GET", path: "/me" },
    );

    expect(result).toMatchObject({
      error: {
        type: "missing_upstream_credentials",
        service: "miniflux",
        retryable: false,
      },
    });
  });

  test("returns normalized timeout error", async () => {
    const server = Bun.serve({
      port: 0,
      async fetch() {
        await Bun.sleep(50);
        return Response.json({ ok: true });
      },
    });
    servers.push(server);

    const service: ServiceDefinition = { ...baseService, baseUrl: `http://127.0.0.1:${server.port}/api` };
    const result = await callService(service, { method: "GET", path: "/slow" }, { timeoutMs: 1 });

    expect(result).toMatchObject({
      error: {
        type: "upstream_timeout",
        service: "miniflux",
        retryable: true,
      },
    });
  });
});
