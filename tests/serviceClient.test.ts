import { afterEach, describe, expect, test } from "bun:test";
import { buildUrl, callService, interpolatePath, isMultipartBody } from "../src/serviceClient.js";
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

describe("isMultipartBody", () => {
  test("returns true for bodies with _multipart: true", () => {
    expect(isMultipartBody({ _multipart: true, title: "doc" })).toBe(true);
  });

  test("returns false for plain JSON bodies", () => {
    expect(isMultipartBody({ title: "doc" })).toBe(false);
  });

  test("returns false for non-objects", () => {
    expect(isMultipartBody(null)).toBe(false);
    expect(isMultipartBody("string")).toBe(false);
    expect(isMultipartBody(undefined)).toBe(false);
  });
});

describe("callService multipart", () => {
  test("sends FormData when body has _multipart: true", async () => {
    let receivedContentType: string | null = null;
    let receivedTitle: string | undefined;
    let receivedFileText: string | undefined;
    let receivedFilename: string | undefined;

    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        receivedContentType = req.headers.get("content-type");
        const form = await req.formData();
        receivedTitle = form.get("title")?.toString();
        const file = form.get("document");
        if (file instanceof File) {
          receivedFilename = file.name;
          receivedFileText = await file.text();
        }
        return Response.json({ ok: true });
      },
    });
    servers.push(server);

    const service: ServiceDefinition = { ...baseService, baseUrl: `http://127.0.0.1:${server.port}/api` };
    const result = await callService(
      service,
      {
        method: "POST",
        path: "/documents/post_document/",
        body: {
          _multipart: true,
          title: "Factura Mayo",
          document: {
            _base64: Buffer.from("hello pdf").toString("base64"),
            filename: "factura.pdf",
            contentType: "application/pdf",
          },
        },
      },
      { timeoutMs: 2_000 },
    );

    expect(receivedContentType).toMatch(/multipart\/form-data/);
    expect(receivedTitle).toBe("Factura Mayo");
    expect(receivedFilename).toBe("factura.pdf");
    expect(receivedFileText).toBe("hello pdf");
    expect(result).toMatchObject({ response: { ok: true, status: 200 } });
  });

  test("sends scalar arrays as repeated form fields", async () => {
    let receivedTags: string[] = [];

    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        const form = await req.formData();
        receivedTags = form.getAll("tags") as string[];
        return Response.json({ ok: true });
      },
    });
    servers.push(server);

    const service: ServiceDefinition = { ...baseService, baseUrl: `http://127.0.0.1:${server.port}/api` };
    await callService(
      service,
      {
        method: "POST",
        path: "/documents/post_document/",
        body: { _multipart: true, tags: ["1", "3", "7"] },
      },
      { timeoutMs: 2_000 },
    );

    expect(receivedTags).toEqual(["1", "3", "7"]);
  });

  test("sends internal byte file fields as multipart files", async () => {
    let receivedFileText: string | undefined;
    let receivedFileType: string | undefined;

    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        const form = await req.formData();
        const file = form.get("document");
        if (file instanceof File) {
          receivedFileText = await file.text();
          receivedFileType = file.type;
        }
        return Response.json({ ok: true });
      },
    });
    servers.push(server);

    const service: ServiceDefinition = { ...baseService, baseUrl: `http://127.0.0.1:${server.port}/api` };
    await callService(
      service,
      {
        method: "POST",
        path: "/documents/post_document/",
        body: {
          _multipart: true,
          document: {
            _bytes: Buffer.from(`%PDF-1.4\nbytes`),
            filename: "bytes.pdf",
            contentType: "application/pdf",
          },
        },
      },
      { timeoutMs: 2_000 },
    );

    expect(receivedFileText).toStartWith("%PDF-1.4");
    expect(receivedFileText).toContain("bytes");
    expect(receivedFileType).toBe("application/pdf");
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

  test("applies fields inside {total, entries} wrapper and preserves total", async () => {
    const server = Bun.serve({
      port: 0,
      fetch() {
        return Response.json({
          total: 42,
          entries: [
            { id: 1, title: "First", url: "https://a", content: "long" },
            { id: 2, title: "Second", url: "https://b", content: "long" },
          ],
        });
      },
    });
    servers.push(server);

    const service: ServiceDefinition = { ...baseService, baseUrl: `http://127.0.0.1:${server.port}/api` };
    const result = await callService(
      service,
      { method: "GET", path: "/entries", fields: ["id", "title"] },
      { timeoutMs: 1_000 },
    );

    expect(result).toMatchObject({
      response: {
        ok: true,
        body: {
          total: 42,
          entries: [
            { id: 1, title: "First" },
            { id: 2, title: "Second" },
          ],
        },
      },
    });
  });

  test("applies nested dotted fields and preserves nested structure", async () => {
    const server = Bun.serve({
      port: 0,
      fetch() {
        return Response.json({
          entity_id: "light.office",
          state: "on",
          attributes: { friendly_name: "Office Light", brightness: 200, extra: "drop me" },
        });
      },
    });
    servers.push(server);

    const service: ServiceDefinition = { ...baseService, baseUrl: `http://127.0.0.1:${server.port}/api` };
    const result = await callService(
      service,
      { method: "GET", path: "/states/light.office", fields: ["entity_id", "state", "attributes.friendly_name"] },
      { timeoutMs: 1_000 },
    );

    expect(result).toMatchObject({
      response: {
        ok: true,
        body: {
          entity_id: "light.office",
          state: "on",
          attributes: { friendly_name: "Office Light" },
        },
      },
    });
  });

  test("silently omits missing nested dotted fields", async () => {
    const server = Bun.serve({
      port: 0,
      fetch() {
        return Response.json({ entity_id: "light.office", state: "on" });
      },
    });
    servers.push(server);

    const service: ServiceDefinition = { ...baseService, baseUrl: `http://127.0.0.1:${server.port}/api` };
    const result = await callService(
      service,
      { method: "GET", path: "/states/light.office", fields: ["state", "attributes.friendly_name"] },
      { timeoutMs: 1_000 },
    );

    expect(result).toMatchObject({
      response: {
        ok: true,
        body: { state: "on" },
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
