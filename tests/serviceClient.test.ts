import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { buildUrl, callService, filterFields, interpolatePath, isMultipartBody, parseFields } from "../src/serviceClient.js";
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
  delete process.env.TEST_MINIFLUX_TOKEN;
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
    const result = (await callService(
      service,
      { method: "GET", path: "/states/light.office", fields: ["entity_id", "state", "attributes.friendly_name"] },
      { timeoutMs: 1_000 },
    )) as { response: { ok: boolean; body: unknown } };

    expect(result.response.ok).toBe(true);
    // Exact equality: unselected fields (attributes.brightness, attributes.extra) must be gone.
    expect(result.response.body).toEqual({
      entity_id: "light.office",
      state: "on",
      attributes: { friendly_name: "Office Light" },
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
    const result = (await callService(
      service,
      { method: "GET", path: "/states/light.office", fields: ["state", "attributes.friendly_name"] },
      { timeoutMs: 1_000 },
    )) as { response: { ok: boolean; body: unknown } };

    expect(result.response.ok).toBe(true);
    // Exact equality: the missing nested path must not appear at all (no empty attributes object).
    expect(result.response.body).toEqual({ state: "on" });
  });

  test("prefers a literal dotted top-level key over nested path interpretation", async () => {
    const server = Bun.serve({
      port: 0,
      fetch() {
        return Response.json({
          "light.office": { state: "on" },
          "light.kitchen": { state: "off" },
        });
      },
    });
    servers.push(server);

    const service: ServiceDefinition = { ...baseService, baseUrl: `http://127.0.0.1:${server.port}/api` };
    const result = (await callService(
      service,
      { method: "GET", path: "/states", fields: ["light.office"] },
      { timeoutMs: 1_000 },
    )) as { response: { ok: boolean; body: unknown } };

    expect(result.response.ok).toBe(true);
    expect(result.response.body).toEqual({ "light.office": { state: "on" } });
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

describe("filterFields prototype-pollution guard", () => {
  test("drops __proto__ paths and never pollutes Object.prototype", () => {
    const data = JSON.parse('{"__proto__": {"polluted": "PWNED"}, "safe": 1}');
    const result = filterFields(data, parseFields(["__proto__.polluted", "safe"]));
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(result).toEqual({ safe: 1 });
  });

  test("drops constructor and prototype segments anywhere in the path", () => {
    const data = { constructor: "evil", a: { prototype: 1, b: 2 } };
    expect(filterFields(data, parseFields(["constructor", "a.prototype", "a.b"]))).toEqual({ a: { b: 2 } });
  });

  test("does not copy inherited properties", () => {
    expect(filterFields({ real: 1 }, parseFields(["toString", "real"]))).toEqual({ real: 1 });
  });
});

describe("callService upstream size cap", () => {
  test("returns an error when the upstream body exceeds the cap", async () => {
    const server = Bun.serve({
      port: 0,
      fetch() {
        return new Response("x".repeat(11 * 1024 * 1024), {
          headers: { "content-type": "text/plain" },
        });
      },
    });
    servers.push(server);
    const service = { ...baseService, baseUrl: `http://localhost:${server.port}` };
    const result = (await callService(service, { method: "GET", path: "/big" })) as {
      error?: { type: string; message: string };
    };
    expect(result.error).toBeDefined();
    expect(result.error?.message).toContain("exceeded");
  });
});

/**
 * fetch follows redirects by default, and Bun (like the spec) only strips
 * `Authorization` when the origin changes — a header-named credential such as
 * Miniflux's `X-Auth-Token` rides along to whatever host the upstream points
 * at. The origin check in buildUrl() only covers the first URL, so the hops
 * after it were also an SSRF pivot into the local network.
 */
describe("redirect handling", () => {
  /** Records what a would-be redirect target actually receives. */
  function victimServer() {
    let received: Record<string, string> | undefined;
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        received = Object.fromEntries(req.headers.entries());
        return Response.json({ stolen: true });
      },
    });
    servers.push(server);
    return { server, headers: () => received };
  }

  /** Redirects everything to `target`, or in a loop back to itself. */
  function redirectingServer(target?: string) {
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        const location = target ?? new URL(req.url).href;
        return new Response(null, { status: 302, headers: { location } });
      },
    });
    servers.push(server);
    return server;
  }

  beforeEach(() => {
    process.env.TEST_MINIFLUX_TOKEN = "MINIFLUX_SECRET";
  });

  function tokenService(baseUrl: string): ServiceDefinition {
    return {
      id: "miniflux",
      title: "Miniflux",
      baseUrl,
      auth: { type: "header", tokenEnv: "TEST_MINIFLUX_TOKEN", headerName: "X-Auth-Token" },
      defaultPathPrefix: "/v1",
    };
  }

  test("a cross-origin redirect is refused and the credential never leaves", async () => {
    const victim = victimServer();
    const upstream = redirectingServer(`http://127.0.0.1:${victim.server.port}/stolen`);

    const result = (await callService(tokenService(`http://127.0.0.1:${upstream.port}`), {
      method: "GET",
      path: "/v1/me",
    })) as { error?: { type: string; message: string } };

    expect(result.error?.type).toBe("upstream_redirect_blocked");
    expect(result.error?.message).toContain(`127.0.0.1:${victim.server.port}`);
    // The point of the whole fix: the other host was never contacted at all.
    expect(victim.headers()).toBeUndefined();
  });

  test("a same-origin redirect is followed with the credential intact", async () => {
    let sawToken: string | undefined;
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === "/v1/me") {
          return new Response(null, { status: 302, headers: { location: "/v1/me/" } });
        }
        sawToken = req.headers.get("x-auth-token") ?? undefined;
        return Response.json({ id: 1 });
      },
    });
    servers.push(server);

    const result = (await callService(tokenService(`http://127.0.0.1:${server.port}`), {
      method: "GET",
      path: "/v1/me",
    })) as { response?: { ok: boolean; body: unknown } };

    expect(result.response?.ok).toBe(true);
    expect(result.response?.body).toEqual({ id: 1 });
    expect(sawToken).toBe("MINIFLUX_SECRET");
  });

  test("a redirect loop is cut instead of followed forever", async () => {
    const upstream = redirectingServer();
    const result = (await callService(tokenService(`http://127.0.0.1:${upstream.port}`), {
      method: "GET",
      path: "/v1/me",
    })) as { error?: { type: string } };
    expect(result.error?.type).toBe("upstream_too_many_redirects");
  });

  test("a non-GET redirect is returned rather than replayed against another URL", async () => {
    // Replaying a POST body across a redirect cannot be done correctly for
    // every body type, so the 3xx is surfaced and the caller decides.
    const upstream = redirectingServer("/v1/elsewhere");
    const result = (await callService(tokenService(`http://127.0.0.1:${upstream.port}`), {
      method: "POST",
      path: "/v1/entries",
      body: { title: "x" },
    })) as { response?: { status: number } };
    expect(result.response?.status).toBe(302);
  });
});
