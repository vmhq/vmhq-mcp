import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { rmSync } from "node:fs";
import { join } from "node:path";

/**
 * Every response the server emits should carry the common security headers.
 * The 401 used to be the one that slipped past secureResponse(), so this walks
 * the whole surface rather than checking the paths someone remembered.
 */
const statePath = join(import.meta.dir, ".headers-test-state.json");
let baseUrl: string;
let proc: ReturnType<typeof Bun.spawn>;
const TOKEN = "x".repeat(48);

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
  rmSync(statePath, { force: true });
  const port = 39400 + Math.floor(Math.random() * 200);
  baseUrl = `http://127.0.0.1:${port}`;
  proc = Bun.spawn(["bun", join(import.meta.dir, "..", "src", "index.ts")], {
    env: {
      ...process.env,
      MCP_ACCESS_TOKEN: TOKEN,
      MCP_PORT: String(port),
      MCP_LOG_LEVEL: "silent",
      MCP_OAUTH_STATE_PATH: statePath,
      MCP_CORS_ORIGIN: "",
      SEARXNG_BASE_URL: "http://searxng.invalid",
    },
    stdout: "ignore",
    stderr: "ignore",
  });
  await waitForHealth(baseUrl);
});

afterAll(() => {
  proc.kill();
  rmSync(statePath, { force: true });
});

describe("security headers", () => {
  const cases: Array<[string, () => Promise<Response>]> = [
    ["/health", () => fetch(`${baseUrl}/health`)],
    ["/icon.svg", () => fetch(`${baseUrl}/icon.svg`)],
    ["404", () => fetch(`${baseUrl}/nope`)],
    ["401 on /mcp", () => fetch(`${baseUrl}/mcp`, { method: "POST", body: "{}" })],
    ["401 on /mcp/read", () => fetch(`${baseUrl}/mcp/read`, { method: "POST", body: "{}" })],
    ["413 oversized body", () =>
      fetch(`${baseUrl}/mcp`, { method: "POST", headers: { "content-length": "99999999" }, body: "{}" })],
    ["protected resource metadata", () => fetch(`${baseUrl}/.well-known/oauth-protected-resource`)],
  ];

  for (const [name, send] of cases) {
    test(`${name} carries the common security headers`, async () => {
      const res = await send();
      expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(res.headers.get("X-Frame-Options")).toBe("DENY");
      expect(res.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    });
  }

  test("the 401 still advertises where to authenticate", async () => {
    const res = await fetch(`${baseUrl}/mcp`, { method: "POST", body: "{}" });
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("resource_metadata=");
  });

  test("no wildcard CORS on /mcp when no origin is configured", async () => {
    const res = await fetch(`${baseUrl}/mcp`, { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  test("OAuth discovery keeps its wildcard, which clients need", async () => {
    const res = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  test("/docs is served with a content security policy", async () => {
    const res = await fetch(`${baseUrl}/docs`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
  });

  test("repeated bad tokens hit the auth-failure limit well before the mcp one", async () => {
    let sawRateLimit = false;
    for (let i = 0; i < 15; i++) {
      const res = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: { Authorization: "Bearer wrong-token-entirely" },
        body: "{}",
      });
      if (res.status === 429) {
        sawRateLimit = true;
        expect(res.headers.get("Retry-After")).toBeTruthy();
        break;
      }
    }
    expect(sawRateLimit).toBe(true);
  });
});
