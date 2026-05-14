import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { rmSync } from "node:fs";
import { join } from "node:path";

type OAuthModule = typeof import("../src/oauth.js");

const statePath = join(import.meta.dir, ".oauth-test-state.json");
let oauth: OAuthModule;

beforeAll(async () => {
  rmSync(statePath, { force: true });
  process.env.MCP_LOG_LEVEL = "silent";
  process.env.MCP_OAUTH_STATE_PATH = statePath;
  oauth = await import("../src/oauth.js");
});

afterAll(() => {
  rmSync(statePath, { force: true });
  rmSync(`${statePath}.tmp`, { force: true });
});

function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

async function register(redirectUri: string): Promise<string> {
  const response = await oauth.registerClient(
    new Request("https://mcp.example.com/oauth/register", {
      method: "POST",
      body: JSON.stringify({ redirect_uris: [redirectUri], client_name: "Test Client" }),
      headers: { "Content-Type": "application/json" },
    }),
  );

  expect(response.status).toBe(200);
  const body = (await response.json()) as { client_id: string };
  return body.client_id;
}

function formRequest(url: string, fields: Record<string, string>): Request {
  const body = new URLSearchParams(fields);
  return new Request(url, {
    method: "POST",
    body,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
}

describe("OAuth", () => {
  test("rejects unsafe redirect URIs at registration", async () => {
    const response = await oauth.registerClient(
      new Request("https://mcp.example.com/oauth/register", {
        method: "POST",
        body: JSON.stringify({ redirect_uris: ["http://evil.example/callback"] }),
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(response.status).toBe(400);
  });

  test("authorize form includes security headers and relative form action", async () => {
    const response = oauth.authorizeForm(new Request("https://mcp.example.com/oauth/authorize"), {});
    const html = await response.text();

    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(html).toContain('action="/oauth/authorize"');
  });

  test("authorize form uses relative form action regardless of publicUrl", async () => {
    const response = oauth.authorizeForm(
      new Request("http://127.0.0.1:3000/oauth/authorize"),
      { publicUrl: "https://mcp.public.example.com" },
    );
    const html = await response.text();

    expect(html).toContain('action="/oauth/authorize"');
  });

  test("authorize form shows error messages from error query param", async () => {
    const tests = [
      { error: "1", expected: "Invalid token" },
      { error: "client_not_found", expected: "Client not found" },
      { error: "invalid_redirect_uri", expected: "redirect URI is not allowed" },
      { error: "invalid_pkce", expected: "PKCE validation failed" },
    ];

    for (const { error, expected } of tests) {
      const response = oauth.authorizeForm(
        new Request(`https://mcp.example.com/oauth/authorize?error=${error}`),
        {},
      );
      const html = await response.text();
      expect(html).toContain(expected);
    }
  });

  test("authorize redirects to form on invalid token", async () => {
    const response = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "wrong-token",
        client_id: "vmhq_test",
        redirect_uri: "https://client.example.com/callback",
        code_challenge: "challenge",
        code_challenge_method: "S256",
      }),
      "server-secret",
      {},
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location");
    expect(location).toContain("/oauth/authorize");
    expect(location).toContain("error=1");
  });

  test("authorize redirects to form on invalid redirect URI", async () => {
    const response = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: "vmhq_nonexistent",
        redirect_uri: "http://evil.example/callback",
        code_challenge: "challenge",
        code_challenge_method: "S256",
      }),
      "server-secret",
      {},
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location");
    expect(location).toContain("/oauth/authorize");
    expect(location).toContain("error=client_not_found");
  });

  test("authorize redirects to form on invalid PKCE", async () => {
    const redirectUri = "https://client.example.com/callback";
    const clientId = await register(redirectUri);

    const response = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: "",
        code_challenge_method: "",
      }),
      "server-secret",
      {},
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location");
    expect(location).toContain("/oauth/authorize");
    expect(location).toContain("error=invalid_pkce");
  });

  test("performs authorization code flow and makes code single-use", async () => {
    const redirectUri = "https://client.example.com/callback";
    const clientId = await register(redirectUri);
    const verifier = "correct-horse-battery-staple";
    const challenge = s256(verifier);

    const authResponse = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        state: "abc",
      }),
      "server-secret",
      {},
    );

    expect(authResponse.status).toBe(303);
    const location = authResponse.headers.get("location");
    expect(location).toBeTruthy();
    const redirect = new URL(location!);
    const code = redirect.searchParams.get("code");
    expect(code).toBeTruthy();
    expect(redirect.searchParams.get("state")).toBe("abc");

    const tokenResponse = await oauth.exchangeToken(
      formRequest("https://mcp.example.com/oauth/token", {
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }),
    );

    expect(tokenResponse.status).toBe(200);
    const tokenBody = (await tokenResponse.json()) as { access_token: string; token_type: string };
    expect(tokenBody.token_type).toBe("Bearer");
    expect(oauth.isOAuthAccessToken(tokenBody.access_token)).toBe(true);

    const replayResponse = await oauth.exchangeToken(
      formRequest("https://mcp.example.com/oauth/token", {
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }),
    );

    expect(replayResponse.status).toBe(400);
  });
});
