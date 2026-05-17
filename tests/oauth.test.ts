import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
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
  const res = await oauth.registerClient(
    new Request("https://mcp.example.com/oauth/register", {
      method: "POST",
      body: JSON.stringify({ redirect_uris: [redirectUri], client_name: "Test Client" }),
      headers: { "Content-Type": "application/json" },
    }),
  );
  expect(res.status).toBe(201);
  const body = (await res.json()) as { client_id: string };
  return body.client_id;
}

function formRequest(url: string, fields: Record<string, string>): Request {
  return new Request(url, {
    method: "POST",
    body: new URLSearchParams(fields),
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
}

// Full authorize → token exchange flow
async function fullFlow(opts: {
  redirectUri: string;
  tokenRedirectUri?: string;
  verifier?: string;
  scope?: string;
  resource?: string;
}) {
  const clientId = await register(opts.redirectUri);
  const verifier = opts.verifier ?? "correct-horse-battery-staple";
  const challenge = s256(verifier);

  const fields: Record<string, string> = {
    token: "server-secret",
    client_id: clientId,
    redirect_uri: opts.redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "abc",
  };
  if (opts.scope) fields.scope = opts.scope;
  if (opts.resource) fields.resource = opts.resource;

  const authRes = await oauth.authorize(
    formRequest("https://mcp.example.com/oauth/authorize", fields),
    "server-secret",
    {},
  );
  expect(authRes.status).toBe(303);
  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
  expect(code).toBeTruthy();

  const tokenFields: Record<string, string> = {
    grant_type: "authorization_code",
    code,
    redirect_uri: opts.tokenRedirectUri ?? opts.redirectUri,
    client_id: clientId,
    code_verifier: verifier,
  };
  if (opts.resource) tokenFields.resource = opts.resource;

  const tokenRes = await oauth.exchangeToken(
    formRequest("https://mcp.example.com/oauth/token", tokenFields),
  );
  return { tokenRes, clientId, code };
}

// ─── Client registration ──────────────────────────────────────────────────────

describe("client registration", () => {
  test("rejects http non-loopback redirect URIs", async () => {
    const res = await oauth.registerClient(
      new Request("https://mcp.example.com/oauth/register", {
        method: "POST",
        body: JSON.stringify({ redirect_uris: ["http://evil.example/callback"] }),
        headers: { "Content-Type": "application/json" },
      }),
    );
    expect(res.status).toBe(400);
  });

  test("accepts loopback http redirect URIs (RFC 8252)", async () => {
    for (const uri of [
      "http://localhost:12345/callback",
      "http://127.0.0.1:9000/cb",
      "http://[::1]:8080/cb",
    ]) {
      const res = await oauth.registerClient(
        new Request("https://mcp.example.com/oauth/register", {
          method: "POST",
          body: JSON.stringify({ redirect_uris: [uri], client_name: "Native App" }),
          headers: { "Content-Type": "application/json" },
        }),
      );
      expect(res.status).toBe(201);
    }
  });

  test("rejects loopback with https scheme", async () => {
    const res = await oauth.registerClient(
      new Request("https://mcp.example.com/oauth/register", {
        method: "POST",
        body: JSON.stringify({ redirect_uris: ["https://localhost/callback"] }),
        headers: { "Content-Type": "application/json" },
      }),
    );
    expect(res.status).toBe(400);
  });

  test("accepts private-use URI scheme redirect URIs (RFC 8252 §7.1)", async () => {
    const res = await oauth.registerClient(
      new Request("https://mcp.example.com/oauth/register", {
        method: "POST",
        body: JSON.stringify({ redirect_uris: ["claude://callback"], client_name: "Claude Desktop" }),
        headers: { "Content-Type": "application/json" },
      }),
    );
    expect(res.status).toBe(201);
  });

  test("responds with 201 and full client metadata", async () => {
    const res = await oauth.registerClient(
      new Request("https://mcp.example.com/oauth/register", {
        method: "POST",
        body: JSON.stringify({ redirect_uris: ["https://app.example.com/callback"], client_name: "My App" }),
        headers: { "Content-Type": "application/json" },
      }),
    );
    expect(res.status).toBe(201);
    const body = await res.json() as Record<string, unknown>;
    expect(body.client_id).toMatch(/^vmhq_/);
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.client_name).toBe("My App");
  });
});

// ─── Authorization form ───────────────────────────────────────────────────────

describe("authorization form", () => {
  test("includes required security headers", () => {
    const res = oauth.authorizeForm(new Request("https://mcp.example.com/oauth/authorize"), {});
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  });

  test("uses relative form action (works behind any reverse proxy)", async () => {
    for (const url of [
      "https://mcp.example.com/oauth/authorize",
      "http://127.0.0.1:3000/oauth/authorize",
    ]) {
      const res = oauth.authorizeForm(new Request(url), { publicUrl: "https://mcp.public.example.com" });
      expect(await res.text()).toContain('action="/oauth/authorize"');
    }
  });

  test("renders error messages from query param", async () => {
    const cases = [
      { error: "1", expected: "Invalid token" },
      { error: "client_not_found", expected: "no longer registered" },
      { error: "invalid_redirect_uri", expected: "redirect URI is not registered" },
      { error: "invalid_pkce", expected: "PKCE validation failed" },
    ];
    for (const { error, expected } of cases) {
      const res = oauth.authorizeForm(
        new Request(`https://mcp.example.com/oauth/authorize?error=${error}`),
        {},
      );
      expect(await res.text()).toContain(expected);
    }
  });

  test("preserves resource and scope hidden fields", async () => {
    const res = oauth.authorizeForm(
      new Request(
        "https://mcp.example.com/oauth/authorize?resource=https%3A%2F%2Fmcp.example.com%2Fmcp&scope=mcp",
      ),
      {},
    );
    const html = await res.text();
    expect(html).toContain('name="resource"');
    expect(html).toContain('name="scope"');
  });
});

// ─── POST /oauth/authorize ────────────────────────────────────────────────────

describe("POST /oauth/authorize", () => {
  test("renders form with error=1 on wrong token", async () => {
    const res = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "wrong",
        client_id: "vmhq_test",
        redirect_uri: "https://client.example.com/callback",
        code_challenge: "c",
        code_challenge_method: "S256",
      }),
      "server-secret",
      {},
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid token");
  });

  test("renders form with client_not_found error when client is unknown", async () => {
    const res = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: "vmhq_nonexistent",
        redirect_uri: "https://client.example.com/callback",
        code_challenge: "c",
        code_challenge_method: "S256",
      }),
      "server-secret",
      {},
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("no longer registered");
  });

  test("renders form with invalid_pkce error when PKCE is absent or not S256", async () => {
    const redirectUri = "https://client.example.com/callback";
    const clientId = await register(redirectUri);
    const res = await oauth.authorize(
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
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("PKCE validation failed");
  });
});

// ─── Authorization code + token exchange flow ─────────────────────────────────

describe("authorization code flow", () => {
  test("issues code and exchanges for token (HTTPS redirect URI)", async () => {
    const { tokenRes } = await fullFlow({ redirectUri: "https://client.example.com/callback" });
    expect(tokenRes.status).toBe(200);
    const body = (await tokenRes.json()) as { access_token: string; token_type: string; scope: string };
    expect(body.token_type).toBe("Bearer");
    expect(body.scope).toBe("mcp");
    expect(oauth.isOAuthAccessToken(body.access_token)).toBe(true);
  });

  test("verifyAccessToken returns AuthInfo with clientId and scopes", async () => {
    const { tokenRes, clientId } = await fullFlow({ redirectUri: "https://client2.example.com/cb" });
    const { access_token } = (await tokenRes.json()) as { access_token: string };
    const info = oauth.verifyAccessToken(access_token);
    expect(info).toBeDefined();
    expect(info?.clientId).toBe(clientId);
    expect(info?.scopes).toContain("mcp");
    expect(info?.token).toBe(access_token);
  });

  test("authorization code survives reload from disk (container restart)", async () => {
    const redirectUri = "https://persist.example.com/cb";
    const clientId = await register(redirectUri);
    const verifier = "persist-verifier-restart";
    const authRes = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256(verifier),
        code_challenge_method: "S256",
      }),
      "server-secret",
      {},
    );
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
    const saved = JSON.parse(readFileSync(statePath, "utf-8")) as {
      authorizationCodes?: Array<[string, unknown]>;
    };
    expect(saved.authorizationCodes?.some(([c]) => c === code)).toBe(true);

    oauth.reloadPersistedOAuthState();

    const tokenRes = await oauth.exchangeToken(
      formRequest("https://mcp.example.com/oauth/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }),
    );
    expect(tokenRes.status).toBe(200);
  });

  test("authorization code is single-use", async () => {
    const redirectUri = "https://once.example.com/cb";
    const clientId = await register(redirectUri);
    const verifier = "single-use-verifier-abc";
    const authRes = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256(verifier),
        code_challenge_method: "S256",
      }),
      "server-secret",
      {},
    );
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
    const baseFields = { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier };

    await oauth.exchangeToken(formRequest("https://mcp.example.com/oauth/token", baseFields));
    const replay = await oauth.exchangeToken(formRequest("https://mcp.example.com/oauth/token", baseFields));
    expect(replay.status).toBe(400);
  });

  test("state is forwarded in redirect", async () => {
    const redirectUri = "https://stateful.example.com/cb";
    const clientId = await register(redirectUri);
    const authRes = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256("v"),
        code_challenge_method: "S256",
        state: "xyz123",
      }),
      "server-secret",
      {},
    );
    const redirectUrl = new URL(authRes.headers.get("location")!);
    expect(redirectUrl.searchParams.get("state")).toBe("xyz123");
  });

  test("token exchange accepts JSON body", async () => {
    const redirectUri = "http://127.0.0.1:9876/callback";
    const clientId = await register(redirectUri);
    const verifier = "json-verifier-test";
    const authRes = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256(verifier),
        code_challenge_method: "S256",
      }),
      "server-secret",
      {},
    );
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await oauth.exchangeToken(
      new Request("https://mcp.example.com/oauth/token", {
        method: "POST",
        body: JSON.stringify({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier }),
        headers: { "Content-Type": "application/json" },
      }),
    );
    expect(tokenRes.status).toBe(200);
    const body = (await tokenRes.json()) as { token_type: string };
    expect(body.token_type).toBe("Bearer");
  });
});

// ─── RFC 8252 §7.3 – loopback port-agnostic matching ─────────────────────────

describe("RFC 8252 loopback port-agnostic redirect URI matching", () => {
  test("token exchange succeeds when port differs from registered URI (native app ephemeral port)", async () => {
    // Register with port 9000, authorize and exchange with 9001
    const { tokenRes } = await fullFlow({
      redirectUri: "http://127.0.0.1:9000/callback",
      tokenRedirectUri: "http://127.0.0.1:9001/callback",
    });
    expect(tokenRes.status).toBe(200);
  });

  test("authorize accepts loopback redirect URI with different port from registered", async () => {
    const clientId = await register("http://localhost:8000/cb");
    const res = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: "http://localhost:8888/cb",
        code_challenge: s256("verifier"),
        code_challenge_method: "S256",
      }),
      "server-secret",
      {},
    );
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).not.toContain("error=");
  });

  test("non-loopback URIs still require exact match", async () => {
    const clientId = await register("https://app.example.com/callback");
    const res = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: "https://app.example.com/different",
        code_challenge: s256("verifier"),
        code_challenge_method: "S256",
      }),
      "server-secret",
      {},
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("redirect URI is not registered");
  });
});

// ─── RFC 8707 – resource indicators ──────────────────────────────────────────

describe("RFC 8707 resource indicators", () => {
  test("resource is stored in token and returned in AuthInfo", async () => {
    const resource = "https://mcp.example.com/mcp";
    const { tokenRes } = await fullFlow({
      redirectUri: "https://resource-test.example.com/cb",
      resource,
    });
    expect(tokenRes.status).toBe(200);
    const { access_token } = (await tokenRes.json()) as { access_token: string };
    const info = oauth.verifyAccessToken(access_token);
    expect(info?.resource?.toString()).toBe(resource);
  });

  test("token exchange rejects mismatched resource indicator", async () => {
    const redirectUri = "https://mismatch.example.com/cb";
    const clientId = await register(redirectUri);
    const verifier = "resource-mismatch-verifier";
    const authRes = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256(verifier),
        code_challenge_method: "S256",
        resource: "https://mcp.example.com/mcp",
      }),
      "server-secret",
      {},
    );
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await oauth.exchangeToken(
      formRequest("https://mcp.example.com/oauth/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
        resource: "https://different-server.example.com/mcp",
      }),
    );
    expect(tokenRes.status).toBe(400);
    const body = (await tokenRes.json()) as { error: string };
    expect(body.error).toBe("invalid_target");
  });

  test("token exchange succeeds when resource matches", async () => {
    const resource = "https://mcp.example.com/mcp";
    const redirectUri = "https://resource-match.example.com/cb";
    const clientId = await register(redirectUri);
    const verifier = "resource-match-verifier";
    const authRes = await oauth.authorize(
      formRequest("https://mcp.example.com/oauth/authorize", {
        token: "server-secret",
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256(verifier),
        code_challenge_method: "S256",
        resource,
      }),
      "server-secret",
      {},
    );
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
    const tokenRes = await oauth.exchangeToken(
      formRequest("https://mcp.example.com/oauth/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
        resource,
      }),
    );
    expect(tokenRes.status).toBe(200);
  });
});

// ─── Scope passthrough ────────────────────────────────────────────────────────

describe("scope passthrough", () => {
  test("custom scopes from authorize are preserved in token response", async () => {
    const { tokenRes } = await fullFlow({
      redirectUri: "https://scope-test.example.com/cb",
      scope: "mcp read write",
    });
    const body = (await tokenRes.json()) as { scope: string };
    expect(body.scope.split(" ")).toEqual(expect.arrayContaining(["mcp", "read", "write"]));
  });
});

// ─── Token revocation ─────────────────────────────────────────────────────────

describe("token revocation", () => {
  test("revoked token is no longer valid", async () => {
    const { tokenRes } = await fullFlow({ redirectUri: "https://revoke-test.example.com/cb" });
    const { access_token } = (await tokenRes.json()) as { access_token: string };
    expect(oauth.isOAuthAccessToken(access_token)).toBe(true);

    const revokeRes = await oauth.revokeToken(
      formRequest("https://mcp.example.com/oauth/revoke", { token: access_token }),
    );
    expect(revokeRes.status).toBe(200);
    expect(oauth.isOAuthAccessToken(access_token)).toBe(false);
    expect(oauth.verifyAccessToken(access_token)).toBeUndefined();
  });

  test("revoking an unknown token returns 200 (RFC 7009 §2.2)", async () => {
    const res = await oauth.revokeToken(
      formRequest("https://mcp.example.com/oauth/revoke", { token: "not-a-real-token" }),
    );
    expect(res.status).toBe(200);
  });
});

// ─── Metadata endpoints ───────────────────────────────────────────────────────

describe("metadata endpoints", () => {
  test("protected resource metadata contains required fields", async () => {
    const res = oauth.protectedResourceMetadata({}, new Request("https://mcp.example.com/path"));
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.resource).toContain("/mcp");
    expect(Array.isArray(body.authorization_servers)).toBe(true);
    expect(body.bearer_methods_supported).toContain("header");
  });

  test("authorization server metadata contains required fields", async () => {
    const res = oauth.authorizationServerMetadata({}, new Request("https://mcp.example.com/path"));
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.issuer).toBe("https://mcp.example.com");
    expect(body.authorization_endpoint).toContain("/oauth/authorize");
    expect(body.token_endpoint).toContain("/oauth/token");
    expect(body.registration_endpoint).toContain("/oauth/register");
    expect(body.code_challenge_methods_supported).toContain("S256");
    expect(body.grant_types_supported).toContain("authorization_code");
  });

  test("authorization server metadata uses publicUrl when configured", async () => {
    const res = oauth.authorizationServerMetadata(
      { publicUrl: "https://public.example.com" },
      new Request("http://internal:3000/ignored"),
    );
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.issuer).toBe("https://public.example.com");
    expect(body.authorization_endpoint).toContain("https://public.example.com");
  });
});
