import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

type OAuthModule = typeof import("../src/oauth.js");

const statePath = join(import.meta.dir, ".oauth-test-state.json");
let oauth: OAuthModule;

// ─── PocketID (OIDC provider) mock ──────────────────────────────────────────────
// The bridge flow calls PocketID's discovery + token endpoints via global fetch.
// We stub fetch so the suite runs offline and we control success/failure.

const POCKETID_ISSUER = "https://id.example.com";
const POCKETID_AUTHORIZE = `${POCKETID_ISSUER}/authorize`;
const POCKETID_TOKEN = `${POCKETID_ISSUER}/token`;

const testConfig = {
  publicUrl: "https://mcp.example.com",
  pocketId: {
    issuer: POCKETID_ISSUER,
    clientId: "mcp-client",
    clientSecret: "mcp-secret",
    scopes: ["openid", "profile", "email"],
  },
};

/** When set, the mocked PocketID token endpoint returns an error. */
let pocketIdTokenShouldFail = false;
const originalFetch = globalThis.fetch;

function installPocketIdMock(): void {
  // @ts-expect-error - test stub matches the subset of fetch we use
  globalThis.fetch = async (input: string | URL | Request): Promise<Response> => {
    const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (urlStr.endsWith("/.well-known/openid-configuration")) {
      return Response.json({
        issuer: POCKETID_ISSUER,
        authorization_endpoint: POCKETID_AUTHORIZE,
        token_endpoint: POCKETID_TOKEN,
      });
    }
    if (urlStr === POCKETID_TOKEN) {
      if (pocketIdTokenShouldFail) {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
      return Response.json({ access_token: "pocket-access", id_token: "pocket-id", token_type: "Bearer" });
    }
    throw new Error(`unexpected fetch in test: ${urlStr}`);
  };
}

beforeAll(async () => {
  rmSync(statePath, { force: true });
  process.env.MCP_LOG_LEVEL = "silent";
  process.env.MCP_OAUTH_STATE_PATH = statePath;
  installPocketIdMock();
  oauth = await import("../src/oauth.js");
});

beforeEach(() => {
  pocketIdTokenShouldFail = false;
  oauth.resetPocketIdDiscoveryCache();
});

afterAll(() => {
  globalThis.fetch = originalFetch;
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

function authorizeRequest(fields: Record<string, string>): Request {
  const u = new URL("https://mcp.example.com/oauth/authorize");
  for (const [k, v] of Object.entries(fields)) u.searchParams.set(k, v);
  return new Request(u.toString());
}

function redirectUrlFromSuccessPage(html: string): string {
  const match = html.match(/content="0;url=([^"]+)"/);
  if (!match) throw new Error("success page missing redirect URL");
  return match[1].replace(/&amp;/g, "&");
}

/** Extract the PocketID sign-in URL from the intermediate consent page. */
function pocketIdUrlFromConsentPage(html: string): string {
  const match = html.match(/class="btn" href="([^"]+)"/);
  if (!match) throw new Error("consent page missing PocketID sign-in URL");
  return match[1].replace(/&amp;/g, "&");
}

/**
 * Drive the full bridge flow: GET /oauth/authorize → PocketID redirect →
 * GET /oauth/callback → MCP authorization code. Returns the issued MCP code.
 */
async function authorizeViaPocketId(opts: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  scope?: string;
  resource?: string;
}): Promise<{ code: string; finalState: string | null }> {
  const fields: Record<string, string> = {
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    code_challenge: opts.codeChallenge,
    code_challenge_method: "S256",
    state: opts.state ?? "abc",
  };
  if (opts.scope) fields.scope = opts.scope;
  if (opts.resource) fields.resource = opts.resource;

  const beginRes = await oauth.beginAuthorize(authorizeRequest(fields), testConfig);
  expect(beginRes.status).toBe(200);
  const pocketIdUrl = pocketIdUrlFromConsentPage(await beginRes.text());
  expect(pocketIdUrl).toContain(POCKETID_AUTHORIZE);
  const txn = new URL(pocketIdUrl).searchParams.get("state")!;
  expect(txn).toBeTruthy();

  const cbRes = await oauth.oauthCallback(
    new Request(`https://mcp.example.com/oauth/callback?code=pocket-code&state=${txn}`),
    testConfig,
  );
  expect(cbRes.status).toBe(200);
  const finalUrl = new URL(redirectUrlFromSuccessPage(await cbRes.text()));
  return { code: finalUrl.searchParams.get("code")!, finalState: finalUrl.searchParams.get("state") };
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

  const { code } = await authorizeViaPocketId({
    clientId,
    redirectUri: opts.redirectUri,
    codeChallenge: challenge,
    scope: opts.scope,
    resource: opts.resource,
  });
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

  test("expands legacy Claude web callback to canonical URI on registration", async () => {
    const res = await oauth.registerClient(
      new Request("https://mcp.example.com/oauth/register", {
        method: "POST",
        body: JSON.stringify({ redirect_uris: ["https://claude.ai/callback"], client_name: "Claude" }),
        headers: { "Content-Type": "application/json" },
      }),
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as { redirect_uris: string[] };
    expect(body.redirect_uris).toContain("https://claude.ai/callback");
    expect(body.redirect_uris).toContain(oauth.CLAUDE_WEB_AUTH_CALLBACK);
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

// ─── GET /oauth/authorize (redirect to PocketID) ──────────────────────────────

describe("GET /oauth/authorize", () => {
  test("shows a consent page linking to PocketID with PKCE and a transaction state", async () => {
    const redirectUri = "https://client.example.com/callback";
    const clientId = await register(redirectUri);
    const res = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256("v"),
        code_challenge_method: "S256",
        state: "client-state",
      }),
      testConfig,
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Sign in with PocketID");
    const location = new URL(pocketIdUrlFromConsentPage(html));
    expect(location.origin + location.pathname).toBe(POCKETID_AUTHORIZE);
    expect(location.searchParams.get("client_id")).toBe("mcp-client");
    expect(location.searchParams.get("redirect_uri")).toBe("https://mcp.example.com/oauth/callback");
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    expect(location.searchParams.get("code_challenge")).toBeTruthy();
    expect(location.searchParams.get("state")).toBeTruthy();
  });

  test("errors when PocketID is not configured", async () => {
    const res = await oauth.beginAuthorize(
      authorizeRequest({ client_id: "vmhq_x", redirect_uri: "https://x/cb", code_challenge: "c", code_challenge_method: "S256" }),
      { publicUrl: "https://mcp.example.com" },
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("not configured");
  });

  test("errors with client_not_found when client is unknown", async () => {
    const res = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: "vmhq_nonexistent",
        redirect_uri: "https://client.example.com/callback",
        code_challenge: "c",
        code_challenge_method: "S256",
      }),
      testConfig,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("no longer registered");
  });

  test("errors with invalid PKCE when challenge absent or not S256", async () => {
    const redirectUri = "https://client.example.com/callback";
    const clientId = await register(redirectUri);
    const res = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: "",
        code_challenge_method: "",
      }),
      testConfig,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("PKCE validation failed");
  });
});

// ─── GET /oauth/callback ──────────────────────────────────────────────────────

describe("GET /oauth/callback", () => {
  test("errors on unknown transaction", async () => {
    const res = await oauth.oauthCallback(
      new Request("https://mcp.example.com/oauth/callback?code=x&state=does-not-exist"),
      testConfig,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("expired");
  });

  test("errors when PocketID returns an error param", async () => {
    const res = await oauth.oauthCallback(
      new Request("https://mcp.example.com/oauth/callback?error=access_denied&state=whatever"),
      testConfig,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("denied");
  });

  test("errors when PocketID token exchange fails", async () => {
    const redirectUri = "https://client.example.com/callback";
    const clientId = await register(redirectUri);
    const beginRes = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256("v"),
        code_challenge_method: "S256",
      }),
      testConfig,
    );
    const txn = new URL(pocketIdUrlFromConsentPage(await beginRes.text())).searchParams.get("state")!;

    pocketIdTokenShouldFail = true;
    const res = await oauth.oauthCallback(
      new Request(`https://mcp.example.com/oauth/callback?code=pocket-code&state=${txn}`),
      testConfig,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("failed");
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
    const { code } = await authorizeViaPocketId({ clientId, redirectUri, codeChallenge: s256(verifier) });

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
    const { code } = await authorizeViaPocketId({ clientId, redirectUri, codeChallenge: s256(verifier) });
    const baseFields = { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier };

    await oauth.exchangeToken(formRequest("https://mcp.example.com/oauth/token", baseFields));
    const replay = await oauth.exchangeToken(formRequest("https://mcp.example.com/oauth/token", baseFields));
    expect(replay.status).toBe(400);
  });

  test("client state is forwarded in the final redirect", async () => {
    const redirectUri = "https://stateful.example.com/cb";
    const clientId = await register(redirectUri);
    const { finalState } = await authorizeViaPocketId({
      clientId,
      redirectUri,
      codeChallenge: s256("v"),
      state: "xyz123",
    });
    expect(finalState).toBe("xyz123");
  });

  test("token exchange accepts JSON body", async () => {
    const redirectUri = "http://127.0.0.1:9876/callback";
    const clientId = await register(redirectUri);
    const verifier = "json-verifier-test";
    const { code } = await authorizeViaPocketId({ clientId, redirectUri, codeChallenge: s256(verifier) });

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

describe("Claude web redirect URI", () => {
  test("success page redirects legacy claude.ai/callback to api/mcp/auth_callback", async () => {
    const clientId = await register("https://claude.ai/callback");
    const verifier = "claude-web-verifier";
    const { code, finalState } = await authorizeViaPocketId({
      clientId,
      redirectUri: "https://claude.ai/callback",
      codeChallenge: s256(verifier),
      state: "claude-state",
    });
    expect(finalState).toBe("claude-state");

    const tokenRes = await oauth.exchangeToken(
      formRequest("https://mcp.example.com/oauth/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://claude.ai/callback",
        client_id: clientId,
        code_verifier: verifier,
      }),
    );
    expect(tokenRes.status).toBe(200);
  });

  test("callback redirect URL uses the canonical Claude web callback host", async () => {
    const clientId = await register("https://claude.ai/callback");
    const fields = {
      client_id: clientId,
      redirect_uri: "https://claude.ai/callback",
      code_challenge: s256("v"),
      code_challenge_method: "S256",
      state: "s",
    };
    const beginRes = await oauth.beginAuthorize(authorizeRequest(fields), testConfig);
    const txn = new URL(pocketIdUrlFromConsentPage(await beginRes.text())).searchParams.get("state")!;
    const cbRes = await oauth.oauthCallback(
      new Request(`https://mcp.example.com/oauth/callback?code=pocket-code&state=${txn}`),
      testConfig,
    );
    const redirectUrl = redirectUrlFromSuccessPage(await cbRes.text());
    expect(redirectUrl).toContain("https://claude.ai/api/mcp/auth_callback");
    expect(redirectUrl).toContain("code=");
  });
});

describe("RFC 8252 loopback port-agnostic redirect URI matching", () => {
  test("token exchange succeeds when port differs from registered URI (native app ephemeral port)", async () => {
    const { tokenRes } = await fullFlow({
      redirectUri: "http://127.0.0.1:9000/callback",
      tokenRedirectUri: "http://127.0.0.1:9001/callback",
    });
    expect(tokenRes.status).toBe(200);
  });

  test("authorize accepts loopback redirect URI with different port from registered", async () => {
    const clientId = await register("http://localhost:8000/cb");
    const { code } = await authorizeViaPocketId({
      clientId,
      redirectUri: "http://localhost:8888/cb",
      codeChallenge: s256("verifier"),
    });
    expect(code).toBeTruthy();
  });

  test("non-loopback URIs still require exact match", async () => {
    const clientId = await register("https://app.example.com/callback");
    const res = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: clientId,
        redirect_uri: "https://app.example.com/different",
        code_challenge: s256("verifier"),
        code_challenge_method: "S256",
      }),
      testConfig,
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
    const { code } = await authorizeViaPocketId({
      clientId,
      redirectUri,
      codeChallenge: s256(verifier),
      resource: "https://mcp.example.com/mcp",
    });

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
    const { code } = await authorizeViaPocketId({
      clientId,
      redirectUri,
      codeChallenge: s256(verifier),
      resource,
    });
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

  // Characterization test (RFC 8707 §2.2): omitting `resource` in the token
  // request is conformant — the issued token keeps the resource bound to the
  // authorization code at authorize time.
  test("token exchange without resource keeps the authorize-time resource bound to the token", async () => {
    const resource = "https://mcp.example.com/mcp";
    const redirectUri = "https://resource-omission.example.com/cb";
    const clientId = await register(redirectUri);
    const verifier = "verifier-8707-omission";
    const { code } = await authorizeViaPocketId({
      clientId,
      redirectUri,
      codeChallenge: s256(verifier),
      resource,
    });
    // omitting `resource` entirely in the token request
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
    const body = (await tokenRes.json()) as { access_token: string };
    const info = oauth.verifyAccessToken(body.access_token);
    expect(info?.resource?.toString()).toBe(resource);
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

// ─── Resource indicator validation (RFC 8707 §2.1) ───────────────────────────

describe("resource indicator validation", () => {
  test("authorize rejects a non-URL resource indicator", async () => {
    const clientId = await register("https://client.example.com/cb");
    const res = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: clientId,
        redirect_uri: "https://client.example.com/cb",
        code_challenge: s256("verifier-resource"),
        code_challenge_method: "S256",
        resource: "not-a-url",
      }),
      testConfig,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("resource");
  });

  test("verifyAccessToken tolerates a legacy invalid resource value", async () => {
    const { accessTokens } = await import("../src/oauth/state.js");
    const token = "legacy-bad-resource-token";
    accessTokens.set(s256(token), {
      clientId: "legacy-client",
      scopes: ["mcp"],
      resource: "not a url",
      expiresAt: Date.now() + 60_000,
    });
    const info = oauth.verifyAccessToken(token);
    expect(info).toBeDefined();
    expect(info?.resource).toBeUndefined();
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
