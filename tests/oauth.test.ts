import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from "jose";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
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
const POCKETID_JWKS = `${POCKETID_ISSUER}/jwks`;
const POCKETID_CLIENT_ID = "mcp-client";

/**
 * The id_token is verified against the provider's JWKS now, so the mock signs
 * real tokens with a real key: a stub string would only prove the mock works.
 */
let signingKeys: { privateKey: CryptoKey; publicJwk: JWK };
let attackerKeys: { privateKey: CryptoKey; publicJwk: JWK };

const DEFAULT_CLAIMS = { sub: "user-123", email: "vicente@example.com", name: "Vicente" };

/** Overrides applied to the next issued id_token, for the rejection cases. */
let idTokenOverride:
  | { claims?: Record<string, unknown>; issuer?: string; audience?: string; expSecondsFromNow?: number; signWithWrongKey?: boolean; omit?: boolean }
  | undefined;

async function makeIdToken(): Promise<string> {
  const o = idTokenOverride ?? {};
  const key = o.signWithWrongKey ? attackerKeys.privateKey : signingKeys.privateKey;
  return new SignJWT({ ...DEFAULT_CLAIMS, ...(o.claims ?? {}) })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(o.issuer ?? POCKETID_ISSUER)
    .setAudience(o.audience ?? POCKETID_CLIENT_ID)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + (o.expSecondsFromNow ?? 3600))
    .sign(key);
}

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
        jwks_uri: POCKETID_JWKS,
      });
    }
    if (urlStr === POCKETID_JWKS) {
      return Response.json({ keys: [{ ...signingKeys.publicJwk, alg: "RS256", use: "sig" }] });
    }
    if (urlStr === POCKETID_TOKEN) {
      if (pocketIdTokenShouldFail) {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
      return Response.json({
        access_token: "pocket-access",
        token_type: "Bearer",
        ...(idTokenOverride?.omit ? {} : { id_token: await makeIdToken() }),
      });
    }
    throw new Error(`unexpected fetch in test: ${urlStr}`);
  };
}

beforeAll(async () => {
  const [real, attacker] = await Promise.all([
    generateKeyPair("RS256", { extractable: true }),
    generateKeyPair("RS256", { extractable: true }),
  ]);
  signingKeys = { privateKey: real.privateKey, publicJwk: await exportJWK(real.publicKey) };
  attackerKeys = { privateKey: attacker.privateKey, publicJwk: await exportJWK(attacker.publicKey) };

  rmSync(statePath, { force: true });
  process.env.MCP_LOG_LEVEL = "silent";
  process.env.MCP_OAUTH_STATE_PATH = statePath;
  installPocketIdMock();
  oauth = await import("../src/oauth.js");
});

beforeEach(() => {
  pocketIdTokenShouldFail = false;
  idTokenOverride = undefined;
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
const consentCookies = new Map<string, string>();
async function pocketIdUrlFromConsentPage(html: string, response: Response): Promise<string> {
  const txn = html.match(/name="transaction" value="([^"]+)"/)![1]!;
  const cookie = response.headers.get("set-cookie")!.split(";")[0]!;
  consentCookies.set(txn, cookie);
  const approved = await oauth.approveAuthorize(new Request("https://mcp.example.com/oauth/authorize", {
    method: "POST", headers: { origin: "https://mcp.example.com", cookie },
    body: new URLSearchParams({transaction: txn}),
  }), testConfig);
  expect(approved.status).toBe(303);
  return approved.headers.get("location")!;
}

describe("browser-bound consent", () => {
  test("rejects missing/foreign cookies, cross-origin POSTs, callback before approval and replay", async () => {
    const clientId = await register("https://client.example.com/cb");
    const page = await oauth.beginAuthorize(authorizeRequest({client_id:clientId, redirect_uri:"https://client.example.com/cb",code_challenge:s256("a".repeat(43)),code_challenge_method:"S256"}), testConfig);
    const html = await page.text();
    expect(html).not.toContain(POCKETID_AUTHORIZE);
    expect(page.headers.get("set-cookie")).toContain("HttpOnly");
    expect(page.headers.get("set-cookie")).toContain("Secure");
    const txn = html.match(/name="transaction" value="([^"]+)"/)![1]!;
    const cookie = page.headers.get("set-cookie")!.split(";")[0]!;
    const approve = (cookieValue: string, origin = "https://mcp.example.com") => oauth.approveAuthorize(new Request("https://mcp.example.com/oauth/authorize", {method:"POST",headers:{cookie:cookieValue,origin},body:new URLSearchParams({transaction:txn})}),testConfig);
    const callback = (cookieValue: string) => oauth.oauthCallback(new Request(`https://mcp.example.com/oauth/callback?code=pocket-code&state=${txn}`,{headers:{cookie:cookieValue}}),testConfig);
    expect((await callback(cookie)).status).toBe(400);
    expect((await approve("")).status).toBe(400);
    expect((await approve(cookie+"wrong")).status).toBe(400);
    expect((await approve(cookie,"https://attacker.example")).status).toBe(400);
    expect((await approve(cookie)).status).toBe(303);
    expect((await approve(cookie)).status).toBe(400);
    // A transferred IdP link does not grant access in the recipient's browser.
    expect((await callback("")).status).toBe(400);
    expect((await callback(cookie+"wrong")).status).toBe(400);
    expect((await callback(cookie)).status).toBe(200);
    expect((await callback(cookie)).status).toBe(400);
  });
});

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
  const pocketIdUrl = await pocketIdUrlFromConsentPage(await beginRes.text(), beginRes);
  expect(pocketIdUrl).toContain(POCKETID_AUTHORIZE);
  const txn = new URL(pocketIdUrl).searchParams.get("state")!;
  expect(txn).toBeTruthy();

  const cbRes = await oauth.oauthCallback(
    new Request(`https://mcp.example.com/oauth/callback?code=pocket-code&state=${txn}`, { headers: { cookie: consentCookies.get(txn) ?? "" } }),
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
    expect(html).toContain("Approve and sign in with PocketID");
    const location = new URL(await pocketIdUrlFromConsentPage(html, res));
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
    const txn = new URL(await pocketIdUrlFromConsentPage(await beginRes.text(), beginRes)).searchParams.get("state")!;

    pocketIdTokenShouldFail = true;
    const res = await oauth.oauthCallback(
      new Request(`https://mcp.example.com/oauth/callback?code=pocket-code&state=${txn}`, { headers: { cookie: consentCookies.get(txn) ?? "" } }),
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
    const txn = new URL(await pocketIdUrlFromConsentPage(await beginRes.text(), beginRes)).searchParams.get("state")!;
    const cbRes = await oauth.oauthCallback(
      new Request(`https://mcp.example.com/oauth/callback?code=pocket-code&state=${txn}`, { headers: { cookie: consentCookies.get(txn) ?? "" } }),
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

  test("verifyAccessToken tolerates a persisted invalid resource value", async () => {
    const { accessTokens } = await import("../src/oauth/state.js");
    const token = "bad-resource-token";
    accessTokens.set(s256(token), {
      clientId: "some-client",
      scopes: ["mcp"],
      resource: "not a url",
      identity: { subject: "user-123", email: "vicente@example.com" },
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

describe("DCR client expiry", () => {
  test("prune removes clients older than CLIENT_TTL_MS", async () => {
    const { clients, CLIENT_TTL_MS } = await import("../src/oauth/state.js");
    const clientId = await register("https://client.example.com/cb");
    const stale = clients.get(clientId)!;
    clients.set(clientId, {
      ...stale,
      clientIdIssuedAt: Math.floor((Date.now() - CLIENT_TTL_MS - 1000) / 1000),
    });
    oauth.pruneExpiredOAuthState();
    expect(clients.has(clientId)).toBe(false);
  });

  test("reload backfills a missing clientIdIssuedAt so prune can age the client out", async () => {
    const { writeFileSync } = await import("node:fs");
    const { clients } = await import("../src/oauth/state.js");
    const legacyId = "vmhq_legacy_no_issued_at";
    // Mimic a client persisted before clientIdIssuedAt existed (no timestamp).
    writeFileSync(
      statePath,
      JSON.stringify({
        clients: [[legacyId, { clientId: legacyId, redirectUris: ["https://legacy.example.com/cb"], clientName: "Legacy" }]],
        authorizationCodes: [],
        pendingAuth: [],
        accessTokens: [],
      }),
    );
    oauth.reloadPersistedOAuthState();
    const loaded = clients.get(legacyId);
    expect(loaded).toBeDefined();
    expect(Number.isFinite(loaded!.clientIdIssuedAt)).toBe(true);
    // Backfilled to "now", so a prune keeps it (fresh TTL, not nuked on sight).
    oauth.pruneExpiredOAuthState();
    expect(clients.has(legacyId)).toBe(true);
  });

  test("prune removes a client whose timestamp is non-finite", async () => {
    const { clients } = await import("../src/oauth/state.js");
    const id = "vmhq_nan_issued_at";
    clients.set(id, { clientId: id, clientIdIssuedAt: Number.NaN, redirectUris: ["https://x.example.com/cb"] });
    oauth.pruneExpiredOAuthState();
    expect(clients.has(id)).toBe(false);
  });
});

describe("token lifetimes", () => {
  test("access tokens last a day and refresh tokens carry the long tail", async () => {
    const { TOKEN_TTL_S, REFRESH_TOKEN_TTL_S } = await import("../src/oauth/state.js");
    expect(TOKEN_TTL_S).toBe(60 * 60 * 24);
    expect(REFRESH_TOKEN_TTL_S).toBe(60 * 60 * 24 * 30);
  });

  test("clients are pruned against the longest credential they can hold", async () => {
    // A client pruned before its own refresh token expires would break the
    // refresh grant it was issued for.
    const { CLIENT_TTL_MS, REFRESH_TOKEN_TTL_S } = await import("../src/oauth/state.js");
    expect(CLIENT_TTL_MS).toBeGreaterThan(REFRESH_TOKEN_TTL_S * 1000);
  });
});

describe("oversized OAuth request bodies", () => {
  test("token endpoint rejects a body over the size cap with 413", async () => {
    const { MAX_REQUEST_BODY_BYTES } = await import("../src/httpGuards.js");
    const oversized = "a".repeat(MAX_REQUEST_BODY_BYTES + 1);
    const res = await oauth.exchangeToken(
      new Request("https://mcp.example.com/oauth/token", {
        method: "POST",
        body: `grant_type=authorization_code&code=${oversized}`,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }),
    );
    expect(res.status).toBe(413);
  });
});

describe("state file permissions", () => {
  test("persists oauth state with 0600 permissions", async () => {
    const { statSync } = await import("node:fs");
    await register("https://client.example.com/cb");
    expect(statSync(statePath).mode & 0o777).toBe(0o600);
  });
});

/**
 * Dynamic client registration is public and accepts any HTTPS host, so the
 * consent page and the destination allowlist are the only things standing
 * between a stranger's client and a token that carries a root shell.
 */
describe("redirect destination control", () => {
  const ALLOWLIST = "MCP_ALLOWED_REDIRECT_HOSTS";
  const originalAllowlist = process.env[ALLOWLIST];

  afterEach(() => {
    if (originalAllowlist === undefined) delete process.env[ALLOWLIST];
    else process.env[ALLOWLIST] = originalAllowlist;
  });

  test("registration refuses a destination outside the allowlist", async () => {
    process.env[ALLOWLIST] = "claude.ai";
    const res = await oauth.registerClient(
      new Request("https://mcp.example.com/oauth/register", {
        method: "POST",
        body: JSON.stringify({ redirect_uris: ["https://evil.example.com/cb"], client_name: "Claude" }),
        headers: { "Content-Type": "application/json" },
      }),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_redirect_uris" });
  });

  test("registration accepts allowlisted hosts and their subdomains", async () => {
    process.env[ALLOWLIST] = "claude.ai";
    for (const uri of ["https://claude.ai/api/mcp/auth_callback", "https://api.claude.ai/cb"]) {
      const res = await oauth.registerClient(
        new Request("https://mcp.example.com/oauth/register", {
          method: "POST",
          body: JSON.stringify({ redirect_uris: [uri] }),
          headers: { "Content-Type": "application/json" },
        }),
      );
      expect(res.status).toBe(201);
    }
  });

  test("loopback and native-app schemes stay usable under an allowlist", async () => {
    process.env[ALLOWLIST] = "claude.ai";
    for (const uri of ["http://127.0.0.1:8976/callback", "http://localhost:1455/cb", "cursor://anysphere.cursor-mcp/oauth/cb"]) {
      const res = await oauth.registerClient(
        new Request("https://mcp.example.com/oauth/register", {
          method: "POST",
          body: JSON.stringify({ redirect_uris: [uri] }),
          headers: { "Content-Type": "application/json" },
        }),
      );
      expect(res.status).toBe(201);
    }
  });

  test("a client registered before the allowlist cannot authorize afterwards", async () => {
    // Registered while everything was allowed…
    delete process.env[ALLOWLIST];
    const redirectUri = "https://evil.example.com/cb";
    const clientId = await register(redirectUri);

    // …and blocked once the allowlist exists, without needing to prune state.
    process.env[ALLOWLIST] = "claude.ai";
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
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("evil.example.com");
  });

  test("without an allowlist the consent page names the destination and nothing else about the server", async () => {
    delete process.env[ALLOWLIST];
    const redirectUri = "https://evil.example.com/cb";
    const res = await oauth.registerClient(
      new Request("https://mcp.example.com/oauth/register", {
        method: "POST",
        body: JSON.stringify({ redirect_uris: [redirectUri], client_name: "Claude" }),
        headers: { "Content-Type": "application/json" },
      }),
    );
    const { client_id: clientId } = (await res.json()) as { client_id: string };

    const page = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256("v"),
        code_challenge_method: "S256",
        state: "client-state",
      }),
      testConfig,
    );
    const html = await page.text();

    expect(html).toContain("Claude");
    // With no allowlist any registrant can ask for a code, so the one thing
    // the person clicking can check is where the code will go. The host is
    // data the registrant supplied, not a description of this server.
    expect(html).toContain("evil.example.com");
    // Nothing about what a token reaches, or how the server is configured,
    // may leak to an unauthenticated visitor.
    expect(html).not.toMatch(/root shell|read and write access|proxmox|miniflux/i);
    expect(html).not.toContain("<li>");
    expect(html).not.toContain("No destination allowlist is configured");
  });

  test("with an allowlist enforced the consent page shows only the client name", async () => {
    process.env[ALLOWLIST] = "client.example.com";
    const redirectUri = "https://client.example.com/cb";
    const clientId = await register(redirectUri);
    const page = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256("v"),
        code_challenge_method: "S256",
        state: "client-state",
      }),
      testConfig,
    );
    const html = await page.text();
    expect(html).toContain("Test Client");
    expect(html).toContain("client.example.com</strong>");
    expect(html).not.toContain("<li>");
  });

  test("the consent page lets the browser follow the approval redirect to PocketID", async () => {
    // Chrome applies form-action to the redirect chain after a form POST, so
    // the provider origin must be listed or the 303 to PocketID is blocked.
    process.env[ALLOWLIST] = "client.example.com";
    const redirectUri = "https://client.example.com/cb";
    const clientId = await register(redirectUri);
    const page = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256("v"),
        code_challenge_method: "S256",
        state: "client-state",
      }),
      testConfig,
    );
    const csp = page.headers.get("content-security-policy") ?? "";
    expect(csp).toContain(`form-action 'self' ${new URL(POCKETID_AUTHORIZE).origin}`);
  });

  test("the client name cannot inject markup into the consent page", async () => {
    delete process.env[ALLOWLIST];
    const redirectUri = "https://client.example.com/cb";
    const res = await oauth.registerClient(
      new Request("https://mcp.example.com/oauth/register", {
        method: "POST",
        body: JSON.stringify({ redirect_uris: [redirectUri], client_name: "<img src=x onerror=alert(1)>" }),
        headers: { "Content-Type": "application/json" },
      }),
    );
    const { client_id: clientId } = (await res.json()) as { client_id: string };
    const page = await oauth.beginAuthorize(
      authorizeRequest({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: s256("v"),
        code_challenge_method: "S256",
        state: "client-state",
      }),
      testConfig,
    );
    const html = await page.text();
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img src=x");
  });
});

type TokenResponse = { access_token: string; refresh_token: string; expires_in: number; scope: string };

/** Runs the whole bridge flow and returns the issued token pair. */
async function fullFlowTokens(): Promise<TokenResponse> {
  const { tokenRes } = await fullFlow({ redirectUri: "https://client.example.com/cb" });
  expect(tokenRes.status).toBe(200);
  return (await tokenRes.json()) as TokenResponse;
}

async function fullFlowAccessToken(): Promise<string> {
  return (await fullFlowTokens()).access_token;
}

/** The issued token pair together with the client that owns it, for refreshes. */
async function fullFlowSession(): Promise<TokenResponse & { clientId: string }> {
  const { tokenRes, clientId } = await fullFlow({ redirectUri: "https://client.example.com/cb" });
  expect(tokenRes.status).toBe(200);
  return { ...((await tokenRes.json()) as TokenResponse), clientId };
}

function postToken(fields: Record<string, string>): Promise<Response> {
  return oauth.exchangeToken(formRequest("https://mcp.example.com/oauth/token", fields));
}

async function refresh(refreshToken: string, clientId: string): Promise<TokenResponse> {
  const res = await postToken({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId });
  expect(res.status).toBe(200);
  return (await res.json()) as TokenResponse;
}

/** Drives authorize → callback and returns the error page text. */
async function callbackFails(): Promise<string> {
  const redirectUri = "https://client.example.com/cb";
  const clientId = await register(redirectUri);
  const beginRes = await oauth.beginAuthorize(
    authorizeRequest({
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: s256("v"),
      code_challenge_method: "S256",
      state: "abc",
    }),
    testConfig,
  );
  const txn = new URL(await pocketIdUrlFromConsentPage(await beginRes.text(), beginRes)).searchParams.get("state")!;
  const cbRes = await oauth.oauthCallback(
    new Request(`https://mcp.example.com/oauth/callback?code=pocket-code&state=${txn}`, { headers: { cookie: consentCookies.get(txn) ?? "" } }),
    testConfig,
  );
  expect(cbRes.status).toBe(400);
  return cbRes.text();
}

/**
 * The access token is what carries a root shell on the hypervisor, so who holds
 * one has to be answerable, and a leaked one has to be both short-lived and
 * cuttable. These cover the identity bound to the token and the refresh
 * lifecycle that replaces the old 30-day bearer.
 */
describe("identity bound to the token", () => {
  test("the signed-in person is carried from PocketID through to the access token", async () => {
    const token = await fullFlowAccessToken();
    const info = oauth.verifyAccessToken(token)!;
    expect(info.extra?.actor).toBe("vicente@example.com");
    expect(info.extra?.identity).toEqual({ subject: "user-123", email: "vicente@example.com" });
  });

  test("falls back to the subject when the provider asserts no email", async () => {
    idTokenOverride = { claims: { sub: "user-456", email: undefined } };
    const token = await fullFlowAccessToken();
    expect(oauth.verifyAccessToken(token)!.extra?.actor).toBe("user-456");
  });

  test("rejects an id_token signed by the wrong key", async () => {
    idTokenOverride = { signWithWrongKey: true };
    expect(await callbackFails()).toContain("Sign-in with the identity provider failed");
  });

  test("rejects an id_token from another issuer or for another audience", async () => {
    idTokenOverride = { issuer: "https://evil.example.com" };
    expect(await callbackFails()).toContain("Sign-in with the identity provider failed");
    idTokenOverride = { audience: "some-other-client" };
    expect(await callbackFails()).toContain("Sign-in with the identity provider failed");
  });

  test("rejects an expired id_token", async () => {
    idTokenOverride = { expSecondsFromNow: -60 };
    expect(await callbackFails()).toContain("Sign-in with the identity provider failed");
  });

  test("says what to fix when the provider returns no id_token at all", async () => {
    idTokenOverride = { omit: true };
    expect(await callbackFails()).toContain("POCKETID_SCOPES includes openid");
  });

  test("a token persisted before identities existed no longer authenticates", async () => {
    const { accessTokens, sha256 } = await import("../src/oauth/state.js");
    const legacy = "vmhq_mcp_legacy_token";
    accessTokens.set(sha256(legacy), {
      clientId: "legacy",
      scopes: ["mcp"],
      expiresAt: Date.now() + 60_000,
    });
    // Nothing reachable through a token may go unattributed, so a token that
    // names nobody is refused and dropped rather than logged as "legacy".
    expect(oauth.verifyAccessToken(legacy)).toBeUndefined();
    expect(accessTokens.has(sha256(legacy))).toBe(false);
  });

  test("the oldest persisted token format (a bare expiry) is dropped on load", async () => {
    const state = await import("../src/oauth/state.js");
    const hash = state.sha256("vmhq_mcp_numeric_format");
    state.saveState();
    const raw = JSON.parse(readFileSync(statePath, "utf-8")) as { accessTokens: unknown[] };
    raw.accessTokens.push([hash, Date.now() + 60_000]);
    writeFileSync(statePath, JSON.stringify(raw));
    state.reloadPersistedOAuthState();
    expect(state.accessTokens.has(hash)).toBe(false);
  });
});

describe("MCP_ALLOWED_SUBJECTS", () => {
  const VAR = "MCP_ALLOWED_SUBJECTS";
  afterEach(() => { delete process.env[VAR]; });

  test("unset lets anyone PocketID authenticated through", async () => {
    expect(await fullFlowAccessToken()).toBeTruthy();
  });

  test("matches on email or subject", async () => {
    process.env[VAR] = "vicente@example.com";
    expect(await fullFlowAccessToken()).toBeTruthy();
    process.env[VAR] = "user-123";
    expect(await fullFlowAccessToken()).toBeTruthy();
  });

  test("blocks an account that is not listed, before any code is issued", async () => {
    process.env[VAR] = "someone-else@example.com";
    expect(await callbackFails()).toContain("not allowed to access this server");
  });

  test("removing a person from the allowlist ends their existing session", async () => {
    const tokens = await fullFlowSession();
    expect(oauth.verifyAccessToken(tokens.access_token)).toBeDefined();

    process.env[VAR] = "someone-else@example.com";
    // The access token stops working immediately, not at its expiry...
    expect(oauth.verifyAccessToken(tokens.access_token)).toBeUndefined();
    // ...and the refresh token cannot bring it back.
    const res = await postToken({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: tokens.clientId });
    expect(res.status).toBe(400);
  });
});

describe("client table cap", () => {
  test("idle clients are evicted oldest first to make room, clients with tokens are kept", async () => {
    const { clients, reserveClientSlot, refreshTokens, sha256 } = await import("../src/oauth/state.js");
    clients.clear();
    refreshTokens.clear();
    for (let i = 0; i < 3; i++) {
      clients.set(`c${i}`, { clientId: `c${i}`, clientIdIssuedAt: 1000 + i, redirectUris: ["https://x/cb"] });
    }
    refreshTokens.set(sha256("rt-c0"), {
      clientId: "c0",
      scopes: ["mcp"],
      familyId: "f",
      expiresAt: Date.now() + 60_000,
    });

    expect(reserveClientSlot(3)).toBe(true);
    expect(clients.has("c0")).toBe(true); // holds a token
    expect(clients.has("c1")).toBe(false); // oldest idle client went first
    expect(clients.has("c2")).toBe(true);
  });

  test("registration is refused once every slot holds a live credential", async () => {
    const { clients, reserveClientSlot, refreshTokens, sha256 } = await import("../src/oauth/state.js");
    clients.clear();
    refreshTokens.clear();
    for (let i = 0; i < 2; i++) {
      clients.set(`c${i}`, { clientId: `c${i}`, clientIdIssuedAt: 1000 + i, redirectUris: ["https://x/cb"] });
      refreshTokens.set(sha256(`rt-c${i}`), { clientId: `c${i}`, scopes: ["mcp"], familyId: `f${i}`, expiresAt: Date.now() + 60_000 });
    }
    expect(reserveClientSlot(2)).toBe(false);
    expect(clients.size).toBe(2);
  });
});

describe("refresh tokens", () => {
  test("the token response carries a refresh token and a one-day access token", async () => {
    const tokens = await fullFlowTokens();
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.expires_in).toBe(60 * 60 * 24);
  });

  test("a refresh token buys a new access token that keeps the identity", async () => {
    const first = await fullFlowSession();
    const refreshed = await refresh(first.refresh_token, first.clientId);
    expect(refreshed.access_token).not.toBe(first.access_token);
    expect(oauth.verifyAccessToken(refreshed.access_token)!.extra?.actor).toBe("vicente@example.com");
  });

  test("rotation invalidates the refresh token that was just used", async () => {
    const first = await fullFlowSession();
    await refresh(first.refresh_token, first.clientId);
    const res = await postToken({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: first.clientId });
    expect(res.status).toBe(400);
  });

  test("replaying a rotated refresh token revokes the whole family", async () => {
    const first = await fullFlowSession();
    const second = await refresh(first.refresh_token, first.clientId);

    // The thief replays the token the legitimate client already spent.
    const res = await postToken({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: first.clientId });
    expect(res.status).toBe(400);

    // Everything descended from that authorization is gone, including the
    // credentials the legitimate client was still holding.
    expect(oauth.verifyAccessToken(second.access_token)).toBeUndefined();
    const afterReuse = await postToken({ grant_type: "refresh_token", refresh_token: second.refresh_token, client_id: first.clientId });
    expect(afterReuse.status).toBe(400);
  });

  test("a refresh without client_id is refused, not waved through", async () => {
    const tokens = await fullFlowSession();
    const res = await postToken({ grant_type: "refresh_token", refresh_token: tokens.refresh_token });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
    // Refusing an incomplete request must not spend the token.
    expect((await refresh(tokens.refresh_token, tokens.clientId)).access_token).toBeTruthy();
  });

  test("the token response is marked uncacheable", async () => {
    const { tokenRes } = await fullFlow({ redirectUri: "https://client.example.com/cb" });
    expect(tokenRes.headers.get("cache-control")).toBe("no-store");
    expect(tokenRes.headers.get("pragma")).toBe("no-cache");
  });

  test("a session ends at its hard limit no matter how often it refreshes", async () => {
    const { accessTokens, refreshTokens, sha256, SESSION_MAX_S } = await import("../src/oauth/state.js");
    const first = await fullFlowSession();
    const stored = refreshTokens.get(sha256(first.refresh_token))!;
    expect(stored.familyExpiresAt).toBeGreaterThan(Date.now() + (SESSION_MAX_S - 60) * 1000);

    // Push the family to within a minute of its end: the next pair is capped.
    const soon = Date.now() + 60_000;
    stored.familyExpiresAt = soon;
    const second = await refresh(first.refresh_token, first.clientId);
    expect(second.expires_in).toBeLessThanOrEqual(60);
    expect(accessTokens.get(sha256(second.access_token))!.expiresAt).toBeLessThanOrEqual(soon);
    expect(refreshTokens.get(sha256(second.refresh_token))!.expiresAt).toBeLessThanOrEqual(soon);

    // Past the end, the refresh token is refused even though it is unspent.
    refreshTokens.get(sha256(second.refresh_token))!.familyExpiresAt = Date.now() - 1;
    const res = await postToken({ grant_type: "refresh_token", refresh_token: second.refresh_token, client_id: first.clientId });
    expect(res.status).toBe(400);
  });

  test("an unknown refresh token is refused without touching anything else", async () => {
    const live = await fullFlowTokens();
    const res = await postToken({ grant_type: "refresh_token", refresh_token: "vmhq_rt_never_issued" });
    expect(res.status).toBe(400);
    expect(oauth.verifyAccessToken(live.access_token)).toBeDefined();
  });

  test("a refresh token cannot be used by a different client", async () => {
    const tokens = await fullFlowTokens();
    const res = await postToken({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: "someone-else" });
    expect(res.status).toBe(400);
  });

  test("metadata advertises the refresh grant", async () => {
    const meta = await oauth.authorizationServerMetadata(testConfig, new Request("https://mcp.example.com/x")).json();
    expect(meta.grant_types_supported).toContain("refresh_token");
  });
});

describe("revocation", () => {
  test("revoking the access token also kills its refresh token", async () => {
    const tokens = await fullFlowTokens();
    await oauth.revokeToken(formRequest("https://mcp.example.com/oauth/revoke", { token: tokens.access_token }));
    expect(oauth.verifyAccessToken(tokens.access_token)).toBeUndefined();
    const res = await postToken({ grant_type: "refresh_token", refresh_token: tokens.refresh_token });
    expect(res.status).toBe(400);
  });

  test("listSessions reports who holds a token and never leaks the token itself", async () => {
    const tokens = await fullFlowTokens();
    const sessions = oauth.listSessions();
    // Earlier tests leave sessions behind whose refresh token was spent or
    // capped, so look for the one this flow just minted: newest and renewable.
    const mine = sessions.filter((s) => s.actor === "vicente@example.com");
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.at(-1)!.renewable).toBe(true);
    const serialized = JSON.stringify(sessions);
    expect(serialized).not.toContain(tokens.access_token);
    expect(serialized).not.toContain(tokens.refresh_token);
  });

  test("revokeSessions cuts a person off, refresh token included", async () => {
    const tokens = await fullFlowTokens();
    const revoked = oauth.revokeSessions({ actor: "vicente@example.com" });
    expect(revoked).toBeGreaterThanOrEqual(2);
    expect(oauth.verifyAccessToken(tokens.access_token)).toBeUndefined();
    const res = await postToken({ grant_type: "refresh_token", refresh_token: tokens.refresh_token });
    expect(res.status).toBe(400);
  });

  test("revokeSessions with no matching filter changes nothing", async () => {
    const tokens = await fullFlowTokens();
    expect(oauth.revokeSessions({ actor: "nobody@example.com" })).toBe(0);
    expect(oauth.verifyAccessToken(tokens.access_token)).toBeDefined();
  });
});

/**
 * A token bound to a resource is only valid at that resource (RFC 8707 §2).
 * Without the check, a token this server issued for one audience still opened
 * /mcp, which is the whole point of binding it in the first place.
 */
describe("token audience", () => {
  const OURS = ["https://mcp.example.com/mcp", "https://mcp.example.com/mcp/read"];

  async function tokenBoundTo(resource?: string): Promise<string> {
    const { tokenRes } = await fullFlow({
      redirectUri: "https://audience.example.com/cb",
      ...(resource ? { resource } : {}),
    });
    expect(tokenRes.status).toBe(200);
    return ((await tokenRes.json()) as { access_token: string }).access_token;
  }

  test("a token bound to another server is refused", async () => {
    const token = await tokenBoundTo("https://someone-else.example.com/mcp");
    expect(oauth.verifyAccessToken(token, OURS)).toBeUndefined();
  });

  test("a token bound to this server is accepted at either endpoint", async () => {
    const token = await tokenBoundTo("https://mcp.example.com/mcp");
    expect(oauth.verifyAccessToken(token, OURS)).toBeDefined();
    // Both paths are the same server; the tool tier is decided by the route.
    expect(oauth.verifyAccessToken(token, ["https://mcp.example.com/mcp/read"])).toBeUndefined();
  });

  test("a trailing slash is not an audience mismatch", async () => {
    const token = await tokenBoundTo("https://mcp.example.com/mcp");
    expect(oauth.verifyAccessToken(token, ["https://mcp.example.com/mcp/"])).toBeDefined();
  });

  test("a token with no resource is unaffected, which covers everything already issued", async () => {
    const token = await tokenBoundTo();
    expect(oauth.verifyAccessToken(token, OURS)).toBeDefined();
  });

  test("no expected resources configured means no audience check", async () => {
    // MCP_PUBLIC_URL unset: the server cannot name itself, so it cannot judge.
    const token = await tokenBoundTo("https://someone-else.example.com/mcp");
    expect(oauth.verifyAccessToken(token, [])).toBeDefined();
    expect(oauth.verifyAccessToken(token)).toBeDefined();
  });
});

describe("client must still be registered at redemption", () => {
  test("a code from a pruned client no longer buys a token", async () => {
    const redirectUri = "https://pruned.example.com/cb";
    const clientId = await register(redirectUri);
    const verifier = "correct-horse-battery-staple";
    const { code } = await authorizeViaPocketId({ clientId, redirectUri, codeChallenge: s256(verifier) });

    // The client ages out between authorizing and redeeming.
    const { clients } = await import("../src/oauth/state.js");
    clients.delete(clientId);

    const res = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_grant" });
  });
});
