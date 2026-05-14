import { createHash, randomBytes } from "node:crypto";

export type OAuthConfig = {
  publicUrl?: string;
};

type Client = {
  clientId: string;
  redirectUris: string[];
  clientName?: string;
};

type AuthorizationCode = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  expiresAt: number;
};

const clients = new Map<string, Client>();
const codes = new Map<string, AuthorizationCode>();
const accessTokens = new Set<string>();

function baseUrl(config: OAuthConfig, req: Request): string {
  if (config.publicUrl) {
    return config.publicUrl.replace(/\/$/, "");
  }

  const url = new URL(req.url);
  return url.origin;
}

export function mcpUrl(config: OAuthConfig, req: Request): string {
  return `${baseUrl(config, req)}/mcp`;
}

export function isOAuthAccessToken(token: string): boolean {
  return accessTokens.has(token);
}

export function unauthorized(config: OAuthConfig, req: Request): Response {
  const root = baseUrl(config, req);

  return Response.json(
    { error: "unauthorized" },
    {
      status: 401,
      headers: {
        "WWW-Authenticate": `Bearer resource_metadata="${root}/.well-known/oauth-protected-resource"`,
      },
    },
  );
}

export function protectedResourceMetadata(config: OAuthConfig, req: Request): Response {
  const root = baseUrl(config, req);

  return Response.json({
    resource: mcpUrl(config, req),
    authorization_servers: [root],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"],
  });
}

export function authorizationServerMetadata(config: OAuthConfig, req: Request): Response {
  const root = baseUrl(config, req);

  return Response.json({
    issuer: root,
    authorization_endpoint: `${root}/oauth/authorize`,
    token_endpoint: `${root}/oauth/token`,
    registration_endpoint: `${root}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["mcp"],
  });
}

export async function registerClient(req: Request): Promise<Response> {
  const body = await req.json().catch(() => ({}));
  const redirectUris = Array.isArray(body.redirect_uris)
    ? body.redirect_uris.filter((uri: unknown): uri is string => typeof uri === "string")
    : [];

  if (redirectUris.length === 0) {
    return Response.json({ error: "invalid_redirect_uris" }, { status: 400 });
  }

  const clientId = `vmhq_${randomBytes(18).toString("base64url")}`;
  clients.set(clientId, {
    clientId,
    redirectUris,
    clientName: typeof body.client_name === "string" ? body.client_name : undefined,
  });

  return Response.json({
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: redirectUris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code"],
    response_types: ["code"],
    scope: "mcp",
  });
}

function bearerToken(req: Request): string {
  const authorization = req.headers.get("authorization") ?? "";
  const [scheme, token] = authorization.split(/\s+/, 2);
  return scheme?.toLowerCase() === "bearer" ? token ?? "" : "";
}

export function authorize(req: Request, accessToken: string): Response {
  if (bearerToken(req) !== accessToken) {
    return Response.json(
      { error: "unauthorized", error_description: "Valid Bearer token required to authorize" },
      {
        status: 401,
        headers: {
          "WWW-Authenticate": "Bearer",
        },
      },
    );
  }

  const url = new URL(req.url);
  const clientId = url.searchParams.get("client_id") ?? "";
  const redirectUri = url.searchParams.get("redirect_uri") ?? "";
  const codeChallenge = url.searchParams.get("code_challenge") ?? "";
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? "";
  const state = url.searchParams.get("state");

  const client = clients.get(clientId);

  if (!client || !client.redirectUris.includes(redirectUri)) {
    return Response.json({ error: "invalid_client" }, { status: 400 });
  }

  if (!codeChallenge || codeChallengeMethod !== "S256") {
    return Response.json({ error: "invalid_request", error_description: "S256 PKCE is required" }, { status: 400 });
  }

  const code = randomBytes(24).toString("base64url");
  codes.set(code, {
    clientId,
    redirectUri,
    codeChallenge,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) {
    redirect.searchParams.set("state", state);
  }

  return Response.redirect(redirect, 302);
}

function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export async function exchangeToken(req: Request): Promise<Response> {
  const form = await req.formData();
  const grantType = String(form.get("grant_type") ?? "");
  const code = String(form.get("code") ?? "");
  const redirectUri = String(form.get("redirect_uri") ?? "");
  const clientId = String(form.get("client_id") ?? "");
  const codeVerifier = String(form.get("code_verifier") ?? "");
  const authorizationCode = codes.get(code);

  if (grantType !== "authorization_code" || !authorizationCode) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  codes.delete(code);

  if (authorizationCode.expiresAt < Date.now()) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  if (authorizationCode.clientId !== clientId || authorizationCode.redirectUri !== redirectUri) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  if (s256(codeVerifier) !== authorizationCode.codeChallenge) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }

  const accessToken = `vmhq_mcp_${randomBytes(32).toString("base64url")}`;
  accessTokens.add(accessToken);

  return Response.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 60 * 60 * 24 * 30,
    scope: "mcp",
  });
}
