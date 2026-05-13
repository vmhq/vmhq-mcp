import type { ServiceDefinition, ServiceRequestInput } from "./services.js";

const BLOCKED_REQUEST_HEADERS = new Set([
  "authorization",
  "cookie",
  "host",
  "x-auth-token",
  "content-length",
  "transfer-encoding",
]);

const RESPONSE_HEADERS = ["content-type", "etag", "last-modified", "x-total-count"];

function serviceToken(service: ServiceDefinition): string {
  if (service.auth.type === "none") {
    return "";
  }

  return process.env[service.auth.tokenEnv] ?? "";
}

function authHeaders(service: ServiceDefinition): Record<string, string> {
  const token = serviceToken(service);

  if (service.auth.type === "none" || !token) {
    return {};
  }

  if (service.auth.type === "bearer") {
    return { Authorization: `Bearer ${token}` };
  }

  if (service.auth.type === "header") {
    return { [service.auth.headerName]: token };
  }

  return { Authorization: `${service.auth.prefix}${token}` };
}

function cleanHeaders(headers: Record<string, string> | undefined): Record<string, string> {
  const cleaned: Record<string, string> = {};

  for (const [name, value] of Object.entries(headers ?? {})) {
    if (BLOCKED_REQUEST_HEADERS.has(name.toLowerCase())) {
      continue;
    }

    cleaned[name] = value;
  }

  return cleaned;
}

export function interpolatePath(path: string, pathParams: Record<string, string | number> = {}): string {
  return path.replace(/\{([^}]+)\}/g, (_match, key: string) => {
    const value = pathParams[key];

    if (value === undefined || value === null) {
      throw new Error(`Missing required path parameter: ${key}`);
    }

    return encodeURIComponent(String(value));
  });
}

function buildUrl(service: ServiceDefinition, input: ServiceRequestInput): URL {
  if (/^https?:\/\//i.test(input.path)) {
    throw new Error("Use relative paths only. Absolute URLs are not allowed.");
  }

  const baseUrl = new URL(service.baseUrl);
  const path = input.path.startsWith("/") ? input.path : `/${input.path}`;
  const url = new URL(path, baseUrl);

  if (url.origin !== baseUrl.origin) {
    throw new Error("Resolved URL escaped the configured service origin.");
  }

  for (const [name, value] of Object.entries(input.query ?? {})) {
    if (Array.isArray(value)) {
      for (const item of value) {
        url.searchParams.append(name, String(item));
      }
    } else {
      url.searchParams.set(name, String(value));
    }
  }

  return url;
}

function usefulResponseHeaders(headers: Headers): Record<string, string> {
  const picked: Record<string, string> = {};

  for (const name of RESPONSE_HEADERS) {
    const value = headers.get(name);
    if (value) {
      picked[name] = value;
    }
  }

  return picked;
}

async function parseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  const text = await response.text();

  if (!text) {
    return null;
  }

  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  return text;
}

export async function callService(service: ServiceDefinition, input: ServiceRequestInput): Promise<unknown> {
  const url = buildUrl(service, input);
  const headers: Record<string, string> = {
    Accept: "application/json, text/plain;q=0.9, */*;q=0.8",
    ...cleanHeaders(input.headers),
    ...authHeaders(service),
  };

  let body: BodyInit | undefined;

  if (input.body !== undefined && input.method !== "GET") {
    body = typeof input.body === "string" ? input.body : JSON.stringify(input.body);
    headers["Content-Type"] ??= "application/json";
  }

  const response = await fetch(url, {
    method: input.method,
    headers,
    body,
  });

  return {
    service: service.id,
    request: {
      method: input.method,
      url: `${url.pathname}${url.search}`,
    },
    response: {
      ok: response.ok,
      status: response.status,
      statusText: response.statusText,
      headers: usefulResponseHeaders(response.headers),
      body: await parseBody(response),
    },
  };
}
