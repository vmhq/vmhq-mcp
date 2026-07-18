import { log } from "./logger.js";
import type { ServiceDefinition, ServiceRequestInput } from "./services.js";

const BLOCKED_REQUEST_HEADERS = new Set([
  "authorization",
  "cookie",
  "host",
  "x-api-key",
  "x-auth-token",
  "content-length",
  "transfer-encoding",
]);

const RESPONSE_HEADERS = ["content-type", "etag", "last-modified", "x-total-count"];
const DEFAULT_UPSTREAM_TIMEOUT_MS = 30_000;

type NormalizedErrorType =
  | "missing_upstream_credentials"
  | "invalid_request"
  | "upstream_timeout"
  | "upstream_network_error"
  | "upstream_error";

function normalizedError(type: NormalizedErrorType, service: ServiceDefinition, message: string, retryable = false): unknown {
  return {
    error: {
      type,
      service: service.id,
      message,
      retryable,
    },
  };
}

function requiredTokenEnv(service: ServiceDefinition): string | undefined {
  if (service.auth.type === "bearer" || service.auth.type === "header" || service.auth.type === "prefixed") {
    return service.auth.tokenEnv;
  }
  return undefined;
}

function serviceToken(service: ServiceDefinition): string {
  const tokenEnv = requiredTokenEnv(service);
  return tokenEnv ? process.env[tokenEnv] ?? "" : "";
}

function authHeaders(service: ServiceDefinition): Record<string, string> {
  if (service.auth.type === "none") {
    return {};
  }

  if (service.auth.type === "static") {
    return { [service.auth.headerName]: service.auth.value };
  }

  const token = serviceToken(service);

  if (!token) {
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

export function buildUrl(service: ServiceDefinition, input: ServiceRequestInput): URL {
  if (/^https?:\/\//i.test(input.path)) {
    throw new Error("Use relative paths only. Absolute URLs are not allowed.");
  }

  const baseUrl = new URL(service.baseUrl);
  const base = baseUrl.href.endsWith("/") ? baseUrl.href : `${baseUrl.href}/`;
  const relativePath = input.path.replace(/^\/+/u, "");
  const url = new URL(relativePath, base);

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

/** Walks a dotted path (e.g. ["attributes", "friendly_name"]) into a plain object. */
function getByPath(record: Record<string, unknown>, path: string[]): { found: boolean; value?: unknown } {
  let current: unknown = record;

  for (const key of path) {
    if (current === null || typeof current !== "object" || Array.isArray(current)) {
      return { found: false };
    }

    const obj = current as Record<string, unknown>;
    if (!(key in obj)) {
      return { found: false };
    }

    current = obj[key];
  }

  return { found: true, value: current };
}

/** Sets a dotted path into a plain object, creating intermediate objects as needed. */
function setByPath(target: Record<string, unknown>, path: string[], value: unknown): void {
  let current = target;

  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i]!;
    if (current[key] === null || typeof current[key] !== "object" || Array.isArray(current[key])) {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }

  current[path[path.length - 1]!] = value;
}

function filterFields(data: unknown, fields: string[]): unknown {
  if (Array.isArray(data)) {
    return data.map((item) => filterFields(item, fields));
  }

  if (data !== null && typeof data === "object") {
    // Miniflux entry lists are wrapped as {total, entries: [...]}. Apply the
    // field filter inside entries and preserve total so callers can paginate.
    const record = data as Record<string, unknown>;
    if (Array.isArray(record.entries) && typeof record.total === "number") {
      return {
        total: record.total,
        entries: filterFields(record.entries, fields),
      };
    }

    const filtered: Record<string, unknown> = {};
    for (const field of fields) {
      // Literal key first: response keys can themselves contain dots
      // (domains, Home Assistant entity IDs), so "light.office" must match
      // a top-level key before being treated as a nested path.
      if (field in record) {
        filtered[field] = record[field];
        continue;
      }
      const path = field.split(".");
      const { found, value } = getByPath(record, path);
      if (found) {
        setByPath(filtered, path, value);
      }
    }
    return filtered;
  }

  return data;
}

function filterByDomain(data: unknown, domain: string): unknown {
  if (!Array.isArray(data)) {
    return data;
  }

  const prefix = `${domain}.`;
  return data.filter((item) => {
    if (item !== null && typeof item === "object" && "entity_id" in item) {
      return String((item as Record<string, unknown>).entity_id).startsWith(prefix);
    }
    return false;
  });
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

type MultipartScalar = string | number | boolean;
type MultipartBase64FileField = { _base64: string; filename: string; contentType?: string };
type MultipartBytesFileField = { _bytes: Uint8Array; filename: string; contentType?: string };
type MultipartFileField = MultipartBase64FileField | MultipartBytesFileField;
type MultipartField = MultipartScalar | MultipartScalar[] | MultipartFileField;
type MultipartBody = { _multipart: true } & Record<string, MultipartField | true>;

function isFileField(value: unknown): value is MultipartFileField {
  return value !== null && typeof value === "object" && "filename" in value && ("_base64" in value || "_bytes" in value);
}

function fileFieldBytes(value: MultipartFileField): Buffer {
  if ("_bytes" in value) {
    return Buffer.from(value._bytes);
  }

  return Buffer.from(value._base64, "base64");
}

export function isMultipartBody(body: unknown): body is MultipartBody {
  return body !== null && typeof body === "object" && "_multipart" in body && (body as Record<string, unknown>)["_multipart"] === true;
}

function buildFormData(body: MultipartBody): FormData {
  const fd = new FormData();

  for (const [key, value] of Object.entries(body)) {
    if (key === "_multipart") continue;

    if (isFileField(value)) {
      const bytes = fileFieldBytes(value);
      const arrayBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
      const blob = new Blob([arrayBuffer], { type: value.contentType ?? "application/octet-stream" });
      fd.append(key, blob, value.filename);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        fd.append(key, String(item));
      }
    } else {
      fd.append(key, String(value));
    }
  }

  return fd;
}

export type CallServiceOptions = {
  timeoutMs?: number;
  operationId?: string;
  requestId?: string;
};

export async function callService(
  service: ServiceDefinition,
  input: ServiceRequestInput,
  options: CallServiceOptions = {},
): Promise<unknown> {
  const startedAt = performance.now();
  let url: URL;

  try {
    url = buildUrl(service, input);
  } catch (error) {
    return normalizedError("invalid_request", service, error instanceof Error ? error.message : "Invalid request.");
  }

  const tokenEnv = requiredTokenEnv(service);
  if (tokenEnv && !serviceToken(service)) {
    return normalizedError("missing_upstream_credentials", service, `Missing required credential environment variable: ${tokenEnv}`);
  }

  const headers: Record<string, string> = {
    Accept: "application/json, text/plain;q=0.9, */*;q=0.8",
    ...cleanHeaders(input.headers),
    ...authHeaders(service),
  };

  let body: BodyInit | undefined;

  if (input.body !== undefined && input.method !== "GET") {
    if (isMultipartBody(input.body)) {
      body = buildFormData(input.body);
    } else {
      body = typeof input.body === "string" ? input.body : JSON.stringify(input.body);
      headers["Content-Type"] ??= "application/json";
    }
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  log("info", "upstream_request_started", {
    service: service.id,
    operationId: options.operationId,
    requestId: options.requestId,
    method: input.method,
    path: url.pathname,
  });

  try {
    const response = await fetch(url, {
      method: input.method,
      headers,
      body,
      signal: controller.signal,
    });

    let responseBody = await parseBody(response);

    if (input.fields && Array.isArray(input.fields) && input.fields.length > 0) {
      responseBody = filterFields(responseBody, input.fields);
    }

    if (input.domain) {
      responseBody = filterByDomain(responseBody, input.domain);
    }

    const durationMs = Math.round(performance.now() - startedAt);
    log(response.ok ? "info" : "error", "upstream_request_finished", {
      service: service.id,
      operationId: options.operationId,
      requestId: options.requestId,
      method: input.method,
      path: url.pathname,
      status: response.status,
      durationMs,
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
        body: responseBody,
      },
      ...(response.ok
        ? {}
        : {
            error: {
              type: "upstream_error",
              service: service.id,
              message: `Upstream responded with HTTP ${response.status}.`,
              retryable: response.status >= 500,
            },
          }),
    };
  } catch (error) {
    const durationMs = Math.round(performance.now() - startedAt);
    const aborted = controller.signal.aborted;
    log("error", "upstream_request_failed", {
      service: service.id,
      operationId: options.operationId,
      requestId: options.requestId,
      method: input.method,
      path: url.pathname,
      durationMs,
      error: error instanceof Error ? error.message : String(error),
      timeout: aborted,
    });

    return normalizedError(
      aborted ? "upstream_timeout" : "upstream_network_error",
      service,
      aborted ? `Upstream request exceeded ${timeoutMs}ms.` : error instanceof Error ? error.message : "Upstream request failed.",
      true,
    );
  } finally {
    clearTimeout(timeout);
  }
}
