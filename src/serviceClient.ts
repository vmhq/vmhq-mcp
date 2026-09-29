import { log } from "./logger.js";
import type { ServiceAuth, ServiceDefinition, ServiceRequestInput } from "./services.js";

/**
 * Caller headers that are never forwarded: credentials (the server injects its
 * own), framing, and anything that asks the upstream to treat the request as
 * something it is not — another method, another client address, another hop.
 */
const BLOCKED_REQUEST_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "host",
  "x-api-key",
  "x-auth-token",
  "content-length",
  "transfer-encoding",
  "x-http-method-override",
  "x-http-method",
  "x-method-override",
  "forwarded",
  "x-real-ip",
]);

/**
 * The only caller headers the read tier forwards. The tier exists for sessions
 * that ingest third-party text, so the model gets content negotiation and
 * caching, and nothing that could change how the upstream reads the request.
 */
const READ_TIER_HEADERS = new Set(["accept", "accept-language", "if-none-match", "if-modified-since", "range"]);

const RESPONSE_HEADERS = ["content-type", "etag", "last-modified", "x-total-count"];
const DEFAULT_UPSTREAM_TIMEOUT_MS = 30_000;

type NormalizedErrorType =
  | "missing_upstream_credentials"
  | "invalid_request"
  | "upstream_timeout"
  | "upstream_network_error"
  | "upstream_redirect_blocked"
  | "upstream_too_many_redirects"
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

function requiredTokenEnv(auth: ServiceAuth): string | undefined {
  if (auth.type === "bearer" || auth.type === "header" || auth.type === "prefixed") {
    return auth.tokenEnv;
  }
  return undefined;
}

function serviceToken(auth: ServiceAuth): string {
  const tokenEnv = requiredTokenEnv(auth);
  return tokenEnv ? process.env[tokenEnv] ?? "" : "";
}

function authHeaders(auth: ServiceAuth): Record<string, string> {
  if (auth.type === "none") {
    return {};
  }

  if (auth.type === "static") {
    return { [auth.headerName]: auth.value };
  }

  const token = serviceToken(auth);

  if (!token) {
    return {};
  }

  if (auth.type === "bearer") {
    return { Authorization: `Bearer ${token}` };
  }

  if (auth.type === "header") {
    return { [auth.headerName]: token };
  }

  return { Authorization: `${auth.prefix}${token}` };
}

function cleanHeaders(headers: Record<string, string> | undefined, readOnly = false): Record<string, string> {
  const cleaned: Record<string, string> = {};

  for (const [name, value] of Object.entries(headers ?? {})) {
    const lower = name.toLowerCase();
    if (readOnly ? !READ_TIER_HEADERS.has(lower) : BLOCKED_REQUEST_HEADERS.has(lower) || lower.startsWith("x-forwarded-")) {
      continue;
    }

    cleaned[name] = value;
  }

  return cleaned;
}

/**
 * Assembles the outgoing headers in a Headers object, so names compare
 * case-insensitively: the server's credential is set last and replaces any
 * caller header of the same name rather than being merged with it.
 */
function requestHeaders(input: ServiceRequestInput, auth: ServiceAuth, readOnly: boolean): Headers {
  const headers = new Headers({ Accept: "application/json, text/plain;q=0.9, */*;q=0.8" });
  for (const [name, value] of Object.entries(cleanHeaders(input.headers, readOnly))) headers.set(name, value);
  for (const [name, value] of Object.entries(authHeaders(auth))) headers.set(name, value);
  return headers;
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
    if (!Object.hasOwn(obj, key)) {
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

type ParsedField = { raw: string; path: string[] };

/** Segments that must never be traversed or written via field paths. */
const FORBIDDEN_FIELD_PATH_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);

export function parseFields(fields: string[]): ParsedField[] {
  return fields
    .map((field) => ({ raw: field, path: field.split(".") }))
    .filter(({ path }) => path.every((segment) => !FORBIDDEN_FIELD_PATH_SEGMENTS.has(segment)));
}

export function filterFields(data: unknown, parsedFields: ParsedField[]): unknown {
  if (Array.isArray(data)) {
    return data.map((item) => filterFields(item, parsedFields));
  }

  if (data !== null && typeof data === "object") {
    // Miniflux entry lists are wrapped as {total, entries: [...]}. Apply the
    // field filter inside entries and preserve total so callers can paginate.
    const record = data as Record<string, unknown>;
    if (Array.isArray(record.entries) && typeof record.total === "number") {
      return {
        total: record.total,
        entries: filterFields(record.entries, parsedFields),
      };
    }

    const filtered: Record<string, unknown> = {};
    for (const { raw, path } of parsedFields) {
      // Literal key first: response keys can themselves contain dots, so
      // "light.office" must match a top-level key before being treated as a
      // nested path.
      if (Object.hasOwn(record, raw)) {
        filtered[raw] = record[raw];
        continue;
      }
      const { found, value } = getByPath(record, path);
      if (found) {
        setByPath(filtered, path, value);
      }
    }
    return filtered;
  }

  return data;
}

/** Cap on upstream response bodies (10 MiB) to bound process memory. */
const MAX_UPSTREAM_BODY_BYTES = 10 * 1024 * 1024;

async function readResponseTextCapped(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error(`Upstream response exceeded the ${maxBytes}-byte limit.`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(out);
}

async function parseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  const text = await readResponseTextCapped(response, MAX_UPSTREAM_BODY_BYTES);

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

/**
 * Redirects are followed by hand rather than by fetch.
 *
 * fetch only strips `Authorization` when the origin changes, so a service
 * authenticated with a named header (Miniflux's `X-Auth-Token`) would hand its
 * credential to whatever host the upstream pointed at. buildUrl() checks the
 * origin of the first URL only, so the hops after it were also a way into the
 * local network. Following the chain here keeps every hop inside the
 * configured origin.
 */
const MAX_REDIRECTS = 3;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function redirectTarget(response: Response, current: URL): URL | undefined {
  if (!REDIRECT_STATUSES.has(response.status)) return undefined;
  const location = response.headers.get("location");
  if (!location) return undefined;
  try {
    return new URL(location, current);
  } catch {
    return undefined;
  }
}

export type CallServiceOptions = {
  allowUrl?: (url: URL) => boolean;
  /**
   * Read tier: forward only READ_TIER_HEADERS from the caller, and use the
   * service's read-only credential when one is configured.
   */
  readOnly?: boolean;
  timeoutMs?: number;
  operationId?: string;
  requestId?: string;
  /** Who is running this, for the audit trail. See RequestContext in mcp.ts. */
  actor?: string;
};

export async function callService(
  service: ServiceDefinition,
  input: ServiceRequestInput,
  options: CallServiceOptions = {},
): Promise<unknown> {
  const startedAt = performance.now();
  const readOnly = options.readOnly === true;
  const auth = readOnly && service.readAuth ? service.readAuth : service.auth;
  let url: URL;

  try {
    url = buildUrl(service, input);
    if (options.allowUrl && !options.allowUrl(url)) throw new Error("not_available_on_read_tier: URL or parameters are not read-only.");
  } catch (error) {
    return normalizedError("invalid_request", service, error instanceof Error ? error.message : "Invalid request.");
  }

  const tokenEnv = requiredTokenEnv(auth);
  if (tokenEnv && !serviceToken(auth)) {
    return normalizedError("missing_upstream_credentials", service, `Missing required credential environment variable: ${tokenEnv}`);
  }

  let headers: Headers;
  try {
    headers = requestHeaders(input, auth, readOnly);
  } catch (error) {
    // Headers rejects names and values that are not valid HTTP.
    return normalizedError("invalid_request", service, error instanceof Error ? error.message : "Invalid header.");
  }

  let body: BodyInit | undefined;

  if (input.body !== undefined && input.method !== "GET") {
    if (isMultipartBody(input.body)) {
      body = buildFormData(input.body);
    } else {
      body = typeof input.body === "string" ? input.body : JSON.stringify(input.body);
      if (!headers.has("content-type")) headers.set("Content-Type", "application/json");
    }
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  log("info", "upstream_request_started", {
    service: service.id,
    operationId: options.operationId,
    requestId: options.requestId,
    actor: options.actor,
    method: input.method,
    path: url.pathname,
  });

  // Only GET/HEAD are followed: replaying a body across a redirect cannot be
  // done correctly for every body type (FormData above all), so for any other
  // method the 3xx is handed back and the caller decides what to do with it.
  const followsRedirects = input.method === "GET";
  const baseOrigin = new URL(service.baseUrl).origin;

  try {
    let requestUrl = url;
    let response = await fetch(requestUrl, {
      method: input.method,
      headers,
      body,
      // Always manual: for methods we do not follow, the 3xx is the response.
      redirect: "manual",
      signal: controller.signal,
      // Scoped to this service only; the global TLS defaults stay intact for
      // every other upstream. See ServiceDefinition.insecureTls.
      ...(service.insecureTls ? { tls: { rejectUnauthorized: false } } : {}),
    });

    if (followsRedirects) {
      let hops = 0;
      for (let next = redirectTarget(response, requestUrl); next; next = redirectTarget(response, requestUrl)) {
        if (options.allowUrl && !options.allowUrl(next)) {
          return normalizedError("invalid_request", service, "not_available_on_read_tier: redirect is not read-only.");
        }
        if (next.origin !== baseOrigin) {
          log("error", "upstream_redirect_blocked", {
            service: service.id,
            operationId: options.operationId,
            requestId: options.requestId,
            actor: options.actor,
            from: requestUrl.origin,
            to: next.origin,
          });
          return normalizedError(
            "upstream_redirect_blocked",
            service,
            `Upstream tried to redirect to ${next.host}, outside the configured service origin. Refusing to follow it, because the request carries this service's credentials.`,
          );
        }

        if (++hops > MAX_REDIRECTS) {
          return normalizedError(
            "upstream_too_many_redirects",
            service,
            `Upstream redirected more than ${MAX_REDIRECTS} times.`,
          );
        }

        requestUrl = next;
        response = await fetch(requestUrl, {
          method: input.method,
          headers,
          redirect: "manual",
          signal: controller.signal,
          ...(service.insecureTls ? { tls: { rejectUnauthorized: false } } : {}),
        });
      }
    }

    let responseBody = await parseBody(response);

    if (input.fields && Array.isArray(input.fields) && input.fields.length > 0) {
      responseBody = filterFields(responseBody, parseFields(input.fields));
    }

    const durationMs = Math.round(performance.now() - startedAt);
    log(response.ok ? "info" : "error", "upstream_request_finished", {
      service: service.id,
      operationId: options.operationId,
      requestId: options.requestId,
      actor: options.actor,
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
      actor: options.actor,
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
