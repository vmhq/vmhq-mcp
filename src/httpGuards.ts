/** Maximum accepted request body size (1 MiB) for JSON/form endpoints. */
export const MAX_REQUEST_BODY_BYTES = 1_048_576;

/**
 * Fast pre-parse check based on Content-Length. Note: chunked bodies without
 * Content-Length are not caught here; per-IP rate limits bound that case.
 */
export function requestBodyTooLarge(req: Request, maxBytes = MAX_REQUEST_BODY_BYTES): boolean {
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  return Number.isFinite(contentLength) && contentLength > maxBytes;
}
