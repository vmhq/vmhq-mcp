/** Maximum accepted request body size (1 MiB) for JSON/form endpoints. */
export const MAX_REQUEST_BODY_BYTES = 1_048_576;

/**
 * Fast pre-parse check based on Content-Length. Chunked bodies without a
 * Content-Length header slip past this cheap gate; readBodyTextCapped()
 * enforces the same limit while the body is actually consumed.
 */
export function requestBodyTooLarge(req: Request, maxBytes = MAX_REQUEST_BODY_BYTES): boolean {
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  return Number.isFinite(contentLength) && contentLength > maxBytes;
}

/** Raised by readBodyTextCapped() when a streamed body exceeds the cap. */
export class RequestBodyTooLargeError extends Error {
  constructor() {
    super("Request body exceeded the maximum accepted size.");
    this.name = "RequestBodyTooLargeError";
  }
}

/**
 * Read a request body as text while enforcing a hard byte cap, so a body sent
 * without a Content-Length header (chunked transfer encoding) cannot bypass the
 * size guard. Returns "" when there is no body. Throws RequestBodyTooLargeError
 * as soon as the cap is exceeded, cancelling the stream instead of buffering.
 */
export async function readBodyTextCapped(req: Request, maxBytes = MAX_REQUEST_BODY_BYTES): Promise<string> {
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new RequestBodyTooLargeError();
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
