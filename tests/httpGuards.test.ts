import { describe, expect, test } from "bun:test";
import {
  MAX_REQUEST_BODY_BYTES,
  readBodyTextCapped,
  requestBodyTooLarge,
  RequestBodyTooLargeError,
} from "../src/httpGuards.js";

describe("requestBodyTooLarge", () => {
  test("returns true when Content-Length exceeds the cap", () => {
    const req = new Request("https://mcp.example.com/mcp", {
      method: "POST",
      headers: { "content-length": String(MAX_REQUEST_BODY_BYTES + 1) },
    });
    expect(requestBodyTooLarge(req)).toBe(true);
  });

  test("returns false at or below the cap", () => {
    const req = new Request("https://mcp.example.com/mcp", {
      method: "POST",
      headers: { "content-length": String(MAX_REQUEST_BODY_BYTES) },
    });
    expect(requestBodyTooLarge(req)).toBe(false);
  });

  test("returns false when Content-Length is absent (chunked) or invalid", () => {
    expect(requestBodyTooLarge(new Request("https://mcp.example.com/mcp", { method: "POST" }))).toBe(false);
  });
});

describe("readBodyTextCapped", () => {
  test("returns the body text when under the cap", async () => {
    const req = new Request("https://mcp.example.com/oauth/token", { method: "POST", body: "grant_type=x" });
    expect(await readBodyTextCapped(req)).toBe("grant_type=x");
  });

  test("returns empty string when there is no body", async () => {
    const req = new Request("https://mcp.example.com/oauth/token", { method: "POST" });
    expect(await readBodyTextCapped(req)).toBe("");
  });

  test("throws once the streamed body exceeds the cap (no Content-Length trust)", async () => {
    // A chunked ReadableStream carries no Content-Length, so the cheap
    // requestBodyTooLarge() gate can't see it — the read-time cap must.
    const chunk = new Uint8Array(8);
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) { controller.enqueue(chunk); },
    });
    const req = new Request("https://mcp.example.com/oauth/token", { method: "POST", body: stream });
    expect(requestBodyTooLarge(req)).toBe(false);
    await expect(readBodyTextCapped(req, 32)).rejects.toBeInstanceOf(RequestBodyTooLargeError);
  });
});
