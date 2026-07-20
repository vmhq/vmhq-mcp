import { describe, expect, test } from "bun:test";
import { MAX_REQUEST_BODY_BYTES, requestBodyTooLarge } from "../src/httpGuards.js";

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
