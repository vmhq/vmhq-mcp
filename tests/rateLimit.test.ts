import { describe, expect, test } from "bun:test";
import { checkRateLimit, clientIp } from "../src/rateLimit.js";

function req(headers: Record<string, string> = {}): Request {
  return new Request("https://mcp.example.com/oauth/register", {
    method: "POST",
    headers,
  });
}

describe("clientIp", () => {
  test("prefers CF-Connecting-IP over X-Forwarded-For", () => {
    expect(
      clientIp(
        req({
          "cf-connecting-ip": "203.0.113.10",
          "x-forwarded-for": "198.51.100.1",
        }),
      ),
    ).toBe("203.0.113.10");
  });

  test("uses X-Real-IP when present", () => {
    expect(clientIp(req({ "x-real-ip": "203.0.113.20" }))).toBe("203.0.113.20");
  });

  test("uses first X-Forwarded-For hop", () => {
    expect(clientIp(req({ "x-forwarded-for": "203.0.113.30, 10.0.0.1" }))).toBe("203.0.113.30");
  });

  test("returns undefined when no proxy headers are set", () => {
    expect(clientIp(req())).toBeUndefined();
  });
});

describe("checkRateLimit", () => {
  test("allows more than 3 oauth_register calls per IP per minute", () => {
    const ip = "203.0.113.99";
    for (let i = 0; i < 5; i++) {
      expect(checkRateLimit(req({ "x-forwarded-for": ip }), "oauth_register")).toBe(true);
    }
  });

  test("isolates oauth_register limits per client IP", () => {
    const ipA = "203.0.113.40";
    const ipB = "203.0.113.41";
    for (let i = 0; i < 30; i++) {
      expect(checkRateLimit(req({ "x-forwarded-for": ipA }), "oauth_register")).toBe(true);
    }
    expect(checkRateLimit(req({ "x-forwarded-for": ipB }), "oauth_register")).toBe(true);
  });
});
