import { describe, expect, test } from "bun:test";
import { isRegistrableRedirectUri } from "../src/oauth/redirectUri.js";

describe("isRegistrableRedirectUri scheme validation", () => {
  test("rejects browser-executable and local-resource schemes", () => {
    for (const uri of [
      "javascript:alert(document.domain)",
      "javascript:alert(1)//",
      "data:text/html,<script>alert(1)</script>",
      "vbscript:msgbox(1)",
      "file:///etc/passwd",
      "filesystem:https://example.com/temporary/x",
      "blob:https://example.com/550e8400-e29b-41d4-a716-446655440000",
      "about:blank",
      "view-source:https://example.com",
    ]) {
      expect(isRegistrableRedirectUri(uri)).toBe(false);
    }
  });

  test("still allows native-app private-use schemes (RFC 8252 §7.1)", () => {
    expect(isRegistrableRedirectUri("claude://callback")).toBe(true);
    expect(isRegistrableRedirectUri("cursor://oauth/callback")).toBe(true);
    expect(isRegistrableRedirectUri("com.example.app:/oauth2redirect")).toBe(true);
  });

  test("keeps https and loopback rules unchanged", () => {
    expect(isRegistrableRedirectUri("https://claude.ai/api/mcp/auth_callback")).toBe(true);
    expect(isRegistrableRedirectUri("http://localhost:3000/cb")).toBe(true);
    expect(isRegistrableRedirectUri("http://127.0.0.1/cb")).toBe(true);
    expect(isRegistrableRedirectUri("https://localhost/cb")).toBe(false);
    expect(isRegistrableRedirectUri("http://evil.example.com/cb")).toBe(false);
  });
});
