import { describe, expect, test } from "bun:test";
import {
  isAllowedRedirectTarget,
  isRegistrableRedirectUri,
  redirectTargetLabel,
} from "../src/oauth/redirectUri.js";

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

describe("isAllowedRedirectTarget", () => {
  test("allows everything when no allowlist is configured", () => {
    expect(isAllowedRedirectTarget("https://evil.example.com/cb", [])).toBe(true);
  });

  test("matches an allowlisted host exactly and as a parent domain", () => {
    const allowed = ["claude.ai", "cursor.com"];
    expect(isAllowedRedirectTarget("https://claude.ai/api/mcp/auth_callback", allowed)).toBe(true);
    expect(isAllowedRedirectTarget("https://api.claude.ai/cb", allowed)).toBe(true);
    expect(isAllowedRedirectTarget("https://cursor.com/cb", allowed)).toBe(true);
  });

  test("rejects lookalikes that merely contain an allowlisted host", () => {
    const allowed = ["claude.ai"];
    for (const uri of [
      "https://claude.ai.evil.com/cb",
      "https://notclaude.ai/cb",
      "https://evil.com/?next=claude.ai",
      "https://claude.aievil.com/cb",
    ]) {
      expect(isAllowedRedirectTarget(uri, allowed)).toBe(false);
    }
  });

  test("is case-insensitive on the hostname", () => {
    expect(isAllowedRedirectTarget("https://CLAUDE.AI/cb", ["claude.ai"])).toBe(true);
  });

  test("never blocks loopback or private-use schemes, which stay on the user's machine", () => {
    const allowed = ["claude.ai"];
    for (const uri of [
      "http://127.0.0.1:53535/cb",
      "http://localhost:8976/callback",
      "http://[::1]:9000/cb",
      "cursor://anysphere.cursor-mcp/oauth/cb",
      "com.example.app:/oauth",
    ]) {
      expect(isAllowedRedirectTarget(uri, allowed)).toBe(true);
    }
  });

  test("rejects an unparseable URI", () => {
    expect(isAllowedRedirectTarget("not a url", ["claude.ai"])).toBe(false);
  });
});

describe("redirectTargetLabel", () => {
  test("shows host and port for http(s), so a lookalike port is visible", () => {
    expect(redirectTargetLabel("https://claude.ai/api/mcp/auth_callback")).toBe("claude.ai");
    expect(redirectTargetLabel("http://127.0.0.1:8976/cb")).toBe("127.0.0.1:8976");
  });

  test("shows the scheme for native-app callbacks", () => {
    expect(redirectTargetLabel("cursor://anysphere.cursor-mcp/oauth/cb")).toBe("cursor://anysphere.cursor-mcp");
  });
});
