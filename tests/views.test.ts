import { describe, expect, test } from "bun:test";
import { renderAuthorizeConsent, renderAuthorizeSuccess } from "../src/oauth/views.js";

describe("renderAuthorizeSuccess", () => {
  test("escapes < in the JS-embedded redirect URL (no </script> breakout)", async () => {
    const res = renderAuthorizeSuccess("myapp:callback</script><script>alert(1)</script>");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).not.toContain("</script><script>alert(1)</script>");
    expect(html).toContain("\\u003c/script>");
  });

  test("escapes the redirect URL in the meta-refresh attribute", async () => {
    const res = renderAuthorizeSuccess("myapp:callback</script><script>alert(1)</script>");
    const html = await res.text();
    expect(html).toContain("&lt;/script&gt;");
  });
});

describe("renderAuthorizeConsent", () => {
  test("names the destination only when no allowlist is enforced", async () => {
    const open = await renderAuthorizeConsent("https://id.example.com/authorize", {
      redirectUri: "https://evil.example.com/cb",
      clientName: "Claude",
      allowlisted: false,
    }).text();
    expect(open).toContain("<strong>evil.example.com</strong>");

    const enforced = await renderAuthorizeConsent("https://id.example.com/authorize", {
      redirectUri: "https://claude.ai/api/mcp/auth_callback",
      clientName: "Claude",
      allowlisted: true,
    }).text();
    expect(enforced).toContain("<strong>claude.ai</strong>");
  });

  test("escapes the destination like everything else on the page", async () => {
    const html = await renderAuthorizeConsent("https://id.example.com/authorize", {
      redirectUri: "myapp://<img src=x onerror=alert(1)>/cb",
      allowlisted: false,
    }).text();
    expect(html).not.toContain("<img");
  });
});
