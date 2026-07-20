import { describe, expect, test } from "bun:test";
import { renderAuthorizeSuccess } from "../src/oauth/views.js";

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
