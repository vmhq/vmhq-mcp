import { describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer, isReadOnlyUrl } from "../src/mcp.js";
import { callService } from "../src/serviceClient.js";
import type { ServiceDefinition } from "../src/services.js";
import { buildPocketIdAuthUrl, resetPocketIdDiscoveryCache } from "../src/oauth/pocketid.js";

const service: ServiceDefinition = { id: "miniflux", title: "Miniflux", baseUrl: "https://miniflux.example", auth: {type:"none"}, defaultPathPrefix:"/v1" };

describe("read policy regressions", () => {
  test("both MCP tools reject mutation variants before contacting upstream; admin still works", async () => {
    const original = globalThis.fetch;
    const requested: string[] = [];
    globalThis.fetch = (async (url: string | URL | Request) => { requested.push(String(url)); return Response.json({content:"ok"}); }) as unknown as typeof fetch;
    try {
      for (const tier of ["read", "admin"] as const) {
        const server = createMcpServer({services:[service],iconUrl:"https://example.com/icon.svg",tier});
        const client = new Client({name:"security-test",version:"1"});
        const [ct,st] = InMemoryTransport.createLinkedPair();
        await Promise.all([server.connect(st),client.connect(ct)]);
        try {
          const variants = [
            {name:"miniflux_operation",arguments:{operationId:"fetch_entry_content",pathParams:{entryID:1},query:{update_content:true}}},
            ...["/v1/entries/1/fetch-content?update_content=true", "/v1/entries/1/fetch-content?update_content=false&update_content=true", "/v1/entries/1/%66etch-content?update_content=true", "/v1/entries/2/../1/fetch-content?update_content=true"].map(path => ({name:"miniflux_request",arguments:{method:"GET",path}})),
          ];
          const before = requested.length;
          for (const request of variants) {
            const response = JSON.stringify(await client.callTool(request));
            expect(response.includes("not_available_on_read_tier")).toBe(tier === "read");
          }
          expect(requested.length - before).toBe(tier === "read" ? 0 : variants.length);
          await client.callTool({name:"miniflux_operation",arguments:{operationId:"fetch_entry_content",pathParams:{entryID:1},query:{update_content:false}}});
          expect(requested.at(-1)).toEndWith("update_content=false");
        } finally { await client.close(); await server.close(); }
      }
    } finally { globalThis.fetch = original; }
  });

  test("validates redirects before fetching and refuses unknown GET routes", async () => {
    expect(isReadOnlyUrl(service,new URL("https://miniflux.example/unknown"))).toBe(false);
    const original = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async () => { calls++; return new Response(null,{status:302,headers:{location:"/v1/entries/1/fetch-content?update_content=true"}}); }) as unknown as typeof fetch;
    try {
      const result = await callService(service,{method:"GET",path:"/v1/me"},{allowUrl:url=>isReadOnlyUrl(service,url)});
      expect(JSON.stringify(result)).toContain("not_available_on_read_tier");
      expect(calls).toBe(1);
    } finally { globalThis.fetch = original; }
  });
});

test("OIDC refuses a different discovery issuer and insecure endpoints", async () => {
  const original = globalThis.fetch;
  const config = {issuer:"https://id.example",clientId:"test",clientSecret:"test",scopes:["openid"]};
  try {
    for (const bad of [{issuer:"https://other.example"},{token_endpoint:"http://other.example/token"}]) {
      resetPocketIdDiscoveryCache();
      globalThis.fetch = (async () => Response.json({issuer:config.issuer,authorization_endpoint:config.issuer+"/authorize",token_endpoint:config.issuer+"/token",jwks_uri:config.issuer+"/jwks",...bad})) as unknown as typeof fetch;
      await expect(buildPocketIdAuthUrl(config,"https://mcp.example/callback",{state:"test",codeChallenge:"test"})).rejects.toThrow();
    }
  } finally { globalThis.fetch = original; resetPocketIdDiscoveryCache(); }
});
