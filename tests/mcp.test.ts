import { describe, expect, test } from "bun:test";
import { operationBody } from "../src/mcp.js";
import { PERPLEXITY_MODELS, searchPerplexity } from "../src/perplexitySearch.js";
import type { ApiEndpoint } from "../src/apiCatalog.js";

describe("operationBody", () => {
  test("returns inputBody unchanged when no defaultBody", () => {
    const endpoint: ApiEndpoint = { operationId: "get_me", method: "GET", path: "/v1/me", group: "users", summary: "Get user." };
    expect(operationBody(endpoint, { foo: "bar" })).toEqual({ foo: "bar" });
  });

  test("returns defaultBody copy when no inputBody", () => {
    const endpoint: ApiEndpoint = {
      operationId: "search_sonar_pro",
      method: "POST",
      path: "/chat/completions",
      group: "search",
      summary: "Search.",
      defaultBody: { model: "perplexity/sonar-pro" },
    };
    expect(operationBody(endpoint, undefined)).toEqual({ model: "perplexity/sonar-pro" });
  });

  test("merges defaultBody with caller body, caller wins on conflict", () => {
    const endpoint: ApiEndpoint = {
      operationId: "search_sonar_pro",
      method: "POST",
      path: "/chat/completions",
      group: "search",
      summary: "Search.",
      defaultBody: { model: "perplexity/sonar-pro" },
    };
    const body = operationBody(endpoint, {
      model: "perplexity/sonar-reasoning-pro",
      messages: [{ role: "user", content: "Compare two options." }],
    });
    expect(body).toEqual({
      model: "perplexity/sonar-reasoning-pro",
      messages: [{ role: "user", content: "Compare two options." }],
    });
  });

  test("parses JSON string body and merges with defaultBody", () => {
    const endpoint: ApiEndpoint = {
      operationId: "search_sonar_pro",
      method: "POST",
      path: "/chat/completions",
      group: "search",
      summary: "Search.",
      defaultBody: { model: "perplexity/sonar-pro" },
    };
    const body = operationBody(endpoint, JSON.stringify({ messages: [{ role: "user", content: "Hello" }], max_tokens: 512 }));
    expect(body).toEqual({
      model: "perplexity/sonar-pro",
      messages: [{ role: "user", content: "Hello" }],
      max_tokens: 512,
    });
  });

  test("preserves non-JSON string bodies", () => {
    const endpoint: ApiEndpoint = {
      operationId: "search_sonar_pro",
      method: "POST",
      path: "/chat/completions",
      group: "search",
      summary: "Search.",
      defaultBody: { model: "perplexity/sonar-pro" },
    };
    expect(operationBody(endpoint, "raw body")).toBe("raw body");
  });
});

describe("PERPLEXITY_MODELS", () => {
  test("maps sonar_pro to the correct model ID", () => {
    expect(PERPLEXITY_MODELS.sonar_pro).toBe("perplexity/sonar-pro");
  });

  test("maps sonar_reasoning_pro to the correct model ID", () => {
    expect(PERPLEXITY_MODELS.sonar_reasoning_pro).toBe("perplexity/sonar-reasoning-pro");
  });
});

describe("searchPerplexity", () => {
  test("returns missing credentials error when apiKey is empty", async () => {
    const result = await searchPerplexity("", "https://openrouter.ai/api/v1", "perplexity/sonar-pro", "test query");
    expect(result).toHaveProperty("error");
  });

  test("returns upstream error on non-ok response", async () => {
    const originalFetch = global.fetch;
    global.fetch = Object.assign(
      async () => new Response(JSON.stringify({ error: { message: "Unauthorized" } }), { status: 401, headers: { "Content-Type": "application/json" } }),
      { preconnect: () => {} },
    ) as typeof fetch;

    const result = await searchPerplexity("bad-key", "https://openrouter.ai/api/v1", "perplexity/sonar-pro", "test");
    expect(result).toHaveProperty("error");
    expect((result as { error: { type: string } }).error.type).toBe("upstream_error");

    global.fetch = originalFetch;
  });

  test("parses top-level citations from a successful response", async () => {
    const originalFetch = global.fetch;
    global.fetch = Object.assign(
      async () =>
        new Response(
          JSON.stringify({
            model: "perplexity/sonar-pro",
            choices: [{ message: { role: "assistant", content: "The answer is 42." }, finish_reason: "stop" }],
            citations: ["https://example.com/1", "https://example.com/2"],
            usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      { preconnect: () => {} },
    ) as typeof fetch;

    const result = await searchPerplexity("valid-key", "https://openrouter.ai/api/v1", "perplexity/sonar-pro", "What is 42?");
    expect(result).not.toHaveProperty("error");
    const r = result as { model: string; content: string; citations: string[]; usage: unknown };
    expect(r.model).toBe("perplexity/sonar-pro");
    expect(r.content).toBe("The answer is 42.");
    expect(r.citations).toEqual(["https://example.com/1", "https://example.com/2"]);
    expect(r.usage).toEqual({ prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 });

    global.fetch = originalFetch;
  });

  test("falls back to annotation URLs when no top-level citations", async () => {
    const originalFetch = global.fetch;
    global.fetch = Object.assign(
      async () =>
        new Response(
          JSON.stringify({
            model: "perplexity/sonar-pro",
            choices: [
              {
                message: {
                  role: "assistant",
                  content: "Result.",
                  annotations: [
                    { type: "url_citation", url: "https://source.com/a" },
                    { type: "url_citation", url: "https://source.com/b" },
                  ],
                },
                finish_reason: "stop",
              },
            ],
            usage: null,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      { preconnect: () => {} },
    ) as typeof fetch;

    const result = await searchPerplexity("valid-key", "https://openrouter.ai/api/v1", "perplexity/sonar-pro", "test");
    const r = result as { citations: string[] };
    expect(r.citations).toEqual(["https://source.com/a", "https://source.com/b"]);

    global.fetch = originalFetch;
  });
});
