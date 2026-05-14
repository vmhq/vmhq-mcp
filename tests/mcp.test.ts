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
  test("returns missing credentials error when apiKey is empty without calling fetch", async () => {
    const originalFetch = global.fetch;
    let called = false;
    global.fetch = Object.assign(
      async () => {
        called = true;
        return new Response("unexpected");
      },
      { preconnect: () => {} },
    ) as typeof fetch;

    const result = await searchPerplexity("", "https://openrouter.ai/api/v1", "perplexity/sonar-pro", "test query");
    expect(result).toHaveProperty("error");
    expect((result as { error: { type: string } }).error.type).toBe("missing_upstream_credentials");
    expect(called).toBe(false);

    global.fetch = originalFetch;
  });

  test("clamps reasoning model max tokens to a safe minimum", async () => {
    const originalFetch = global.fetch;
    let body: unknown;
    global.fetch = Object.assign(
      async (_url: string | URL | Request, init?: RequestInit) => {
        body = JSON.parse(String(init?.body));
        return new Response(
          JSON.stringify({
            model: "perplexity/sonar-reasoning-pro",
            choices: [{ message: { role: "assistant", content: "Reasoned answer." }, finish_reason: "stop" }],
            usage: null,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      },
      { preconnect: () => {} },
    ) as typeof fetch;

    const result = await searchPerplexity("valid-key", "https://openrouter.ai/api/v1", "perplexity/sonar-reasoning-pro", "test", { maxTokens: 1 });
    expect(result).not.toHaveProperty("error");
    expect((body as { max_tokens: number }).max_tokens).toBe(512);

    global.fetch = originalFetch;
  });

  test("returns upstream error on non-ok response", async () => {
    const originalFetch = global.fetch;
    global.fetch = Object.assign(
      async () => new Response(JSON.stringify({ error: { message: "Unauthorized", code: 401 } }), { status: 401, headers: { "Content-Type": "application/json" } }),
      { preconnect: () => {} },
    ) as typeof fetch;

    const result = await searchPerplexity("bad-key", "https://openrouter.ai/api/v1", "perplexity/sonar-pro", "test");
    expect(result).toHaveProperty("error");
    const err = (result as { error: { type: string; status?: number; code?: string } }).error;
    expect(err.type).toBe("upstream_error");
    expect(err.status).toBe(401);
    expect(err.code).toBe("401");

    global.fetch = originalFetch;
  });

  test("normalizes non-json upstream errors", async () => {
    const originalFetch = global.fetch;
    global.fetch = Object.assign(
      async () => new Response("Internal Server Error", { status: 500, headers: { "Content-Type": "text/plain" } }),
      { preconnect: () => {} },
    ) as typeof fetch;

    const result = await searchPerplexity("valid-key", "https://openrouter.ai/api/v1", "perplexity/sonar-pro", "test");
    expect(result).toHaveProperty("error");
    const err = (result as { error: { type: string; message: string; retryable: boolean; status?: number } }).error;
    expect(err.type).toBe("upstream_error");
    expect(err.message).toContain("HTTP 500");
    expect(err.message).toContain("Internal Server Error");
    expect(err.retryable).toBe(true);
    expect(err.status).toBe(500);

    global.fetch = originalFetch;
  });

  test("returns empty_response for successful responses without assistant content", async () => {
    const originalFetch = global.fetch;
    global.fetch = Object.assign(
      async () =>
        new Response(
          JSON.stringify({
            model: "perplexity/sonar-pro",
            choices: [{ message: { role: "assistant", content: "" }, finish_reason: "length" }],
            usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      { preconnect: () => {} },
    ) as typeof fetch;

    const result = await searchPerplexity("valid-key", "https://openrouter.ai/api/v1", "perplexity/sonar-pro", "test");
    expect(result).toHaveProperty("error");
    const err = (result as { error: { type: string; retryable: boolean } }).error;
    expect(err.type).toBe("empty_response");
    expect(err.retryable).toBe(true);

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
