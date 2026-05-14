import { describe, expect, test } from "bun:test";
import { API_CATALOGS } from "../src/apiCatalog.js";
import { operationBody } from "../src/mcp.js";

describe("Perplexity operation defaults", () => {
  test("catalog defines default models for Perplexity operations", () => {
    const endpoints = Object.fromEntries(
      API_CATALOGS.perplexity.endpoints.map((endpoint) => [endpoint.operationId, endpoint]),
    );

    expect(endpoints.search_sonar_pro.defaultBody).toEqual({ model: "perplexity/sonar-pro" });
    expect(endpoints.search_sonar_reasoning_pro.defaultBody).toEqual({ model: "perplexity/sonar-reasoning-pro" });
    expect(endpoints.deep_research.defaultBody).toEqual({ model: "perplexity/sonar-deep-research" });
  });

  test("operationBody injects the default model while preserving caller body", () => {
    const endpoint = API_CATALOGS.perplexity.endpoints.find((item) => item.operationId === "search_sonar_pro");
    expect(endpoint).toBeTruthy();

    const body = operationBody(endpoint!, {
      messages: [{ role: "user", content: "Current Bitcoin price?" }],
      max_tokens: 1024,
    });

    expect(body).toEqual({
      model: "perplexity/sonar-pro",
      messages: [{ role: "user", content: "Current Bitcoin price?" }],
      max_tokens: 1024,
    });
  });

  test("operationBody allows advanced callers to override the default model", () => {
    const endpoint = API_CATALOGS.perplexity.endpoints.find((item) => item.operationId === "search_sonar_pro");
    expect(endpoint).toBeTruthy();

    const body = operationBody(endpoint!, {
      model: "perplexity/sonar-reasoning-pro",
      messages: [{ role: "user", content: "Compare two options." }],
    });

    expect(body).toEqual({
      model: "perplexity/sonar-reasoning-pro",
      messages: [{ role: "user", content: "Compare two options." }],
    });
  });

  test("operationBody preserves non-object bodies", () => {
    const endpoint = API_CATALOGS.perplexity.endpoints.find((item) => item.operationId === "search_sonar_pro");
    expect(endpoint).toBeTruthy();

    expect(operationBody(endpoint!, "raw body")).toBe("raw body");
  });
});
