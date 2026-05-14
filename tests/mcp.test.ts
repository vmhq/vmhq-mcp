import { describe, expect, test } from "bun:test";
import { operationBody } from "../src/mcp.js";
import type { ApiEndpoint } from "../src/apiCatalog.js";

describe("operationBody", () => {
  test("returns inputBody unchanged when no defaultBody", () => {
    const endpoint: ApiEndpoint = { operationId: "get_me", method: "GET", path: "/v1/me", group: "users", summary: "Get user." };
    expect(operationBody(endpoint, { foo: "bar" })).toEqual({ foo: "bar" });
  });

  test("returns defaultBody copy when no inputBody", () => {
    const endpoint: ApiEndpoint = {
      operationId: "create_item",
      method: "POST",
      path: "/v1/items",
      group: "items",
      summary: "Create item.",
      defaultBody: { enabled: true },
    };
    expect(operationBody(endpoint, undefined)).toEqual({ enabled: true });
  });

  test("merges defaultBody with caller body, caller wins on conflict", () => {
    const endpoint: ApiEndpoint = {
      operationId: "create_item",
      method: "POST",
      path: "/v1/items",
      group: "items",
      summary: "Create item.",
      defaultBody: { enabled: true, category: "default" },
    };
    const body = operationBody(endpoint, {
      enabled: false,
      name: "Example",
    });
    expect(body).toEqual({
      enabled: false,
      category: "default",
      name: "Example",
    });
  });

  test("parses JSON string body and merges with defaultBody", () => {
    const endpoint: ApiEndpoint = {
      operationId: "create_item",
      method: "POST",
      path: "/v1/items",
      group: "items",
      summary: "Create item.",
      defaultBody: { enabled: true },
    };
    const body = operationBody(endpoint, JSON.stringify({ name: "Hello", count: 2 }));
    expect(body).toEqual({
      enabled: true,
      name: "Hello",
      count: 2,
    });
  });

  test("preserves non-JSON string bodies", () => {
    const endpoint: ApiEndpoint = {
      operationId: "create_item",
      method: "POST",
      path: "/v1/items",
      group: "items",
      summary: "Create item.",
      defaultBody: { enabled: true },
    };
    expect(operationBody(endpoint, "raw body")).toBe("raw body");
  });
});
