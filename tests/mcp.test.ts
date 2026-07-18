import { describe, expect, test } from "bun:test";
import { combineAdguardStats, operationBody } from "../src/mcp.js";
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

describe("combineAdguardStats", () => {
  test("sums numeric counters across instances", () => {
    const combined = combineAdguardStats([
      { num_dns_queries: 100, num_blocked_filtering: 10 },
      { num_dns_queries: 50, num_blocked_filtering: 5 },
    ]);
    expect(combined.num_dns_queries).toBe(150);
    expect(combined.num_blocked_filtering).toBe(15);
  });

  test("sums per-unit series aligned at the most recent value", () => {
    const combined = combineAdguardStats([
      { dns_queries: [1, 2, 3] },
      { dns_queries: [10, 20] },
    ]);
    expect(combined.dns_queries).toEqual([1, 12, 23]);
  });

  test("merges top_* lists summing shared entries and sorting by count", () => {
    const combined = combineAdguardStats([
      { top_blocked_domains: [{ "ads.example.com": 5 }, { "tracker.example.com": 3 }] },
      { top_blocked_domains: [{ "tracker.example.com": 9 }] },
    ]);
    expect(combined.top_blocked_domains).toEqual([
      { "tracker.example.com": 12 },
      { "ads.example.com": 5 },
    ]);
  });

  test("weights avg_processing_time by query count", () => {
    const combined = combineAdguardStats([
      { num_dns_queries: 90, avg_processing_time: 10 },
      { num_dns_queries: 10, avg_processing_time: 110 },
    ]);
    expect(combined.avg_processing_time).toBe(20);
  });

  test("falls back to simple mean for avg_processing_time when there are no queries", () => {
    const combined = combineAdguardStats([
      { num_dns_queries: 0, avg_processing_time: 4 },
      { num_dns_queries: 0, avg_processing_time: 6 },
    ]);
    expect(combined.avg_processing_time).toBe(5);
  });

  test("keeps the first value for non-numeric fields like time_units", () => {
    const combined = combineAdguardStats([{ time_units: "hours" }, { time_units: "hours" }]);
    expect(combined.time_units).toBe("hours");
  });
});
