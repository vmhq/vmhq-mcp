import { afterEach, describe, expect, test } from "bun:test";
import { loadConfig } from "../src/config.js";

const original = process.env.MCP_ACCESS_TOKEN;
afterEach(() => {
  if (original === undefined) delete process.env.MCP_ACCESS_TOKEN;
  else process.env.MCP_ACCESS_TOKEN = original;
});

describe("MCP_ACCESS_TOKEN strength", () => {
  test("rejects tokens shorter than 32 characters", () => {
    process.env.MCP_ACCESS_TOKEN = "change-me";
    expect(() => loadConfig()).toThrow("MCP_ACCESS_TOKEN");
  });

  test("accepts a 48-character token", () => {
    process.env.MCP_ACCESS_TOKEN = "x".repeat(48);
    expect(() => loadConfig()).not.toThrow();
  });
});
