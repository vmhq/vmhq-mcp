import { describe, expect, test } from "bun:test";
import { SERVICE_REGISTRY, serviceFromRegistryEntry } from "../src/serviceRegistry.js";
import { API_CATALOGS } from "../src/apiCatalog.js";

function makeReadEnv(env: Record<string, string>) {
  return (name: string, fallback?: string): string => env[name] ?? fallback ?? "";
}

function entryFor(id: string) {
  const entry = SERVICE_REGISTRY.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Registry entry not found: ${id}`);
  return entry;
}

describe("adguard second instance", () => {
  test("adguard2 is disabled without ADGUARD2_BASE_URL", () => {
    const service = serviceFromRegistryEntry(entryFor("adguard2"), makeReadEnv({}));
    expect(service).toBeUndefined();
  });

  test("adguard2 builds from its own env vars", () => {
    const service = serviceFromRegistryEntry(
      entryFor("adguard2"),
      makeReadEnv({
        ADGUARD2_BASE_URL: "https://adguard2.example.com",
        ADGUARD2_USERNAME: "admin",
        ADGUARD2_PASSWORD: "secret",
      }),
    );

    expect(service?.id).toBe("adguard2");
    expect(service?.baseUrl).toBe("https://adguard2.example.com");
    expect(service?.defaultPathPrefix).toBe("/control");
    expect(service?.auth).toEqual({
      type: "static",
      headerName: "Authorization",
      value: `Basic ${Buffer.from("admin:secret").toString("base64")}`,
    });
  });

  test("adguard2 ignores primary ADGUARD_* credentials", () => {
    const service = serviceFromRegistryEntry(
      entryFor("adguard2"),
      makeReadEnv({
        ADGUARD2_BASE_URL: "https://adguard2.example.com",
        ADGUARD_USERNAME: "admin",
        ADGUARD_PASSWORD: "secret",
      }),
    );

    expect(service?.auth).toEqual({ type: "none" });
  });

  test("adguard2 throws when only one credential is set", () => {
    expect(() =>
      serviceFromRegistryEntry(
        entryFor("adguard2"),
        makeReadEnv({
          ADGUARD2_BASE_URL: "https://adguard2.example.com",
          ADGUARD2_USERNAME: "admin",
        }),
      ),
    ).toThrow("ADGUARD2_USERNAME and ADGUARD2_PASSWORD must be configured together.");
  });

  test("adguard2 catalog reuses the adguard endpoints", () => {
    expect(API_CATALOGS.adguard2.service).toBe("adguard2");
    expect(API_CATALOGS.adguard2.endpoints).toBe(API_CATALOGS.adguard.endpoints);
    expect(API_CATALOGS.adguard2.auth).toContain("ADGUARD2_USERNAME");
  });
});
