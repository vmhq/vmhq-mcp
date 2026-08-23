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

describe("adguard instance", () => {
  test("adguard is disabled without ADGUARD_BASE_URL", () => {
    const service = serviceFromRegistryEntry(entryFor("adguard"), makeReadEnv({}));
    expect(service).toBeUndefined();
  });

  test("adguard builds from its own env vars", () => {
    const service = serviceFromRegistryEntry(
      entryFor("adguard"),
      makeReadEnv({
        ADGUARD_BASE_URL: "https://adguard.example.com",
        ADGUARD_USERNAME: "admin",
        ADGUARD_PASSWORD: "secret",
      }),
    );

    expect(service?.id).toBe("adguard");
    expect(service?.baseUrl).toBe("https://adguard.example.com");
    expect(service?.defaultPathPrefix).toBe("/control");
    expect(service?.auth).toEqual({
      type: "static",
      headerName: "Authorization",
      value: `Basic ${Buffer.from("admin:secret").toString("base64")}`,
    });
  });

  test("adguard sets auth none when credentials are empty", () => {
    const service = serviceFromRegistryEntry(
      entryFor("adguard"),
      makeReadEnv({
        ADGUARD_BASE_URL: "https://adguard.example.com",
      }),
    );

    expect(service?.auth).toEqual({ type: "none" });
  });

  test("adguard throws when only one credential is set", () => {
    expect(() =>
      serviceFromRegistryEntry(
        entryFor("adguard"),
        makeReadEnv({
          ADGUARD_BASE_URL: "https://adguard.example.com",
          ADGUARD_USERNAME: "admin",
        }),
      ),
    ).toThrow("ADGUARD_USERNAME and ADGUARD_PASSWORD must be configured together.");
  });

  test("adguard catalog has expected properties", () => {
    expect(API_CATALOGS.adguard.service).toBe("adguard");
    expect(API_CATALOGS.adguard.auth).toContain("ADGUARD_USERNAME");
  });
});
