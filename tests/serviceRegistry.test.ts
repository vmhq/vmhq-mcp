import { describe, expect, test } from "bun:test";
import { isPrivateHost, SERVICE_REGISTRY, serviceFromRegistryEntry } from "../src/serviceRegistry.js";
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

describe("proxmox insecure TLS", () => {
  const baseEnv = {
    PROXMOX_BASE_URL: "https://192.168.3.10:8006",
    PROXMOX_TOKEN_ID: "root@pam!mcp",
    PROXMOX_TOKEN_SECRET: "secret",
  };

  test("TLS verification stays on by default", () => {
    const service = serviceFromRegistryEntry(entryFor("proxmox"), makeReadEnv(baseEnv));
    expect(service?.insecureTls).toBe(false);
  });

  test("PROXMOX_INSECURE_TLS=true disables verification for a private host", () => {
    const service = serviceFromRegistryEntry(
      entryFor("proxmox"),
      makeReadEnv({ ...baseEnv, PROXMOX_INSECURE_TLS: "true" }),
    );
    expect(service?.insecureTls).toBe(true);
  });

  test("other services are unaffected by the flag", () => {
    const service = serviceFromRegistryEntry(
      entryFor("memos"),
      makeReadEnv({ MEMOS_BASE_URL: "https://192.168.3.10", PROXMOX_INSECURE_TLS: "true" }),
    );
    expect(service?.insecureTls).toBe(false);
  });

  test("a non-truthy value keeps verification on", () => {
    const service = serviceFromRegistryEntry(
      entryFor("proxmox"),
      makeReadEnv({ ...baseEnv, PROXMOX_INSECURE_TLS: "false" }),
    );
    expect(service?.insecureTls).toBe(false);
  });

  test("throws when enabled for a public host", () => {
    expect(() =>
      serviceFromRegistryEntry(
        entryFor("proxmox"),
        makeReadEnv({ ...baseEnv, PROXMOX_BASE_URL: "https://pve.example.com:8006", PROXMOX_INSECURE_TLS: "true" }),
      ),
    ).toThrow("may only be enabled for private-network hosts");
  });
});

describe("isPrivateHost", () => {
  test("accepts loopback, RFC1918, CGNAT and local names", () => {
    for (const host of [
      "localhost",
      "127.0.0.1",
      "::1",
      "10.1.2.3",
      "192.168.3.10",
      "172.16.0.1",
      "172.31.255.254",
      "169.254.1.1",
      "100.64.0.1",
      "vmhq.local",
      "pve.internal",
      "fd00::1",
    ]) {
      expect(isPrivateHost(host)).toBe(true);
    }
  });

  test("rejects public hosts and near-miss ranges", () => {
    for (const host of [
      "example.com",
      "8.8.8.8",
      "172.15.0.1",
      "172.32.0.1",
      "192.169.0.1",
      "100.63.0.1",
      "100.128.0.1",
      "2606:4700::1111",
    ]) {
      expect(isPrivateHost(host)).toBe(false);
    }
  });
});
