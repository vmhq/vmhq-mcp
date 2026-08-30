import { afterEach, describe, expect, test } from "bun:test";
import { loadConfig, loadProxmoxSshConfig } from "../src/config.js";

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

const SSH_ENV_VARS = [
  "PROXMOX_SSH_HOST",
  "PROXMOX_SSH_PORT",
  "PROXMOX_SSH_USER",
  "PROXMOX_SSH_HOST_FINGERPRINT",
  "PROXMOX_SSH_ALLOWED_VMIDS",
  "PROXMOX_SSH_SUDO",
  "PROXMOX_SSH_CONTAINER_SHELL",
  "PROXMOX_SSH_JOB_DIR",
  "PROXMOX_SSH_JOB_RETENTION_DAYS",
] as const;

afterEach(() => {
  for (const name of SSH_ENV_VARS) delete process.env[name];
});

describe("loadProxmoxSshConfig", () => {
  test("stays disabled until PROXMOX_SSH_HOST is set", () => {
    expect(loadProxmoxSshConfig()).toBeUndefined();
  });

  test("applies maintenance-friendly defaults for a private node", () => {
    process.env.PROXMOX_SSH_HOST = "192.168.1.10";
    expect(loadProxmoxSshConfig()).toEqual({
      host: "192.168.1.10",
      port: 22,
      user: "root",
      hostFingerprint: undefined,
      timeoutMs: 120_000,
      maxOutputChars: 30_000,
      allowedVmids: undefined,
      sudo: false,
      containerShell: "/bin/sh",
      jobDir: "/var/log/vmhq-mcp",
      jobRetentionDays: 30,
    });
  });

  test("reads port, user, sudo, shell and the container allowlist", () => {
    process.env.PROXMOX_SSH_HOST = "pve.local";
    process.env.PROXMOX_SSH_PORT = "2222";
    process.env.PROXMOX_SSH_USER = "mcp";
    process.env.PROXMOX_SSH_SUDO = "true";
    process.env.PROXMOX_SSH_CONTAINER_SHELL = "/bin/bash";
    process.env.PROXMOX_SSH_ALLOWED_VMIDS = "101, 102 ,103";
    process.env.PROXMOX_SSH_JOB_DIR = "/srv/vmhq-jobs";
    process.env.PROXMOX_SSH_JOB_RETENTION_DAYS = "7";

    const config = loadProxmoxSshConfig();
    expect(config).toMatchObject({
      host: "pve.local",
      port: 2222,
      user: "mcp",
      sudo: true,
      containerShell: "/bin/bash",
      allowedVmids: [101, 102, 103],
      jobDir: "/srv/vmhq-jobs",
      jobRetentionDays: 7,
    });
  });

  test("rejects a malformed container allowlist", () => {
    process.env.PROXMOX_SSH_HOST = "pve.local";
    process.env.PROXMOX_SSH_ALLOWED_VMIDS = "101,not-a-vmid";
    expect(() => loadProxmoxSshConfig()).toThrow("PROXMOX_SSH_ALLOWED_VMIDS");
  });

  test("treats a single-label hostname as a local node", () => {
    process.env.PROXMOX_SSH_HOST = "pve";
    expect(loadProxmoxSshConfig()?.host).toBe("pve");
  });

  test("requires a pinned host key for a public node", () => {
    process.env.PROXMOX_SSH_HOST = "pve.example.com";
    expect(() => loadProxmoxSshConfig()).toThrow("PROXMOX_SSH_HOST_FINGERPRINT");

    process.env.PROXMOX_SSH_HOST_FINGERPRINT = "SHA256:abc";
    expect(loadProxmoxSshConfig()?.hostFingerprint).toBe("SHA256:abc");
  });
});
