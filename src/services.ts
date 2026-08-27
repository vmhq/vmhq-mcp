export type ServiceId =
  | "home_assistant"
  | "miniflux"
  | "karakeep"
  | "searxng"
  | "proxmox"
  | "memos"
  | "adguard";

export type ServiceAuth =
  | { type: "none" }
  | { type: "bearer"; tokenEnv: string }
  | { type: "header"; tokenEnv: string; headerName: string }
  | { type: "prefixed"; tokenEnv: string; prefix: string }
  | { type: "static"; headerName: string; value: string };

export type ServiceDefinition = {
  id: ServiceId;
  title: string;
  baseUrl: string;
  auth: ServiceAuth;
  defaultPathPrefix: string;
  defaultPathParams?: Record<string, string>;
  timeoutMs?: number;
  pingPath?: string;
  /**
   * Skip TLS certificate verification for this service only. Intended for
   * upstreams on the local network that present a self-signed certificate
   * (e.g. Proxmox VE's cluster CA). Only honoured for private/loopback hosts.
   */
  insecureTls?: boolean;
};

export const SERVICE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type ServiceMethod = (typeof SERVICE_METHODS)[number];

export type ServiceRequestInput = {
  method: ServiceMethod;
  path: string;
  query?: Record<string, string | number | boolean | Array<string | number | boolean>>;
  body?: unknown;
  headers?: Record<string, string>;
  fields?: string[];
  maxLength?: number;
  domain?: string;
};
