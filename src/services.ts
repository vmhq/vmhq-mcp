export type ServiceId =
  | "home_assistant"
  | "miniflux"
  | "karakeep"
  | "searxng"
  | "proxmox"
  | "memos";

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
};

export const SERVICE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type ServiceMethod = (typeof SERVICE_METHODS)[number];

export type ServiceRequestInput = {
  method: ServiceMethod;
  path: string;
  query?: Record<string, string | number | boolean | Array<string | number | boolean>>;
  body?: unknown;
  headers?: Record<string, string>;
};
