export type LogLevel = "silent" | "error" | "info" | "debug";

const LEVELS: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  info: 2,
  debug: 3,
};

function configuredLevel(): LogLevel {
  const raw = (process.env.MCP_LOG_LEVEL ?? "info").toLowerCase();
  if (raw === "silent" || raw === "error" || raw === "info" || raw === "debug") {
    return raw;
  }
  return "info";
}

function shouldLog(level: Exclude<LogLevel, "silent">): boolean {
  return LEVELS[configuredLevel()] >= LEVELS[level];
}

export function log(level: Exclude<LogLevel, "silent">, event: string, fields: Record<string, unknown> = {}): void {
  if (!shouldLog(level)) return;

  const payload = {
    timestamp: new Date().toISOString(),
    level,
    event,
    ...fields,
  };

  const line = JSON.stringify(payload);
  if (level === "error") {
    console.error(line);
  } else {
    console.log(line);
  }
}
