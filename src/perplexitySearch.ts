import { log } from "./logger.js";

export const PERPLEXITY_MODELS = {
  sonar_pro: "perplexity/sonar-pro",
  sonar_reasoning_pro: "perplexity/sonar-reasoning-pro",
} as const;

export type PerplexityModelKey = keyof typeof PERPLEXITY_MODELS;
export type PerplexityModelId = (typeof PERPLEXITY_MODELS)[PerplexityModelKey];

export type PerplexitySearchOptions = {
  system?: string;
  maxTokens?: number;
  timeoutMs?: number;
};

export type PerplexitySearchResult = {
  model: string;
  content: string;
  citations: string[];
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number } | null;
};

export type PerplexitySearchError = {
  error: { type: string; service: "perplexity"; message: string; retryable: boolean };
};

const DEFAULT_MAX_TOKENS: Record<PerplexityModelId, number> = {
  "perplexity/sonar-pro": 1024,
  "perplexity/sonar-reasoning-pro": 2048,
};

export async function searchPerplexity(
  apiKey: string,
  baseUrl: string,
  model: PerplexityModelId,
  query: string,
  options: PerplexitySearchOptions = {},
): Promise<PerplexitySearchResult | PerplexitySearchError> {
  const { system, maxTokens, timeoutMs = 60_000 } = options;

  const messages = [
    ...(system ? [{ role: "system", content: system }] : []),
    { role: "user", content: query },
  ];

  const requestBody = JSON.stringify({
    model,
    messages,
    max_tokens: maxTokens ?? DEFAULT_MAX_TOKENS[model],
  });

  const url = `${baseUrl.replace(/\/+$/, "")}/chat/completions`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = performance.now();

  log("info", "upstream_request_started", { service: "perplexity", operationId: model, method: "POST", path: "/chat/completions" });

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
        Accept: "application/json",
      },
      body: requestBody,
      signal: controller.signal,
    });

    const text = await response.text();
    const durationMs = Math.round(performance.now() - startedAt);

    log(response.ok ? "info" : "error", "upstream_request_finished", {
      service: "perplexity",
      operationId: model,
      method: "POST",
      path: "/chat/completions",
      status: response.status,
      durationMs,
    });

    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      return { error: { type: "parse_error", service: "perplexity", message: "Failed to parse OpenRouter response.", retryable: false } };
    }

    if (!response.ok) {
      const msg = typeof data === "object" && data !== null && "error" in data
        ? JSON.stringify((data as Record<string, unknown>).error)
        : text;
      return {
        error: {
          type: "upstream_error",
          service: "perplexity",
          message: `OpenRouter responded with HTTP ${response.status}: ${msg}`,
          retryable: response.status >= 500,
        },
      };
    }

    const d = data as Record<string, unknown>;
    const choices = Array.isArray(d.choices) ? (d.choices as Array<Record<string, unknown>>) : [];
    const message = choices[0]?.message as Record<string, unknown> | undefined;
    const content = typeof message?.content === "string" ? message.content : "";

    const topLevelCitations = Array.isArray(d.citations) ? (d.citations as string[]) : [];
    const annotations = Array.isArray(message?.annotations) ? (message.annotations as Array<Record<string, unknown>>) : [];
    const annotationUrls = annotations
      .filter((a) => a.type === "url_citation" && typeof a.url === "string")
      .map((a) => a.url as string);

    const citations = topLevelCitations.length > 0 ? topLevelCitations : annotationUrls;
    const usage = (d.usage as { prompt_tokens: number; completion_tokens: number; total_tokens: number } | undefined) ?? null;
    const actualModel = typeof d.model === "string" ? d.model : model;

    return { model: actualModel, content, citations, usage };
  } catch (error) {
    const durationMs = Math.round(performance.now() - startedAt);
    const aborted = controller.signal.aborted;

    log("error", "upstream_request_failed", {
      service: "perplexity",
      operationId: model,
      method: "POST",
      path: "/chat/completions",
      durationMs,
      error: error instanceof Error ? error.message : String(error),
      timeout: aborted,
    });

    return {
      error: {
        type: aborted ? "upstream_timeout" : "upstream_network_error",
        service: "perplexity",
        message: aborted ? `Request exceeded ${timeoutMs}ms.` : error instanceof Error ? error.message : "Request failed.",
        retryable: true,
      },
    };
  } finally {
    clearTimeout(timeout);
  }
}
