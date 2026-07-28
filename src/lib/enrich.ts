import type { Indicator } from "./phishing-engine";

const TIMEOUT_MS = 4000;
const VALID_CATEGORIES = new Set(["sender", "links", "content", "urgency"]);

export type EnrichStatus = "disabled" | "ok" | "timeout" | "error";

export type EnrichResult = {
  indicators: Indicator[];
  status: EnrichStatus;
};

export async function enrichWithPythonService(
  senderDomain: string | null,
  urls: string[],
): Promise<EnrichResult> {
  const baseUrl = process.env.PYTHON_SERVICE_URL;
  if (!baseUrl) return { indicators: [], status: "disabled" };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/enrich`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sender_domain: senderDomain ?? "", urls }),
      signal: controller.signal,
    });

    if (!res.ok) {
      console.error("Enrichment service error", res.status, await res.text());
      return { indicators: [], status: "error" };
    }

    const data = await res.json();
    const indicators = Array.isArray(data?.indicators)
      ? data.indicators.filter(isValidIndicator)
      : [];
    return { indicators, status: "ok" };
  } catch (err) {
    const timedOut = err instanceof Error && err.name === "AbortError";
    console.error(timedOut ? "Enrichment service call timed out" : "Enrichment service call failed", err);
    return { indicators: [], status: timedOut ? "timeout" : "error" };
  } finally {
    clearTimeout(timer);
  }
}

function isValidIndicator(value: unknown): value is Indicator {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === "string" &&
    typeof v.label === "string" &&
    typeof v.detail === "string" &&
    typeof v.weight === "number" &&
    typeof v.category === "string" &&
    VALID_CATEGORIES.has(v.category)
  );
}
