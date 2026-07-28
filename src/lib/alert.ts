import type { ScanRecord } from "./store";

const TIMEOUT_MS = 3000;

export function fireAlertWebhook(record: ScanRecord): void {
  const url = process.env.ALERT_WEBHOOK_URL;
  if (!url) return;
  if (record.result.level !== "High" && record.result.level !== "Critical") return;

  const topIndicators = record.result.indicators
    .slice(0, 3)
    .map((i) => `• ${i.label}`)
    .join("\n");

  const text =
    `:rotating_light: PhishLens ${record.result.level.toUpperCase()} alert — score ${record.result.score}/100\n` +
    `Org: ${record.org}\n` +
    `Sender: ${record.sender || "(none)"}\n` +
    `Subject: ${record.subject || "(none)"}\n` +
    (topIndicators ? `Top indicators:\n${topIndicators}` : "");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text }),
    signal: controller.signal,
  })
    .catch((err) => console.error("Alert webhook failed", err))
    .finally(() => clearTimeout(timer));
}
