import type { AnalysisResult } from "./phishing-engine";

const MODEL = process.env.ANTHROPIC_MODEL || "claude-haiku-4-5-20251001";

export async function explainWithAI(
  input: { sender: string; subject: string; body: string },
  result: AnalysisResult,
): Promise<string | null> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return null;

  const indicatorSummary = result.indicators.length
    ? result.indicators.map((i) => `- ${i.label}: ${i.detail}`).join("\n")
    : "- No automated indicators were triggered.";

  const prompt = `You are a security analyst assistant embedded in a phishing-detection tool. Given the message below and the heuristic indicators already detected, write a short (3-5 sentence) plain-English explanation for a non-technical employee: what this message is, why it scored the way it did, and one clear recommended action. Do not repeat the raw indicator list verbatim, synthesize it. Be concise and direct.

Sender: ${input.sender}
Subject: ${input.subject}
Body:
${input.body}

Heuristic risk score: ${result.score}/100 (${result.level})
Detected indicators:
${indicatorSummary}`;

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 300,
        messages: [{ role: "user", content: prompt }],
      }),
    });

    if (!res.ok) {
      console.error("Anthropic API error", res.status, await res.text());
      return null;
    }

    const data = await res.json();
    const text = data?.content?.[0]?.text;
    return typeof text === "string" ? text.trim() : null;
  } catch (err) {
    console.error("Anthropic API call failed", err);
    return null;
  }
}
