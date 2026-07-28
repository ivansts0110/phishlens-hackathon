import { NextRequest, NextResponse } from "next/server";
import { analyze, scoreResult, senderDomain } from "@/lib/phishing-engine";
import { addScan } from "@/lib/store";
import { explainWithAI } from "@/lib/ai-explain";
import { enrichWithPythonService } from "@/lib/enrich";
import { checkRateLimit, clientKey } from "@/lib/rate-limit";

const MAX_BODY_LENGTH = 20_000;
const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60_000;

export async function POST(req: NextRequest) {
  const rate = checkRateLimit(clientKey(req), RATE_LIMIT, RATE_WINDOW_MS);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many requests. Please slow down." },
      { status: 429, headers: { "Retry-After": Math.ceil(rate.retryAfterMs / 1000).toString() } },
    );
  }

  let payload: unknown;
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 });
  }

  const { sender, subject, body: messageBody, org } = (payload as Record<string, unknown>) ?? {};

  if (typeof messageBody !== "string" || messageBody.trim().length === 0) {
    return NextResponse.json({ error: "Message body is required." }, { status: 400 });
  }
  if (messageBody.length > MAX_BODY_LENGTH) {
    return NextResponse.json(
      { error: `Message body must be under ${MAX_BODY_LENGTH.toLocaleString()} characters.` },
      { status: 400 },
    );
  }

  const input = {
    sender: typeof sender === "string" ? sender.slice(0, 500) : "",
    subject: typeof subject === "string" ? subject.slice(0, 500) : "",
    body: messageBody,
  };

  const heuristicResult = analyze(input);
  const enrichment = await enrichWithPythonService(senderDomain(input.sender), heuristicResult.urls);
  const result = enrichment.indicators.length
    ? scoreResult([...heuristicResult.indicators, ...enrichment.indicators], heuristicResult.urls)
    : heuristicResult;

  const ai = await explainWithAI(input, result);

  const record = addScan({
    org: typeof org === "string" && org.trim() ? org.trim().slice(0, 200) : "Unassigned",
    sender: input.sender,
    subject: input.subject,
    result,
    aiExplanation: ai.text ?? undefined,
  });

  return NextResponse.json({ ...record, aiStatus: ai.status, enrichStatus: enrichment.status });
}
