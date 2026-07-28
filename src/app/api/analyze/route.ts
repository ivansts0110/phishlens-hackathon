import { NextRequest, NextResponse } from "next/server";
import { analyze, scoreResult, senderDomain } from "@/lib/phishing-engine";
import { analyzeHeaders, type HeaderReport } from "@/lib/header-analysis";
import { parseEml } from "@/lib/eml";
import { addScan } from "@/lib/store";
import { explainWithAI } from "@/lib/ai-explain";
import { enrichWithPythonService } from "@/lib/enrich";
import { fireAlertWebhook } from "@/lib/alert";
import { checkRateLimit, clientKey } from "@/lib/rate-limit";

const MAX_BODY_LENGTH = 20_000;
const MAX_EML_LENGTH = 500_000;
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

  const { sender, subject, body: messageBody, org, eml } = (payload as Record<string, unknown>) ?? {};

  let input: { sender: string; subject: string; body: string };
  let headerIndicators: ReturnType<typeof analyzeHeaders>["indicators"] = [];
  let headerReport: HeaderReport | undefined;

  if (typeof eml === "string" && eml.trim()) {
    if (eml.length > MAX_EML_LENGTH) {
      return NextResponse.json(
        { error: `Raw email must be under ${(MAX_EML_LENGTH / 1000).toLocaleString()} KB.` },
        { status: 400 },
      );
    }
    let parsed;
    try {
      parsed = await parseEml(eml);
    } catch {
      return NextResponse.json({ error: "Could not parse the uploaded file as an email (.eml)." }, { status: 400 });
    }
    const headerAnalysis = analyzeHeaders(parsed.headers);
    headerIndicators = headerAnalysis.indicators;
    headerReport = headerAnalysis.report;
    input = {
      sender: parsed.sender.slice(0, 500),
      subject: parsed.subject.slice(0, 500),
      body: parsed.body.slice(0, MAX_BODY_LENGTH),
    };
  } else {
    if (typeof messageBody !== "string" || messageBody.trim().length === 0) {
      return NextResponse.json({ error: "Message body is required." }, { status: 400 });
    }
    if (messageBody.length > MAX_BODY_LENGTH) {
      return NextResponse.json(
        { error: `Message body must be under ${MAX_BODY_LENGTH.toLocaleString()} characters.` },
        { status: 400 },
      );
    }
    input = {
      sender: typeof sender === "string" ? sender.slice(0, 500) : "",
      subject: typeof subject === "string" ? subject.slice(0, 500) : "",
      body: messageBody,
    };
  }

  const heuristicResult = analyze(input);
  const enrichment = await enrichWithPythonService(senderDomain(input.sender), heuristicResult.urls);

  const extraIndicators = [...headerIndicators, ...enrichment.indicators];
  const result = extraIndicators.length
    ? scoreResult([...heuristicResult.indicators, ...extraIndicators], heuristicResult.urls)
    : heuristicResult;

  const ai = await explainWithAI(input, result);

  const record = addScan({
    org: typeof org === "string" && org.trim() ? org.trim().slice(0, 200) : "Unassigned",
    sender: input.sender,
    subject: input.subject,
    result,
    aiExplanation: ai.text ?? undefined,
    headerReport,
  });

  fireAlertWebhook(record);

  return NextResponse.json({ ...record, aiStatus: ai.status, enrichStatus: enrichment.status });
}
