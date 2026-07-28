import { NextRequest, NextResponse } from "next/server";
import { traceUrl } from "@/lib/trace";
import { checkRateLimit, clientKey } from "@/lib/rate-limit";

// Stricter than /api/analyze: every call makes outbound network requests.
const RATE_LIMIT = 10;
const RATE_WINDOW_MS = 60_000;

export async function POST(req: NextRequest) {
  const rate = checkRateLimit(`trace:${clientKey(req)}`, RATE_LIMIT, RATE_WINDOW_MS);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many trace requests. Please slow down." },
      { status: 429, headers: { "Retry-After": Math.ceil(rate.retryAfterMs / 1000).toString() } },
    );
  }

  let payload: unknown;
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 });
  }

  const { url } = (payload as Record<string, unknown>) ?? {};
  if (typeof url !== "string" || !url.trim() || url.length > 2000) {
    return NextResponse.json({ error: "A url string is required." }, { status: 400 });
  }

  const result = await traceUrl(url.trim());
  return NextResponse.json(result);
}
