import { NextRequest, NextResponse } from "next/server";
import { redTeam } from "@/lib/adversary";
import { checkRateLimit, clientKey } from "@/lib/rate-limit";

const MAX_BODY_LENGTH = 20_000;
const RATE_LIMIT = 15;
const RATE_WINDOW_MS = 60_000;

export async function POST(req: NextRequest) {
  const rate = checkRateLimit(`redteam:${clientKey(req)}`, RATE_LIMIT, RATE_WINDOW_MS);
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

  const { sender, subject, body } = (payload as Record<string, unknown>) ?? {};
  if (typeof body !== "string" || body.trim().length === 0) {
    return NextResponse.json({ error: "Message body is required." }, { status: 400 });
  }
  if (body.length > MAX_BODY_LENGTH) {
    return NextResponse.json({ error: "Message body is too long." }, { status: 400 });
  }

  const report = redTeam({
    sender: typeof sender === "string" ? sender.slice(0, 500) : "",
    subject: typeof subject === "string" ? subject.slice(0, 500) : "",
    body,
  });

  return NextResponse.json(report);
}
