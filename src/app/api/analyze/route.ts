import { NextRequest, NextResponse } from "next/server";
import { analyze } from "@/lib/phishing-engine";
import { addScan } from "@/lib/store";
import { explainWithAI } from "@/lib/ai-explain";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const { sender, subject, body: messageBody, org } = body ?? {};

  if (typeof messageBody !== "string" || messageBody.trim().length === 0) {
    return NextResponse.json({ error: "Message body is required." }, { status: 400 });
  }

  const input = {
    sender: typeof sender === "string" ? sender : "",
    subject: typeof subject === "string" ? subject : "",
    body: messageBody,
  };

  const result = analyze(input);
  const aiExplanation = await explainWithAI(input, result);

  const record = addScan({
    org: typeof org === "string" && org.trim() ? org.trim() : "Unassigned",
    sender: input.sender,
    subject: input.subject,
    result,
    aiExplanation: aiExplanation ?? undefined,
  });

  return NextResponse.json(record);
}
