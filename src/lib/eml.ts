import PostalMime from "postal-mime";
import type { RawHeader } from "./header-analysis";

export type ParsedEml = {
  sender: string;
  subject: string;
  body: string;
  headers: RawHeader[];
};

export async function parseEml(raw: string): Promise<ParsedEml> {
  const parser = new PostalMime();
  const email = await parser.parse(raw);

  const fromName = email.from?.name?.trim();
  const fromAddress = email.from?.address ?? "";
  const sender = fromName ? `${fromName} <${fromAddress}>` : fromAddress;

  let body = email.text ?? "";
  if (!body.trim() && email.html) {
    body = email.html
      .replace(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, "[$2]($1)")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/g, " ")
      .replace(/\s{2,}/g, " ")
      .trim();
  }

  return {
    sender,
    subject: email.subject ?? "",
    body,
    headers: (email.headers ?? []).map((h) => ({ key: h.key, value: h.value })),
  };
}
