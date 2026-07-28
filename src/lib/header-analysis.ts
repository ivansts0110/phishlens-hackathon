import type { Indicator } from "./phishing-engine";

export type HeaderReport = {
  authenticationResults: {
    spf: string | null;
    dkim: string | null;
    dmarc: string | null;
  };
  fromDomain: string | null;
  returnPathDomain: string | null;
  replyToDomain: string | null;
  receivedChain: string[];
};

export type RawHeader = { key: string; value: string };

function domainOfAddress(value: string | undefined | null): string | null {
  if (!value) return null;
  const match = value.match(/@([^\s<>@"',;]+)/);
  return match ? match[1].replace(/[>.,;\s]+$/, "").toLowerCase() : null;
}

function headerValue(headers: RawHeader[], name: string): string | null {
  const h = headers.find((x) => x.key.toLowerCase() === name.toLowerCase());
  return h ? h.value : null;
}

function headerValues(headers: RawHeader[], name: string): string[] {
  return headers.filter((x) => x.key.toLowerCase() === name.toLowerCase()).map((x) => x.value);
}

function parseAuthenticationResults(headers: RawHeader[]): HeaderReport["authenticationResults"] {
  const results: HeaderReport["authenticationResults"] = { spf: null, dkim: null, dmarc: null };
  for (const value of headerValues(headers, "authentication-results")) {
    const lower = value.toLowerCase();
    for (const mech of ["spf", "dkim", "dmarc"] as const) {
      if (results[mech]) continue;
      const m = lower.match(new RegExp(`${mech}=([a-z]+)`));
      if (m) results[mech] = m[1];
    }
  }
  return results;
}

export function analyzeHeaders(headers: RawHeader[]): { indicators: Indicator[]; report: HeaderReport } {
  const indicators: Indicator[] = [];

  const auth = parseAuthenticationResults(headers);
  const fromDomain = domainOfAddress(headerValue(headers, "from"));
  const returnPathDomain = domainOfAddress(headerValue(headers, "return-path"));
  const replyToDomain = domainOfAddress(headerValue(headers, "reply-to"));
  const receivedChain = headerValues(headers, "received").map((v) => v.split(";")[0].trim());

  const FAIL_VERDICTS = new Set(["fail", "softfail", "permerror"]);

  if (auth.spf && FAIL_VERDICTS.has(auth.spf)) {
    indicators.push({
      id: "header-spf-fail",
      category: "sender",
      label: `SPF check failed (${auth.spf})`,
      detail:
        "The receiving mail server determined the sending server was not authorized to send for this domain.",
      weight: 25,
    });
  }

  if (auth.dkim && FAIL_VERDICTS.has(auth.dkim)) {
    indicators.push({
      id: "header-dkim-fail",
      category: "sender",
      label: `DKIM signature failed (${auth.dkim})`,
      detail:
        "The message's cryptographic signature did not verify — the content may have been altered or forged in transit.",
      weight: 25,
    });
  }

  if (auth.dmarc && FAIL_VERDICTS.has(auth.dmarc)) {
    indicators.push({
      id: "header-dmarc-fail",
      category: "sender",
      label: `DMARC check failed (${auth.dmarc})`,
      detail:
        "The message failed the sending domain's own published authentication policy.",
      weight: 25,
    });
  }

  if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
    indicators.push({
      id: "header-return-path-mismatch",
      category: "sender",
      label: "Return-Path differs from From domain",
      detail: `Visible sender is "${fromDomain}" but bounces route to "${returnPathDomain}" — common when a spoofed From address rides on someone else's mail infrastructure. (Also produced by legitimate mailing-list and marketing senders, so this is a weak signal on its own.)`,
      weight: 10,
    });
  }

  if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
    indicators.push({
      id: "header-reply-to-mismatch",
      category: "sender",
      label: "Reply-To differs from From domain",
      detail: `Replies to this message go to "${replyToDomain}", not the visible sender domain "${fromDomain}" — a staple of invoice-fraud and executive-impersonation scams.`,
      weight: 18,
    });
  }

  return {
    indicators,
    report: { authenticationResults: auth, fromDomain, returnPathDomain, replyToDomain, receivedChain },
  };
}
