export type Indicator = {
  id: string;
  category: "sender" | "links" | "content" | "urgency";
  label: string;
  detail: string;
  weight: number;
};

export type AnalysisInput = {
  sender: string;
  subject: string;
  body: string;
};

export type AnalysisResult = {
  score: number;
  level: "Low" | "Medium" | "High" | "Critical";
  indicators: Indicator[];
  urls: string[];
};

const KNOWN_BRANDS: { name: string; domain: string }[] = [
  { name: "PayPal", domain: "paypal.com" },
  { name: "Apple", domain: "apple.com" },
  { name: "Microsoft", domain: "microsoft.com" },
  { name: "Google", domain: "google.com" },
  { name: "Amazon", domain: "amazon.com" },
  { name: "Bank of America", domain: "bankofamerica.com" },
  { name: "Chase", domain: "chase.com" },
  { name: "Wells Fargo", domain: "wellsfargo.com" },
  { name: "Netflix", domain: "netflix.com" },
  { name: "DHL", domain: "dhl.com" },
  { name: "USPS", domain: "usps.com" },
  { name: "IRS", domain: "irs.gov" },
  { name: "DocuSign", domain: "docusign.com" },
  { name: "LinkedIn", domain: "linkedin.com" },
  { name: "Facebook", domain: "facebook.com" },
  { name: "Instagram", domain: "instagram.com" },
  { name: "Coinbase", domain: "coinbase.com" },
  { name: "Binance", domain: "binance.com" },
  { name: "American Express", domain: "americanexpress.com" },
  { name: "UPS", domain: "ups.com" },
  { name: "FedEx", domain: "fedex.com" },
  { name: "Zoom", domain: "zoom.us" },
  { name: "Dropbox", domain: "dropbox.com" },
  { name: "Adobe", domain: "adobe.com" },
];

const SUSPICIOUS_TLDS = [
  "zip", "top", "xyz", "country", "gq", "tk", "ml", "cf",
  "work", "click", "link", "support", "fit", "kim", "loan", "men", "rest",
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
];

const URGENCY_PHRASES = [
  "act now", "immediate action", "urgent", "within 24 hours", "expire", "expires today",
  "final notice", "last chance", "time-sensitive", "immediately", "right away", "as soon as possible",
];

const THREAT_PHRASES = [
  "account suspended", "account will be locked", "account has been limited", "unusual activity",
  "unauthorized access", "your account will be closed", "legal action", "suspended", "restricted",
  "your access will be", "failure to comply",
];

const CREDENTIAL_PHRASES = [
  "verify your password", "confirm your identity", "update your payment", "verify your account",
  "confirm your account", "reset your password", "enter your credentials", "log in to verify",
  "provide your ssn", "confirm your billing", "validate your information",
];

const GENERIC_GREETINGS = [
  "dear customer", "dear user", "dear valued customer", "dear account holder", "dear member",
];

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return dp[a.length][b.length];
}

function extractUrls(text: string): string[] {
  const urlRegex = /(https?:\/\/[^\s"'<>)\]]+)/gi;
  const matches = text.match(urlRegex) ?? [];
  return Array.from(new Set(matches));
}

function extractMarkupLinks(text: string): { text: string; href: string }[] {
  const links: { text: string; href: string }[] = [];
  const mdRegex = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi;
  let m: RegExpExecArray | null;
  while ((m = mdRegex.exec(text))) {
    links.push({ text: m[1], href: m[2] });
  }
  const anchorRegex = /<a\s+[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>([^<]*)<\/a>/gi;
  while ((m = anchorRegex.exec(text))) {
    links.push({ text: m[2], href: m[1] });
  }
  return links;
}

function domainOf(url: string): string | null {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

function isIpLiteral(hostname: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

function tldOf(hostname: string): string {
  const parts = hostname.split(".");
  return parts[parts.length - 1];
}

function senderDomain(sender: string): string | null {
  const match = sender.match(/@([a-zA-Z0-9.-]+)/);
  return match ? match[1].toLowerCase() : null;
}

function senderDisplayName(sender: string): string {
  const match = sender.match(/^([^<]+)</);
  return match ? match[1].trim() : "";
}

export function analyze(input: AnalysisInput): AnalysisResult {
  const indicators: Indicator[] = [];
  const fullText = `${input.subject}\n${input.body}`.toLowerCase();
  const urls = extractUrls(input.body);
  const markupLinks = extractMarkupLinks(input.body);
  const sDomain = senderDomain(input.sender);
  const displayName = senderDisplayName(input.sender).toLowerCase();

  // 1. Brand impersonation: display name claims to be a known brand, but the sender
  // domain isn't that brand's real domain. This catches both close typo-domains
  // (paypa1.com) and brand-name-stuffed unrelated domains (paypal-support-secure.com),
  // which is the more common real-world pattern.
  for (const brand of KNOWN_BRANDS) {
    const claimsBrand = displayName.includes(brand.name.toLowerCase());
    if (claimsBrand && sDomain && sDomain !== brand.domain && !sDomain.endsWith(`.${brand.domain}`)) {
      const brandLabel = brand.domain.split(".")[0];
      const domainLabel = sDomain.split(".")[0];
      const dist = levenshtein(domainLabel, brandLabel);
      const closeTypo = dist <= 2;
      indicators.push({
        id: `impersonation-${brand.domain}`,
        category: "sender",
        label: `Likely impersonation of ${brand.name}`,
        detail: `Sender display name claims to be "${brand.name}" but the domain is "${sDomain}", not "${brand.domain}".`,
        weight: closeTypo ? 35 : 28,
      });
      break;
    }
  }

  // 2. Suspicious URLs
  let flaggedShortener = false;
  let flaggedIp = false;
  let flaggedTld = false;
  for (const url of urls) {
    const host = domainOf(url);
    if (!host) continue;
    if (isIpLiteral(host) && !flaggedIp) {
      flaggedIp = true;
      indicators.push({
        id: "ip-url",
        category: "links",
        label: "Raw IP address used as a link",
        detail: `Link points directly to an IP address (${host}) instead of a domain name — common in phishing kits.`,
        weight: 20,
      });
    }
    if (URL_SHORTENERS.includes(host) && !flaggedShortener) {
      flaggedShortener = true;
      indicators.push({
        id: "shortener",
        category: "links",
        label: "URL shortener detected",
        detail: `Link uses a shortening service (${host}) that hides the real destination.`,
        weight: 15,
      });
    }
    if (SUSPICIOUS_TLDS.includes(tldOf(host)) && !flaggedTld) {
      flaggedTld = true;
      indicators.push({
        id: "suspicious-tld",
        category: "links",
        label: "Uncommon top-level domain",
        detail: `Link domain "${host}" uses a TLD frequently abused for throwaway phishing infrastructure.`,
        weight: 15,
      });
    }
  }

  // 3. Mismatched link text vs actual destination
  for (const link of markupLinks) {
    const textLooksLikeUrl = /^(https?:\/\/|www\.)/i.test(link.text.trim());
    const hrefHost = domainOf(link.href);
    if (textLooksLikeUrl && hrefHost) {
      const textHost = link.text.replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
      if (textHost && !textHost.includes(hrefHost) && !hrefHost.includes(textHost)) {
        indicators.push({
          id: "link-mismatch",
          category: "links",
          label: "Link text does not match destination",
          detail: `Displayed link "${link.text.trim()}" actually points to "${hrefHost}".`,
          weight: 25,
        });
        break;
      }
    }
  }

  // 4. Urgency language
  const urgencyHits = URGENCY_PHRASES.filter((p) => fullText.includes(p));
  if (urgencyHits.length > 0) {
    indicators.push({
      id: "urgency",
      category: "urgency",
      label: "Urgency / pressure language",
      detail: `Phrases designed to rush a decision: "${urgencyHits.slice(0, 3).join('", "')}".`,
      weight: Math.min(10 + (urgencyHits.length - 1) * 5, 20),
    });
  }

  // 5. Threats of account loss
  const threatHits = THREAT_PHRASES.filter((p) => fullText.includes(p));
  if (threatHits.length > 0) {
    indicators.push({
      id: "threat",
      category: "urgency",
      label: "Threatening consequences",
      detail: `Warns of loss of access or legal trouble: "${threatHits.slice(0, 2).join('", "')}".`,
      weight: 15,
    });
  }

  // 6. Credential / payment harvesting language
  const credHits = CREDENTIAL_PHRASES.filter((p) => fullText.includes(p));
  if (credHits.length > 0) {
    indicators.push({
      id: "credential-harvest",
      category: "content",
      label: "Requests credentials or payment info",
      detail: `Asks the recipient to verify sensitive information: "${credHits.slice(0, 2).join('", "')}".`,
      weight: 20,
    });
  }

  // 7. Generic greeting
  if (GENERIC_GREETINGS.some((g) => fullText.includes(g))) {
    indicators.push({
      id: "generic-greeting",
      category: "content",
      label: "Generic, non-personalized greeting",
      detail: `Uses a generic salutation instead of the recipient's name — common in mass phishing blasts.`,
      weight: 8,
    });
  }

  // 8. Reply-to mismatch
  const replyToMatch = input.body.match(/reply-to:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)>?/i);
  if (replyToMatch && sDomain) {
    const replyDomain = replyToMatch[1].split("@")[1].toLowerCase();
    if (replyDomain !== sDomain) {
      indicators.push({
        id: "reply-to-mismatch",
        category: "sender",
        label: "Reply-To differs from sender domain",
        detail: `Sender domain is "${sDomain}" but replies are routed to "${replyDomain}".`,
        weight: 15,
      });
    }
  }

  // 9. Suspicious attachment mention
  if (/\.(exe|scr|js|vbs|jar|bat|cmd)\b/i.test(input.body)) {
    indicators.push({
      id: "suspicious-attachment",
      category: "content",
      label: "References an executable attachment",
      detail: "Mentions an attachment type commonly used to deliver malware.",
      weight: 20,
    });
  }

  const rawScore = indicators.reduce((sum, i) => sum + i.weight, 0);
  const score = Math.min(100, rawScore);

  let level: AnalysisResult["level"] = "Low";
  if (score >= 75) level = "Critical";
  else if (score >= 50) level = "High";
  else if (score >= 25) level = "Medium";

  return { score, level, indicators, urls };
}
