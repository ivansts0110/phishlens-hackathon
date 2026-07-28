import { analyze, CREDENTIAL_PHRASES, GENERIC_GREETINGS, type AnalysisResult } from "./phishing-engine";

export type Email = { sender: string; subject: string; body: string };

export type Operator = {
  id: string;
  label: string;
  technique: string;
  targets: string;
  hardenable: boolean;
  recommendation: string;
  apply: (e: Email) => Email;
};

export type AttackStep = {
  operator: string;
  technique: string;
  scoreBefore: number;
  scoreAfter: number;
  defeatedIndicators: string[];
  hardenable: boolean;
  recommendation: string;
};

export type AttackReport = {
  startScore: number;
  startLevel: string;
  finalScore: number;
  finalLevel: string;
  steps: AttackStep[];
  finalEmail: Email;

  hardenedFinalScore: number;
  hardenedFinalLevel: string;
  neutralizedByHardening: string[];
  survivingTechniques: string[];
};

const ZWSP = "\u200b";

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function injectInvisible(text: string, phrases: readonly string[]): string {
  let out = text;
  for (const phrase of phrases) {
    const re = new RegExp(escapeRegExp(phrase), "gi");
    out = out.replace(re, (m) => m[0] + ZWSP + m.slice(1));
  }
  return out;
}

function replacePhrases(text: string, map: Record<string, string>): string {
  let out = text;
  for (const [from, to] of Object.entries(map)) {
    const re = new RegExp(escapeRegExp(from), "gi");
    out = out.replace(re, to);
  }
  return out;
}

const URGENCY_SOFTENING: Record<string, string> = {
  "act now": "when you have a moment",
  "immediate action": "a quick review",
  "within 24 hours": "at your convenience",
  "expires today": "available for a while",
  "final notice": "friendly reminder",
  "last chance": "opportunity",
  "time-sensitive": "routine",
  "immediately": "soon",
  "right away": "soon",
  "as soon as possible": "when convenient",
  "urgent": "a note",
  "expire": "continue",
};

const THREAT_SOFTENING: Record<string, string> = {
  "account will be locked": "account is in good standing",
  "account has been limited": "account is active",
  "account suspended": "account is active",
  "unusual activity": "recent activity",
  "unauthorized access": "your recent sign-in",
  "your account will be closed": "your account remains open",
  "failure to comply": "when you're ready",
  "legal action": "next steps",
  "your access will be": "your access is",
  "suspended": "active",
  "restricted": "available",
};

const OPERATORS: Operator[] = [
  {
    id: "invisible-chars",
    label: "Invisible-character injection",
    technique:
      "Inserts zero-width Unicode characters inside credential-request phrases (e.g. “verify your p\u200bassword”). Visually identical to a human, but it shatters a naive substring match.",
    targets: "Credential-harvesting keywords",
    hardenable: true,
    recommendation:
      "Normalize Unicode and strip zero-width / bidi control characters before keyword matching. (PhishLens already applies this — see below.)",
    apply: (e) => ({
      ...e,
      subject: injectInvisible(e.subject, CREDENTIAL_PHRASES),
      body: injectInvisible(e.body, CREDENTIAL_PHRASES),
    }),
  },
  {
    id: "urgency-paraphrase",
    label: "Urgency paraphrasing",
    technique:
      "Rewrites pressure phrases into calm, neutral language that carries the same intent without matching any keyword.",
    targets: "Urgency / pressure language",
    hardenable: false,
    recommendation:
      "Keyword lists can't catch paraphrased urgency. Layer a semantic / LLM classifier that scores intent, not literal strings (the optional AI layer).",
    apply: (e) => ({
      ...e,
      subject: replacePhrases(e.subject, URGENCY_SOFTENING),
      body: replacePhrases(e.body, URGENCY_SOFTENING),
    }),
  },
  {
    id: "threat-paraphrase",
    label: "Threat paraphrasing",
    technique: "Rewrites account-loss threats into reassuring language while preserving the call to action.",
    targets: "Threatening consequences",
    hardenable: false,
    recommendation: "Same as urgency — semantic intent modelling is needed, not a static phrase list.",
    apply: (e) => ({
      ...e,
      subject: replacePhrases(e.subject, THREAT_SOFTENING),
      body: replacePhrases(e.body, THREAT_SOFTENING),
    }),
  },
  {
    id: "sender-neutralize",
    label: "Sender neutralization",
    technique:
      "Drops the impersonated brand from the display name and swaps the look-alike domain for a plausible, brand-free throwaway domain.",
    targets: "Brand impersonation",
    hardenable: false,
    recommendation:
      "Content can't reveal a brand-free throwaway domain. Verify sender authentication (SPF/DKIM/DMARC in headers) and check domain age / reputation (the enrichment layer).",
    apply: (e) => ({
      ...e,
      sender: "Account Services <notice@account-secure-portal.com>",
    }),
  },
  {
    id: "link-launder",
    label: "Link laundering",
    technique:
      "Replaces shortened / raw-IP / suspicious-TLD links with a clean-looking .com URL that trips none of the link heuristics.",
    targets: "Suspicious links",
    hardenable: false,
    recommendation:
      "A never-before-seen .com looks clean by structure alone. Trace the redirect chain and consult a domain-reputation / newly-registered-domain feed (link tracer + enrichment layer).",
    apply: (e) => ({
      ...e,
      body: e.body.replace(/https?:\/\/[^\s"'<>)\]]+/gi, "http://account-secure-portal.com/verify"),
    }),
  },
  {
    id: "greeting-personalize",
    label: "Greeting personalization",
    technique: "Replaces the generic mass-mail salutation with a warmer, non-templated greeting.",
    targets: "Generic greeting",
    hardenable: false,
    recommendation: "Weak signal on its own; only meaningful in combination with the stronger checks above.",
    apply: (e) => ({
      ...e,
      subject: replacePhrases(e.subject, Object.fromEntries(GENERIC_GREETINGS.map((g) => [g, "hello there"]))),
      body: replacePhrases(e.body, Object.fromEntries(GENERIC_GREETINGS.map((g) => [g, "Hello there"]))),
    }),
  },
];

function naiveScore(e: Email): AnalysisResult {
  return analyze(e, { hardened: false });
}

function indicatorIds(r: AnalysisResult): Set<string> {
  return new Set(r.indicators.map((i) => i.id));
}

export function redTeam(input: Email, maxSteps = OPERATORS.length): AttackReport {
  let current = input;
  let currentResult = naiveScore(current);
  const startResult = currentResult;
  const steps: AttackStep[] = [];
  const used = new Set<string>();

  for (let i = 0; i < maxSteps; i++) {
    let best: { op: Operator; email: Email; result: AnalysisResult } | null = null;

    for (const op of OPERATORS) {
      if (used.has(op.id)) continue;
      const candidate = op.apply(current);
      if (candidate.sender === current.sender && candidate.subject === current.subject && candidate.body === current.body) {
        continue;
      }
      const result = naiveScore(candidate);
      if (result.score >= currentResult.score) continue;
      if (!best || result.score < best.result.score) best = { op, email: candidate, result };
    }

    if (!best) break;

    const before = indicatorIds(currentResult);
    const after = indicatorIds(best.result);
    const defeated = currentResult.indicators
      .filter((ind) => before.has(ind.id) && !after.has(ind.id))
      .map((ind) => ind.label);

    steps.push({
      operator: best.op.label,
      technique: best.op.technique,
      scoreBefore: currentResult.score,
      scoreAfter: best.result.score,
      defeatedIndicators: defeated,
      hardenable: best.op.hardenable,
      recommendation: best.op.recommendation,
    });

    used.add(best.op.id);
    current = best.email;
    currentResult = best.result;
    if (currentResult.level === "Low" && currentResult.score === 0) break;
  }

  const hardenedResult = analyze(current, { hardened: true });
  const naiveIds = indicatorIds(currentResult);
  const hardenedIds = indicatorIds(hardenedResult);
  const neutralizedByHardening = hardenedResult.indicators
    .filter((ind) => hardenedIds.has(ind.id) && !naiveIds.has(ind.id))
    .map((ind) => ind.label);
  const survivingTechniques = steps.filter((s) => !s.hardenable).map((s) => s.operator);

  return {
    startScore: startResult.score,
    startLevel: startResult.level,
    finalScore: currentResult.score,
    finalLevel: currentResult.level,
    steps,
    finalEmail: current,
    hardenedFinalScore: hardenedResult.score,
    hardenedFinalLevel: hardenedResult.level,
    neutralizedByHardening,
    survivingTechniques,
  };
}
